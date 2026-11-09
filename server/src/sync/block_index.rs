use anyhow::{bail, Context};

use tokio::sync::watch;

use futures::future::join_all;
use tracing::{trace, debug, info, warn};

use bitcoind_async_client::Client as BitcoindClient;
use bitcoind_async_client::traits::Reader;
use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef};

use crate::bitcoind as bcd;
use crate::database::{BlockTable, Db};
use crate::sync::{BlockData, ChainEventListener};
use crate::telemetry;

pub struct BlockIndex {
	/// The latest observed tip of bitcoind
	chain_tip_tx: watch::Sender<BlockRef>,
	/// The block index has synced up-to and including this height
	sync_height_tx: watch::Sender<BlockRef>,
	bitcoind: BitcoindClient,
	db: Db,
	pub(super) listeners: Vec<Box<dyn ChainEventListener>>,
	/// Which block table this index uses for persistence
	block_table: BlockTable,
	/// Whether the listeners may hold blocks above the highest stored block,
	/// and must be rolled back to it before the sync goes on.
	pending_reorg: bool,
}

impl BlockIndex {
	/// Initializes a new block index.
	///
	/// The `birthday` parameter specifies the starting block for fresh databases.
	/// If the database already contains blocks, this parameter is ignored and
	/// the existing tip is used instead.
	///
	/// # Warning
	///
	/// A reorg that goes below the birthday height is unrecoverable. The server
	/// stores no blocks below the birthday, so it cannot find a common ancestor
	/// with the Bitcoin chain. Choose a birthday that is sufficiently deep
	/// (e.g., 100+ confirmations) to make this scenario unlikely.
	pub async fn new(
		bitcoind: BitcoindClient,
		db: Db,
		listeners: Vec<Box<dyn ChainEventListener>>,
		birthday: BlockRef,
		block_table: BlockTable,
	) -> anyhow::Result<Self> {
		let sync_tip = match db.read(async |t| t.get_highest_block(block_table).await).await.context("Failed to get tip from database")? {
			Some(tip) => tip,
			None => {
				db.write(async |t| t.store_block(block_table, &birthday).await).await.context("Failed to store tip in database")?;
				birthday
			}
		};

		let chain_tip = bcd::tip(&bitcoind).await.context("Failed to get bitcoind tip")?;

		// Initialize telemetry with current values
		telemetry::set_block_height(chain_tip.height);
		telemetry::set_sync_height(sync_tip.height);

		let (chain_tip_tx, _) = watch::channel(chain_tip);
		let (sync_height_tx, _ ) = watch::channel(sync_tip);
		// Roll listeners back to the stored tip once, in case a previous run
		// stopped between removing blocks and notifying them.
		let pending_reorg = true;
		Ok(Self { chain_tip_tx, sync_height_tx, bitcoind, db, listeners, block_table, pending_reorg })
	}

	/// Get the latest observed tip of bitcoind
	pub fn chain_tip_watcher(&self) -> watch::Receiver<BlockRef> {
		self.chain_tip_tx.subscribe()
	}

	/// Get the block height up to which we are fully synced
	pub fn sync_height_watcher(&self) -> watch::Receiver<BlockRef> {
		self.sync_height_tx.subscribe()
	}

	fn update_tip(&self, tip: BlockRef) {
		self.chain_tip_tx.send_replace(tip);
		telemetry::set_block_height(tip.height);
		slog!(TipUpdated, height: tip.height, hash: tip.hash);
	}

	fn update_sync_height(&self, tip: BlockRef) {
		self.sync_height_tx.send_replace(tip);
		telemetry::set_sync_height(tip.height);
		slog!(SyncedToHeight, height: tip.height, hash: tip.hash);
	}

	/// Returns the latest observed tip of the Bitcoin blockchain.
	///
	/// This is updated immediately when a new tip is detected from bitcoind,
	/// even before all blocks have been processed. Use `sync_tip()` to check
	/// how far the block index has actually synced.
	pub fn chain_tip(&self) -> BlockRef {
		*self.chain_tip_tx.borrow()
	}

	/// Returns the block up to which we have synced.
	///
	/// This is the highest block that has been fully processed and stored
	/// in the database. May lag behind `chain_tip()` during sync operations.
	///
	/// Only published for observers, [`Self::sync`] reads the database instead.
	pub fn sync_tip(&self) -> BlockRef {
		*self.sync_height_tx.borrow()
	}

	/// Syncs the block index with the blockchain.
	///
	/// Syncs from the highest stored block, not from `sync_tip`. The published
	/// `sync_tip` never points above the highest stored block, but may lag it.
	/// Handles chain reorganizations by rolling back to the common ancestor.
	/// Adds new blocks to the index if needed and notifies all listeners.
	///
	/// Returns `Ok(false)` if the sync was already completed and nothing happened.
	pub async fn sync(&mut self) -> anyhow::Result<bool> {
		let bitcoind_tip = bcd::tip(&self.bitcoind).await
			.context("Failed to get bitcoind tip")?;

		if self.chain_tip() != bitcoind_tip {
			self.update_tip(bitcoind_tip);
		}

		let mut stored_tip = self.db.read(async |t| t.get_highest_block(self.block_table).await).await
			.context("failed to read the highest stored block")?
			.context("block index holds no blocks")?;

		if self.pending_reorg {
			self.notify_reorg(stored_tip).await?;
		}

		if stored_tip == bitcoind_tip {
			// Only republish here, a stored tip below the chain tip may be orphaned.
			if stored_tip != self.sync_tip() {
				self.update_sync_height(stored_tip);
				return Ok(true);
			}
			return Ok(false);
		}

		if bitcoind_tip.height < stored_tip.height {
			panic!("bitcoind chain went backward. We probably restarted. Wait for bitcoind to sync and start again");
		}

		debug!("Discovered new tip with height={} and hash={}", bitcoind_tip.height, bitcoind_tip.hash);

		// Try and find the common ancestor
		let common = self.common_ancestor(stored_tip).await?;

		// Log if a reorg occurred
		let reorg_depth = stored_tip.height.checked_blocks_since(common.height)
			.expect("common ancestor is below the sync tip");
		if reorg_depth > 6 {
			warn!("Reorg detected with depth {}", reorg_depth);
		} else if reorg_depth > 0 {
			info!("Reorg detected with depth {}", reorg_depth);
		}

		if reorg_depth > 0 {
			self.org_out_blocks_above(common).await?;
			stored_tip = common;
		}


		// Add new blocks to the index
		for height in common.height.to_u32()+1..=bitcoind_tip.height.to_u32() {
			let height = BlockHeight::new(height);
			let hash = self.bitcoind.get_block_hash(height.into()).await?;
			let block = self.bitcoind.get_block(&hash).await?;

			debug!("Adding block {} - {} - {} to the index", height, hash, block.block_hash());

			if block.header.prev_blockhash != stored_tip.hash {
				bail!("Block {} has unexpected previous block hash. Expected: {}, Got: {}",
					height,
					stored_tip.hash,
					block.header.prev_blockhash
				);
			}

			let block_data = BlockData {
				block_ref: BlockRef { height, hash: block.block_hash()},
				block,
			};


			let block_ref = block_data.block_ref;
			self.add_block(block_data).await?;
			stored_tip = block_ref;
		}

		Ok(true)
	}

	/// Handles a chain reorganization by rolling back to the given block.
	///
	/// The `block` parameter is the fork point (last common ancestor) and will
	/// become the new tip after this operation.
	///
	/// # Ordering
	///
	/// The published sync height is lowered to the fork point and the orphaned
	/// blocks are removed from the database *before* listeners are notified. A
	/// listener may commit its rollback while another fails, so
	/// [Self::pending_reorg] retries it on the next sync before anything else.
	/// Should the chain switch back meanwhile, the blocks above the fork point
	/// are replayed, since the index no longer holds them.
	///
	/// # Idempotency
	///
	/// Listeners must handle being called multiple times for the same reorg due to
	/// retries. Orphaned blocks are not provided directly.
	async fn org_out_blocks_above(&mut self, block: BlockRef) -> anyhow::Result<()> {
		// Lower the published tip first, it must never point above the stored tip.
		self.update_sync_height(block);
		self.pending_reorg = true;
		self.db.write(async |t| t.remove_blocks_above(self.block_table, block.height).await).await?;
		self.notify_reorg(block).await
	}

	/// Rolls all listeners back to `block` and clears [Self::pending_reorg].
	async fn notify_reorg(&mut self, block: BlockRef) -> anyhow::Result<()> {
		let results = join_all(self.listeners.iter().map(|listener| {
			listener.on_reorg(block)
		})).await;

		// Raise the error if one of the ChainListeners failed
		for result in results {
			if result.is_err() {
				bail!("Failed to process reorg: {:#?}", result)
			}
		}

		self.pending_reorg = false;
		Ok(())
	}

	/// Adds a new block to the index and notifies listeners.
	///
	/// Callers must ensure blocks are added sequentially in height order with
	/// valid `prev_blockhash` links. This is enforced by [`Self::sync`].
	///
	/// # Ordering
	///
	/// Listeners are notified *before* the block is stored in the database.
	/// This ensures we don't commit to the new tip until all listeners have
	/// successfully processed the block. If any listener fails, the database
	/// remains unchanged and the same block will be retried on the next sync.
	///
	/// Listeners that need to persist data should use their own database
	/// transactions. Since some may have applied the block when this fails,
	/// [Self::pending_reorg] rolls them back to the stored tip first.
	///
	/// # Idempotency
	///
	/// Listeners must handle receiving the same block multiple times due to
	/// retries (listener failure or `store_block` failure).
	async fn add_block(&mut self, block: BlockData) -> anyhow::Result<()> {
		self.pending_reorg = true;
		let results = join_all(self.listeners.iter().map(|listener| {
			listener.on_block_added(&block)
		})).await;

		// Raise the error if one of the ChainListeners failed
		for result in results {
			if result.is_err() {
				bail!("Failed to process new block: {:#?}", result)
			}
		}

		self.db.write(async |t| t.store_block(self.block_table, &block.block_ref).await).await?;
		self.pending_reorg = false;
		self.update_sync_height(block.block_ref);
		Ok(())
	}


	/// Finds a common ancestor in the bitcoind chain and the local chain
	async fn common_ancestor(&self, local_tip: BlockRef) -> anyhow::Result<BlockRef> {
		trace!("Looking for common ancestor");

		let bitcoind_tip = bcd::tip(&self.bitcoind).await
			.context("Failed to get bitcoind tip")?;
		let local_height = local_tip.height;

		// Take the local and bitcoind at this height and see if they match
		let mut height = std::cmp::min(bitcoind_tip.height, local_height);
		let mut bitcoind_block = bcd::get_block_by_height(&self.bitcoind, height).await
			.context("failed to get bitcoind block by height")?;
		let mut local_block = self.db.read(async |t|
			t.get_block_by_height(self.block_table, height).await
		).await
			.context("Failed to get local block by height")?
			.context("No local block at height")?;

		// Keep walking down the chain until we find a match
		while bitcoind_block != local_block {
			trace!("Checking if height {} is a common ancestor", height);
			height = height.saturating_sub(BlockDelta::new(1));
			bitcoind_block = bcd::get_block_by_height(&self.bitcoind, height).await
				.context("Failed to get bitcoind block by height")?;
			local_block = self.db.read(async |t| t.get_block_by_height(self.block_table, height).await).await
				.context("Failed to get local block by height")?
				.context("No local block at height")?;
		}

		Ok(bitcoind_block)
	}
}
