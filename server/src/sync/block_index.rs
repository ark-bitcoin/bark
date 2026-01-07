use anyhow::{bail, Context};

use tokio::sync::watch;

use futures::future::join_all;
use log::{trace, debug, info, warn};

use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};
use bitcoin_ext::{BlockRef};

use crate::database::Db;
use crate::sync::BlockData;
use crate::sync::ChainEventListener;
use crate::telemetry;

pub struct BlockIndex {
	/// The latest observed tip of bitcoind
	chain_tip_tx: watch::Sender<BlockRef>,
	/// The block index has synced up-to and including this height
	sync_height_tx: watch::Sender<BlockRef>,
	bitcoind: BitcoinRpcClient,
	db: Db,
	pub(super) listeners: Vec<Box<dyn ChainEventListener>>,
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
		bitcoind: BitcoinRpcClient,
		db: Db,
		listeners: Vec<Box<dyn ChainEventListener>>,
		birthday: BlockRef,
	) -> anyhow::Result<Self> {
		let sync_tip = match db.get_highest_block().await.context("Failed to get tip from database")? {
			Some(tip) => tip,
			None => {
				db.store_block(&birthday).await.context("Failed to store tip in database")?;
				birthday
			}
		};

		let chain_tip = bitcoind.tip().context("Failed to get bitcoind tip")?;

		let (chain_tip_tx, _) = watch::channel(chain_tip);
		let (sync_height_tx, _ ) = watch::channel(sync_tip);
		Ok(Self { chain_tip_tx, sync_height_tx, bitcoind, db, listeners })
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
	pub fn sync_tip(&self) -> BlockRef {
		*self.sync_height_tx.borrow()
	}

	/// Syncs the block index with the blockchain.
	///
	/// Updates both `chain_tip` and `sync_tip`.
	/// Handles chain reorganizations by rolling back to the common ancestor.
	/// Adds new blocks to the index if needed and notifies all listeners.
	///
	/// Returns `Ok(true)` if blocks were synced, `Ok(false)` if already in sync.
	pub async fn sync(&mut self) -> anyhow::Result<bool> {
		let bitcoind_tip = self.bitcoind.tip().context("Failed to get bitcoind tip")?;

		if self.chain_tip() != bitcoind_tip {
			self.update_tip(bitcoind_tip);
		}

		if self.sync_tip() == bitcoind_tip {
			return Ok(false);
		}

		if bitcoind_tip.height < self.sync_tip().height {
			panic!("bitcoind chain went backward. We probably restarted. Wait for bitcoind to sync and start again");
		}

		debug!("Discovered new tip with height={} and hash={}", bitcoind_tip.height, bitcoind_tip.hash);

		// Try and find the common ancestor
		let common = self.common_ancestor().await?;

		// Log if a reorg occurred
		let reorg_depth = self.sync_tip().height - common.height;
		if reorg_depth > 6 {
			warn!("Reorg detected with depth {}", reorg_depth);
		} else if reorg_depth > 0 {
			info!("Reorg detected with depth {}", reorg_depth);
		}

		if reorg_depth > 0 {
			self.org_out_blocks_above(common).await?;
		}


		// Add new blocks to the index
		for height in common.height+1..=bitcoind_tip.height {
			let hash = self.bitcoind.get_block_hash(height as u64)?;
			let block = self.bitcoind.get_block(&hash)?;

			debug!("Adding block {} - {} - {} to the index", height, hash, block.block_hash());

			if block.header.prev_blockhash != self.sync_tip().hash {
				bail!("Block {} has unexpected previous block hash. Expected: {}, Got: {}",
					height,
					self.sync_tip().hash,
					block.header.prev_blockhash
				);
			}

			let block_data = BlockData {
				block_ref: BlockRef { height, hash: block.block_hash()},
				block,
			};


			self.add_block(block_data).await?;
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
	/// Listeners are notified *before* the database is updated. This ensures we
	/// don't commit to the new tip until all listeners have successfully processed
	/// the reorg. If any listener fails, the database remains unchanged and the
	/// same reorg will be retried on the next sync cycle.
	///
	/// # Idempotency
	///
	/// Listeners must handle being called multiple times for the same reorg due to
	/// retries. Orphaned blocks are not provided directly - listeners can look them
	/// up by height if needed before the database is updated.
	async fn org_out_blocks_above(&self, block: BlockRef) -> anyhow::Result<()> {
		// We are only synced upto this height
		self.update_sync_height(block);

		let results = join_all(self.listeners.iter().map(|listener| {
			listener.on_reorg(block)
		})).await;

		// Raise the error if one of the ChainListeners failed
		for result in results {
			if result.is_err() {
				bail!("Failed to process reorg: {:#?}", result)
			}
		}

		self.db.remove_blocks_above(block.height).await?;
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
	/// transactions.
	///
	/// # Idempotency
	///
	/// Listeners must handle receiving the same block multiple times due to
	/// retries (listener failure or `store_block` failure).
	async fn add_block(&self, block: BlockData) -> anyhow::Result<()> {
		let results = join_all(self.listeners.iter().map(|listener| {
			listener.on_block_added(&block)
		})).await;

		// Raise the error if one of the ChainListeners failed
		for result in results {
			if result.is_err() {
				bail!("Failed to process new block: {:#?}", result)
			}
		}

		self.db.store_block(&block.block_ref).await?;
		self.update_sync_height(block.block_ref);
		Ok(())
	}


	/// Finds a common ancestor in the bitcoind chain and the local chain
	async fn common_ancestor(&self) -> anyhow::Result<BlockRef> {
		trace!("Looking for common ancestor");

		let bitcoind_tip = self.bitcoind.tip().context("Failed to get bitcoind tip")?;
		let local_height = self.sync_tip().height;

		// Take the local and bitcoind at this height and see if they match
		let mut height = std::cmp::min(bitcoind_tip.height, local_height);
		let mut bitcoind_block = self.bitcoind.get_block_by_height(height).context("failed to get bitcoind block by height")?;
		let mut local_block = self.db.get_block_by_height(height).await
			.context("Failed to get local block by height")?
			.context("No local block at height")?;

		// Keep walking down the chain until we find a match
		while bitcoind_block != local_block {
			trace!("Checking if height {} is a common ancestor", height);
			height -= 1;
			bitcoind_block = self.bitcoind.get_block_by_height(height)
				.context("Failed to get bitcoind block by height")?;
			local_block = self.db.get_block_by_height(height).await
				.context("Failed to get local block by height")?
				.context("No local block at height")?;
		}

		Ok(bitcoind_block)
	}
}
