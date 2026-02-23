pub mod block_index;

pub use block_index::BlockIndex;

use std::time::Duration;

use anyhow::Context;
use bitcoin::{Block, Txid};
use chrono::{DateTime, Local};
use futures::future::join_all;
use tokio::sync::watch;

use tracing::{error, info};

use bitcoin_ext::rpc::{BitcoinRpcClient, RpcApi};
use bitcoin_ext::BlockRef;

use crate::database::{BlockTable, Db};
use crate::system::RuntimeManager;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlockData {
	pub block_ref: BlockRef,
	pub block: Block,
}

/// A snapshot of the mempool at a given time.
#[derive(Debug, Clone)]
pub struct RawMempool {
	pub observed_at: DateTime<Local>,
	pub txids: Vec<Txid>,
}

/// A listener for blockchain events from the [`SyncManager`].
///
/// Implementers receive notifications about new blocks, chain reorganizations,
/// and mempool updates. All listener methods are called concurrently across
/// registered listeners.
///
/// # Error Handling
///
/// - [`on_block_added`](Self::on_block_added) and [`on_reorg`](Self::on_reorg):
///   Errors halt the sync loop, but it will retry on the next polling interval.
///   Implementers should error carefully.
/// - [`on_mempool_update`](Self::on_mempool_update): Errors are logged
///   and do not halt the sync loop.
///
/// # Idempotency
///
/// Due to restarts or temporary errors, the same block may be provided multiple
/// times via `on_block_added`. Implementations must handle this gracefully.
#[async_trait]
pub trait ChainEventListener: Send + Sync {
	/// Called when a new block has been added to the chain.
	///
	/// The block is guaranteed to be on the best chain at the time of the call.
	/// Blocks are always provided in exact height order.
	///
	/// **Note:** The same block may be delivered multiple times due to restarts
	/// or temporary errors. Implementations should be idempotent.
	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()>;

	/// Called when a chain reorganization is detected.
	///
	/// The `block_ref` parameter is the last common ancestor between the old
	/// and new chains (the fork point). After this call, `block_ref` becomes
	/// the new tip, and subsequent `on_block_added` calls will provide the
	/// blocks on the new chain.
	///
	/// Reorgs can be of arbitrary depth. Implementations should roll back any
	/// state that depended on blocks after the fork point.
	async fn on_reorg(&self, block_ref: BlockRef) -> anyhow::Result<()>;

	/// Called when the mempool has been polled.
	///
	/// Contains a complete snapshot of all transaction IDs currently in the
	/// mempool (not a diff). This is called periodically and always immediately
	/// after a new block is added.
	async fn on_mempool_update(&self, mempool: &RawMempool) -> anyhow::Result<()>;
}

struct Process {
	block_index: BlockIndex,
	bitcoind: BitcoinRpcClient,
	block_poll_interval: Duration,
}

impl Process {
	/// Runs the sync process loop.
	///
	/// This loop is responsible for keeping the server in sync with the blockchain:
	/// - Polls for new blocks every second and updates the block index
	/// - Polls the mempool immediately after a new blocks are found
	async fn run(mut self, rtmgr: RuntimeManager) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn_critical("SyncManager");

		let mut block_interval = tokio::time::interval(self.block_poll_interval);
		block_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

		loop {
			tokio::select!{
				_ = block_interval.tick() => {
					match self.block_index.sync().await {
						// New block found: poll mempool to update tx statuses
						Ok(true) => {
							if let Err(e) = self.poll_mempool().await {
								error!("Error polling mempool: {}", e);
								// Back off to avoid overwhelming a struggling downstream system
								tokio::time::sleep(Duration::from_secs(10)).await;
							}
						},
						// Already in sync, nothing to do
						Ok(false) => {},
						Err(e) => {
							error!("Error syncing block index: {}", e);
							// Back off to avoid overwhelming a struggling downstream system
							tokio::time::sleep(Duration::from_secs(10)).await;
						}
					}
				},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting SyncManager loop...");
					break;
				}
			}
		}

		info!("SyncManager loop terminated gracefully.");
		Ok(())
	}

	async fn poll_mempool(&mut self) -> anyhow::Result<()> {
		// We don't want false evictions.
		// You should only do this if you are sure that
		// all blocks are fully synced.
		self.block_index.sync().await?;

		let txids = self.bitcoind.get_raw_mempool()?;
		let mempool = RawMempool {
			observed_at: chrono::Local::now(),
			txids,
		};

		let results = join_all(self.block_index.listeners.iter().map(|listener| {
			listener.on_mempool_update(&mempool)
		})).await;

		for result in results {
			if let Err(e) = result {
				bail!("Listener failed to process mempool update: {}", e);
			}
		}

		Ok(())
	}
}

pub struct SyncManager {
	chain_tip_rx: watch::Receiver<BlockRef>,
	sync_height_rx: watch::Receiver<BlockRef>,
}

impl SyncManager {
	pub async fn start<'a>(
		rtmgr: RuntimeManager,
		bitcoind: BitcoinRpcClient,
		db: Db,
		listeners: Vec<Box<dyn ChainEventListener>>,
		birthday: BlockRef,
		block_poll_interval: Duration,
		block_table: BlockTable,
	) -> anyhow::Result<Self> {
		// Create the block index
		let block_index = BlockIndex::new(bitcoind.clone(), db, listeners, birthday, block_table).await
			.context("failed to create BlockIndex")?;
		let chain_tip_rx = block_index.chain_tip_watcher();
		let sync_height_rx = block_index.sync_height_watcher();


		// Create the process and start running it in a separate task
		let process = Process { block_index, bitcoind, block_poll_interval };
		tokio::spawn(process.run(rtmgr));

		Ok(SyncManager {
			chain_tip_rx,
			sync_height_rx,
		})
	}

	/// Fetches the current tip
	pub fn chain_tip(&self) -> BlockRef {
		self.chain_tip_rx.borrow().clone()
	}

	/// Fetches the current sync-height
	pub fn sync_height(&self) -> BlockRef {
		self.sync_height_rx.borrow().clone()
	}
}
