pub mod block_index;

use bitcoin::{Block, Txid};
use chrono::{DateTime, Local};

use bitcoin_ext::BlockRef;

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
