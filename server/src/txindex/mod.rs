
pub mod block;
pub mod broadcast;

use std::{cmp, fmt};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Context;
use bitcoin::consensus::encode::serialize;
use bitcoin::{Transaction, Txid};
use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};
use chrono::{DateTime, Local};
use tracing::{info, trace, warn};
use crate::database::Db;
use crate::system::RuntimeManager;

use self::block::BlockIndex;

pub struct RawMempool {
	observed_at: DateTime<Local>,
	txids: Vec<Txid>
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
	/// We have not seen this tx yet.
	Unseen,
	/// We have observed this tx in the mempool.
	///
	/// Accompanied by the first time we saw the transaction.
	MempoolSince(DateTime<Local>),
	/// This transcation was confirmed in the given block height.
	ConfirmedIn(BlockRef),
}

impl TxStatus {
	/// Whether we have seen this tx in either the mempool or the chain.
	pub fn seen(&self) -> bool {
		match self {
			TxStatus::Unseen => false,
			TxStatus::MempoolSince(_) => true,
			TxStatus::ConfirmedIn(_) => true,
		}
	}

	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			Self::ConfirmedIn(h) => Some(*h),
			Self::Unseen | Self::MempoolSince(_) => None,
		}
	}

	pub fn confirmed(&self) -> bool {
		self.confirmed_in().is_some()
	}

	fn update_mempool(&mut self, time: DateTime<Local>) {
		match self {
			TxStatus::MempoolSince(prev) => {
				*self = TxStatus::MempoolSince(cmp::min(*prev, time));
			}
			TxStatus::Unseen => *self = TxStatus::MempoolSince(time),
			TxStatus::ConfirmedIn(_) => *self = TxStatus::MempoolSince(time),
		}
	}

	fn update_not_in_mempool(&mut self) {
		match self {
			TxStatus::MempoolSince(_) => { *self = TxStatus::Unseen },
			TxStatus::Unseen => {},
			TxStatus::ConfirmedIn(_) => {},
		}
	}
}

impl From<bitcoin_ext::TxStatus> for TxStatus {
	fn from(value: bitcoin_ext::TxStatus) -> Self {
		match value {
			bitcoin_ext::TxStatus::Confirmed(block_ref) => TxStatus::ConfirmedIn(block_ref),
			bitcoin_ext::TxStatus::Mempool => TxStatus::MempoolSince(chrono::Local::now()),
			bitcoin_ext::TxStatus::NotFound => TxStatus::Unseen,
		}
	}
}

/// Shorthand for an [Arc] to an [IndexedTx].
pub type Tx = Arc<IndexedTx>;
type WeakTx = Weak<IndexedTx>;

/// A [Transaction] accompanied with their [Txid] and with access to their confirmation status.
///
/// Implementations of [PartialEq], [Eq] and [Hash] are delegated to the txid.
pub struct IndexedTx {
	pub txid: Txid,
	pub tx: Transaction,
	status: parking_lot::Mutex<TxStatus>,
}

impl IndexedTx {
	fn new_as(txid: Txid, tx: Transaction, status: TxStatus) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				status: parking_lot::Mutex::new(status),
			}
		)
	}

	/// Check the transaction's status.
	pub fn status(&self) -> TxStatus {
		//TODO(stevenroose) we can do await with this wait once we persist the txindex
		self.status.lock().clone()
	}

	/// Whether we have seen this tx in either the mempool or the chain.
	pub fn seen(&self) -> bool {
		self.status().seen()
	}

	/// Whether this tx is confirmed.
	pub fn confirmed(&self) -> bool {
		self.status().confirmed()
	}
}

impl fmt::Debug for IndexedTx {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.txid)
	}
}

impl PartialEq for IndexedTx {
	fn eq(&self, other: &Self) -> bool {
		self.txid.eq(&other.txid)
	}
}
impl Eq for IndexedTx {}

impl std::hash::Hash for IndexedTx {
	fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
		self.txid.hash(h)
	}
}

/// The handle to the transaction index.
#[derive(Clone, Debug)]
struct TxIndexData {
	tx_map: Arc<tokio::sync::RwLock<HashMap<Txid, WeakTx>>>,
	block_index: Arc<tokio::sync::RwLock<BlockIndex>>,
}

impl TxIndexData {
	fn new(base: BlockRef) -> TxIndexData {
		TxIndexData {
			tx_map: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
			block_index: Arc::new(tokio::sync::RwLock::new(BlockIndex::from_base(base))),
		}
	}

	/// Get a tx from the index.
	async fn get(&self, txid: &Txid) -> Option<Tx> {
		self.tx_map.read().await
			.get(txid)
			.map(|wtx| wtx.upgrade())
			.flatten()
	}

	async fn get_batch(&self, txids: impl IntoIterator<Item = &Txid>) -> Vec<Option<Tx>> {
		let iter = txids.into_iter();

		let size_hint = iter.size_hint();
		let mut ret = Vec::with_capacity(size_hint.1.unwrap_or(size_hint.0));

		let tx_map = self.tx_map.read().await;
		for txid in iter {
			let tx = tx_map.get(txid).map(|wtx| wtx.upgrade()).flatten();
			ret.push(tx);
		}

		ret
	}

	/// Get a tx from the index or insert when not present.
	async fn get_or_insert(
		&self,
		txid: &Txid,
		register: impl FnOnce() -> (Transaction, TxStatus),
	)-> Tx {
		if let Some(tx) = self.get(txid).await {
			tx
		} else {
			let (tx, status) = register();
			let ret = IndexedTx::new_as(*txid, tx, status);
			self.tx_map.write().await.insert(*txid, Arc::downgrade(&ret));
			ret
		}
	}

	/// Register a new tx in the index and return the tx handle.
	async fn register_as(&self, tx: Transaction, status: TxStatus) -> Tx {
		let txid = tx.compute_txid();
		let mut tx_map = self.tx_map.write().await;
		if let Some(original) = tx_map.get(&txid).map(|wtx| wtx.upgrade()).flatten() {
			if original.tx != tx {
				slog!(DifferentDuplicate,
					txid,
					raw_tx_original: serialize(&original.tx),
					raw_tx_duplicate: serialize(&tx),
				);
			}
			original.clone()
		} else {
			let ret = IndexedTx::new_as(txid, tx, status);
			tx_map.insert(txid, Arc::downgrade(&ret));
			ret
		}
	}

	/// Adds a new block to the [TxIndex].
	///
	/// It will assume that all blocks with a higher index are evicted
	async fn process_block(
		&self,
		block: block::BlockData,
	) -> Result<(), block::BlockInsertionError> {
		let mut block_index_lock = self.block_index.write().await;
		block_index_lock.try_insert(
			block.block_ref,
			block.prev_hash,
		)?;

		let block_txids = block.txids.iter().collect::<HashSet<_>>();

		for (txid, tx) in self.tx_map.read().await.iter() {
			// Check if the tx is still in the index
			let tx = match tx.upgrade() {
				Some(tx) => tx,
				None => continue,
			};


			let mut status = tx.status.lock();
			// If the transaction is added to the latest block we update the status
			if block_txids.contains(txid) {
				*status = TxStatus::ConfirmedIn(block.block_ref);
			}
			// If the transaction was in a higher block it has been
			// evicted and we kick it.
			else if let TxStatus::ConfirmedIn(b) = *status {
				if b.height >= block.block_ref.height {
					*status = TxStatus::MempoolSince(block.observed_at)
				}
			}
		}

		// Ensure other processes can only read from
		// the block index once the entire [TxIndex]
		// has been updated
		drop(block_index_lock);
		Ok(())
	}

	async fn process_mempool(&self, mempool_data: RawMempool) {
		// Put the current mempool into a HashSet
		let txids = mempool_data.txids.into_iter().collect::<HashSet<_>>();

		// Go over all transactions of the index and update them
		for (txid, tx) in self.tx_map.read().await.iter() {

			// Check if the tx is still in the index
			// If not, we don't need updates
			let index = match tx.upgrade() {
				Some(index) => index,
				None => continue,
			};

			let mut current_status = index.status.lock();
			if txids.contains(txid) {
				current_status.update_mempool(mempool_data.observed_at);
			} else {
				current_status.update_not_in_mempool();
			}
		}
	}

	async fn drop_weak_refs(&self) {
		self.tx_map.write().await.retain(|_, w| w.strong_count() > 0);
	}
}

#[derive(Clone)]
pub struct TxIndex {
	/// The index keeps data in memory
	data: TxIndexData,
	/// Can be used to query the status
	rpc: BitcoinRpcClient,
	/// Can be used to query the content of a transaction
	/// Note, that a [bitcoin::Transaction] that hasn't
	/// entered the mempool will not be known by bitcoind.
	///
	/// That's why we only rely on our database for the content
	/// of a [bitcoin::Transaction]
	db: Db,
}

impl TxIndex {
	pub async fn get(&self, txid: Txid) -> anyhow::Result<Option<Tx>> {
		match self.data.get(&txid).await {
			Some(tx) => Ok(Some(tx)),
			None => self.database_to_index(txid).await,
		}
	}

	pub async fn get_batch(&self, txids: &[Txid]) -> anyhow::Result<Vec<Option<Tx>>> {
		let mut batch = self.data.get_batch(txids).await;

		for (i, txid) in txids.into_iter().enumerate() {
			if batch[i].is_some() {
				continue
			}

			// TODO: Optimize the expensive case
			batch[i]  = self.database_to_index(*txid).await?;
		}

		Ok(batch)
	}

	pub async fn get_or_insert(
		&self,
		txid: Txid,
		register: impl FnOnce() -> Transaction
	) -> anyhow::Result<Tx> {
		match self.data.get(&txid).await {
			Some(tx) => Ok(tx),
			None => self.dump_transaction(txid, register()).await
		}
	}

	pub async fn register(&self, tx: Transaction) -> anyhow::Result<Tx> {
		let txid = tx.compute_txid();
		self.db.upsert_bitcoin_transaction(txid, &tx).await
			.context("failed to store bitcoin tx in db")?;
		let status = self.rpc.tx_status(&txid)
			.context("failed to get bitcoin tx status")?;
		Ok(self.data.register_as(tx, status.into()).await)
	}

	pub async fn register_as(&self, tx: Transaction, status: TxStatus) -> anyhow::Result<Tx> {
		let txid = tx.compute_txid();
		self.db.upsert_bitcoin_transaction(txid, &tx).await
			.context("failed to store bitcoin tx in db")?;
		Ok(self.data.register_as(tx, status).await)
	}

	async fn dump_transaction(&self, txid: Txid, tx: Transaction) -> anyhow::Result<Tx> {
		self.db.upsert_bitcoin_transaction(txid, &tx).await
			.context("failed to store bitcoin tx in db")?;
		let status = self.rpc.tx_status(&txid)?;
		let indexed_tx = self.data.get_or_insert(&txid, || (tx, status.into())).await;
		Ok(indexed_tx)
	}

	async fn database_to_index(&self, txid: Txid) -> anyhow::Result<Option<Tx>> {
		let db_tx = self.db.get_bitcoin_transaction_by_id(txid).await
			.context("failed to query bitcoin tx from db")?;

		match db_tx {
			None => Ok(None),
			Some(tx) => {
				let status = self.rpc.tx_status(&txid)
					.context("failed to get bitcoin tx status")?;
				let indexed_tx = self.data.get_or_insert(&txid, || (tx, status.into())).await;
				Ok(Some(indexed_tx))
			}
		}
	}

	pub fn start(
		deep_tip: BlockRef,
		rtmgr: RuntimeManager,
		bitcoind: BitcoinRpcClient,
		interval: Duration,
		db: Db,
	) -> TxIndex {
		let data = TxIndexData::new(deep_tip);
		let proc = Process {
			rtmgr,
			bitcoind: bitcoind.clone(),
			interval,
			data: data.clone(),
		};

		tokio::spawn( async move {
			proc.run().await.context("txindex exited with error")?;
			info!("TxIndex shut down");
			Ok::<(), anyhow::Error>(())
		});

		TxIndex {
			data,
			rpc: bitcoind,
			db,
		}
	}
}

struct Process {
	bitcoind: BitcoinRpcClient,
	interval: Duration,
	data: TxIndexData,
	rtmgr: RuntimeManager,
}

impl Process {
	async fn update_mempool(&self) -> anyhow::Result<()> {
		let txids = self.bitcoind.get_raw_mempool()?;
		let mempool = RawMempool {
			observed_at: chrono::Local::now(),
			txids: txids,
		};

		self.data.process_mempool(mempool).await;
		Ok(())
	}

	async fn update_blocks(&self) -> anyhow::Result<()> {
		let bitcoind_tip = self.bitcoind.tip().context("Failed to get tip from bitcoind")?;

		let index_start = self.data.block_index.read().await.first().height;
		let index_tip = self.data.block_index.read().await.tip();

		// Nothing to do
		// The index is up-to-date
		if bitcoind_tip == index_tip {
			return Ok(())
		}

		let mut new_blocks = vec![];

		// The chain has a new tip
		// This is potentially a re-org or multiple blocks
		// have been found at the same time.
		for height in (index_start..=bitcoind_tip.height).rev() {
			let block_hash = self.bitcoind.get_block_hash(height as u64)?;
			let block_info = self.bitcoind.get_block_info(&block_hash)?;
			let block_ref  = BlockRef { height, hash: block_hash};
			let prev_hash = block_info.previousblockhash.unwrap();

			new_blocks.push(block_info);

			if self.data.block_index.read().await.would_accept(block_ref, prev_hash) {
				break
			}
		}

		// Add all the blocks to the index one-by-one
		for block in new_blocks.into_iter().rev() {
			let data = block::BlockData {
				block_ref: BlockRef { height: block.height as BlockHeight, hash: block.hash},
				prev_hash: block.previousblockhash.unwrap(),
				txids: block.tx,
				observed_at: chrono::Local::now(),
			};

			self.data.process_block(data).await?;
		};

		Ok(())
	}

	/// Run the txindex.
	///
	/// This method will only return once the txindex stops, so it should be called
	/// in a context that allows it to keep running.
	async fn run(self) -> anyhow::Result<()> {
		let _worker = self.rtmgr.spawn_critical("TxIndex");

		let mut interval = tokio::time::interval(self.interval);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		loop {
			tokio::select! {
				_ = interval.tick() => {},
				_ = self.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting tx index loop...");
					return Ok(());
				},
			}

			trace!("Starting update of all txs...");

			self.data.drop_weak_refs().await;

			if let Err(e) = self.update_blocks().await {
				warn!("Error updating TxIndex from blocks: {}", e);
			}

			if let Err(e) = self.update_mempool().await {
				warn!("Error updating TxIndex from mempool: {}", e);
			}

			slog!(TxIndexUpdateFinished);
		}
	}
}

#[cfg(test)]
mod test {

	use super::*;
	use block::BlockData;
	use block::test::dummy_block;

	/// The transaction index just caches data. It doesn't care
	/// if the transactions don't make any sense and we can safely
	/// use dummy transactions.
	fn dummy_tx(num: u32) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version::non_standard(3),
			lock_time: bitcoin::absolute::LockTime::from_height(num).unwrap(),
			input: vec![],
			output: vec![],
		}
	}


	#[tokio::test]
	async fn insert_tx_index() {
		// This test should actually work now
		let first_block = dummy_block(0, 0);
		let tx = dummy_tx(1);
		let txid = tx.compute_txid();

		// Create the index
		let index = TxIndexData::new(first_block);

		// Register the transaction and verify
		// it has been registered
		let arc = index.register_as(tx.clone(), TxStatus::Unseen).await;
		let tx_handle = index.get(&txid).await.expect("Transaction in index");
		assert_eq!(tx_handle.status(), TxStatus::Unseen);
		drop(arc);


		// Register the transaction again
		index.register_as(tx.clone(), TxStatus::Unseen).await;
		assert_eq!(tx_handle.status(), TxStatus::Unseen);
	}

	#[tokio::test]
	async fn tx_index_handles_reorg() {
		// We define 4 blocks on fork a
		let old_block = dummy_block(0x0a, 1);
		let block_ref_a0 = dummy_block(0xa0, 1000);
		let block_ref_a1 = dummy_block(0xa1, 1001);
		let block_ref_a2 = dummy_block(0xa2, 1002);
		let block_ref_a3 = dummy_block(0xa3, 1003);

		// This will re-ort out a_2 and _a3
		let block_ref_b2 = dummy_block(0xb2, 1002);

		// Each block has 2 transactions
		// The first will go into the mempool and the other will not
		// tx_ai_j goes into block i and is transaction number j in that block
		let tx_a1_1=dummy_tx(0xa1_1); let tx_a1_2=dummy_tx(0xa1_2);
		let tx_a2_1=dummy_tx(0xa2_1); let tx_a2_2=dummy_tx(0xa2_2);
		let tx_a3_1=dummy_tx(0xa3_1); let tx_a3_2=dummy_tx(0xa3_2);
		let tx_b2_1=dummy_tx(0xb2_1);

		// We also have an old tx which was confirmed before the TxIndex
		let old_tx = dummy_tx(0xa1_9999);

		// Register all transactions to the index
		let index = TxIndexData::new(block_ref_a0);
		let tx_a1_1 = index.register_as(tx_a1_1, TxStatus::Unseen).await;
		let tx_a1_2 = index.register_as(tx_a1_2, TxStatus::Unseen).await;
		let tx_a2_1 = index.register_as(tx_a2_1, TxStatus::Unseen).await;
		let tx_a2_2 = index.register_as(tx_a2_2, TxStatus::Unseen).await;
		let tx_a3_1 = index.register_as(tx_a3_1, TxStatus::Unseen).await;
		let tx_a3_2 = index.register_as(tx_a3_2, TxStatus::Unseen).await;
		let tx_b2_1 = index.register_as(tx_b2_1, TxStatus::Unseen).await;
		let old_tx = index.register_as(old_tx, TxStatus::ConfirmedIn(old_block)).await;

		// Push the block to the index
		let t2 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_a1,
			prev_hash: block_ref_a0.hash,
			txids: vec![tx_a1_1.txid, tx_a1_2.txid],
			observed_at: t2,
		}).await.unwrap();

		let t3 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_a2,
			prev_hash: block_ref_a1.hash,
			txids: vec![tx_a2_1.txid, tx_a2_2.txid],
			observed_at: t3,
		}).await.unwrap();

		let t4 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_a3,
			prev_hash: block_ref_a2.hash,
			txids: vec![tx_a3_1.txid, tx_a3_2.txid],
			observed_at: t4,
		}).await.unwrap();

		assert_eq!(tx_a1_1.status(), TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a2_1.status(), TxStatus::ConfirmedIn(block_ref_a2));
		assert_eq!(tx_a3_1.status(), TxStatus::ConfirmedIn(block_ref_a3));

		// Now we do a reorg by introducing block_ref_b2
		// ai_1 transactions will be in the new block
		// ai_2 transactions will be evicted
		let t5 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_b2,
			prev_hash: block_ref_a1.hash,
			txids: vec![tx_b2_1.txid, tx_a2_1.txid, tx_a3_1.txid],
			observed_at: t5,
		}).await.unwrap();

		assert_eq!(tx_a1_1.status(), TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a1_2.status(), TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a2_1.status(), TxStatus::ConfirmedIn(block_ref_b2));
		assert_eq!(tx_a2_2.status(), TxStatus::MempoolSince(t5));
		assert_eq!(tx_a3_1.status(), TxStatus::ConfirmedIn(block_ref_b2));
		assert_eq!(tx_a3_2.status(), TxStatus::MempoolSince(t5));
		assert_eq!(old_tx.status(),TxStatus::ConfirmedIn(old_block));
	}
}
