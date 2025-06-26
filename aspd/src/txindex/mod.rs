//TODO(stevenroose) remove after Jiri's txindex refactor
#![allow(unused)]
pub mod block;
pub mod broadcast;

use std::{cmp, fmt};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin::consensus::encode::serialize;
use bitcoin::{BlockHash, Transaction, Txid, Wtxid};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcErrorExt, BitcoinRpcExt};
use bitcoin_ext::{BlockHeight, BlockRef};
use chrono::{DateTime, Local};
use log::{trace, debug, info, warn};
use opentelemetry::trace::FutureExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use block::BlockIndex;
use crate::system::RuntimeManager;

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

	/// This tx is no longer being tracked by the txindex.
	Unregistered,
}

impl TxStatus {

	/// Whether we have seen this tx in either the mempool or the chain.
	pub fn seen(&self) -> bool {
		match self {
			TxStatus::Unseen => false,
			TxStatus::MempoolSince(_) => true,
			TxStatus::ConfirmedIn(_) => true,
			TxStatus::Unregistered => false,
		}
	}

	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			Self::ConfirmedIn(h) => Some(*h),
			Self::Unseen | Self::MempoolSince(_) | Self::Unregistered => None,
		}
	}

	pub fn confirmed(&self) -> bool {
		self.confirmed_in().is_some()
	}

	fn update_mempool(&mut self, time: DateTime<Local>) {
		match self {
			TxStatus::Unregistered => {},
			TxStatus::MempoolSince(ref prev) => {
				*self = TxStatus::MempoolSince(cmp::min(*prev, time));
			}
			TxStatus::Unseen => *self = TxStatus::MempoolSince(time),
			TxStatus::ConfirmedIn(_) => *self = TxStatus::MempoolSince(time),
		}
	}

	fn update_not_in_mempool(&mut self, time: DateTime<Local>) {
		match self {
			TxStatus::Unregistered => {},
			TxStatus::MempoolSince(ref prev) => { *self = TxStatus::Unseen},
			TxStatus::Unseen => {},
			TxStatus::ConfirmedIn(_) => {},
		}
	}
}

impl From<bitcoin_ext::rpc::TxStatus> for TxStatus {
	fn from(value: bitcoin_ext::rpc::TxStatus) -> Self {
		match value {
			bitcoin_ext::rpc::TxStatus::Confirmed(block_ref) => TxStatus::ConfirmedIn(block_ref),
			bitcoin_ext::rpc::TxStatus::Mempool => TxStatus::MempoolSince(chrono::Local::now()),
			bitcoin_ext::rpc::TxStatus::NotFound => TxStatus::Unseen,
		}
	}
}

/// Shorthand for an [Arc] to an [IndexedTx].
pub type Tx = Arc<IndexedTx>;

/// A [Transaction] accompanied with their [Txid] and with access to their confirmation status.
///
/// Implementations of [PartialEq], [Eq] and [Hash] are delegated to the txid.
pub struct IndexedTx {
	pub txid: Txid,
	pub tx: Transaction,
	/// An incomplete tx is a tx that is missing some witness data to be valid for broadcast.
	/// This is used for txs that we don't fully control and can potentially be broadcast
	/// by users when they finalize the tx with their signature.
	pub incomplete: bool,
	//TODO(stevenroose) if we persist the txindex, we can do away with this Option
	// and the complications it brings for updating the status
	status: Mutex<TxStatus>,
}
//TODO(stevenroose) consider adding some stats about confirmation times
// like the time it got first broadcast and then we can log how long it took to be confirmed

impl IndexedTx {
	fn new_as(txid: Txid, tx: Transaction, status: TxStatus) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				incomplete: false,
				status: Mutex::new(status),
			}
		)
	}

	fn new_incomplete(txid: Txid, tx: Transaction) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				incomplete: true,
				status: Mutex::new(TxStatus::Unseen),
			}
		)
	}

	/// Check the transaction's status.
	pub async fn status(&self) -> TxStatus {
		//TODO(stevenroose) we can do await with this wait once we persist the txindex
		self.status.lock().await.clone()
	}

	/// Whether we have seen this tx in either the mempool or the chain.
	pub async fn seen(&self) -> bool {
		self.status().await.seen()
	}

	/// Whether this tx is confirmed.
	pub async fn confirmed(&self) -> bool {
		self.status().await.confirmed()
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

pub trait TxOrTxid {
	fn txid(&self) -> Txid;
}

impl TxOrTxid for Txid {
	fn txid(&self) -> Txid { *self }
}
impl TxOrTxid for Tx {
	fn txid(&self) -> Txid { self.txid }
}
impl TxOrTxid for Transaction {
	fn txid(&self) -> Txid { self.compute_txid() }
}
impl<'a, T: TxOrTxid> TxOrTxid for &'a T {
	fn txid(&self) -> Txid { (*self).txid() }
}

/// The handle to the transaction index.
#[derive(Clone, Debug)]
pub struct TxIndex {
	tx_map: Arc<RwLock<HashMap<Txid, Tx>>>,
	block_index: Arc<RwLock<BlockIndex>>,
}

//TODO(stevenroose) consider persisting all this state
// - this would make it easier to entirely rely on new blocks and incoming mempool txs
// - it would simplify the startup mechanism in that case
// - it would also allow for better statistics keeping on conf times

impl TxIndex {
	/// Get a tx from the index.
	pub async fn get(&self, txid: &Txid) -> Option<Tx> {
		self.tx_map.read().await.get(txid).cloned()
	}

	pub async fn get_batch(&self, batch: impl IntoIterator<Item=&Txid>) -> Vec<Option<Tx>> {
		let iter = batch.into_iter();

		let size_hint = iter.size_hint();
		let mut result = Vec::with_capacity(size_hint.1.unwrap_or(size_hint.0));

		let tx_map = self.tx_map.read().await;
		for txid in iter {
			result.push(tx_map.get(txid).cloned());
		}

		result
	}

	/// Quick getter for the status of a tx by txid.
	///
	/// Returns [None] for a tx not in the index.
	pub async fn status_of(&self, txid: &Txid) -> Option<TxStatus> {
		if let Some(tx) = self.get(txid).await {
			Some(tx.status().await)
		} else {
			None
		}
	}

	/// Get a tx from the index or insert when not present.
	pub async fn get_or_insert(&self, txid: &Txid, register: impl FnOnce() -> (Transaction, TxStatus))-> Tx {
		if let Some(tx) = self.get(txid).await {
			tx
		} else {
			let (tx, status) = register();
			let ret = IndexedTx::new_as(*txid, tx, status);
			self.tx_map.write().await.insert(*txid, ret.clone());
			ret
		}
	}

	pub async fn get_or_insert_with_bitcoind(
		&self,
		txid: &Txid,
		register: impl FnOnce() -> Transaction,
		bitcoind: &BitcoinRpcClient
	) -> anyhow::Result<Tx> {
		if let Some(tx) = self.get(txid).await {
			Ok(tx)
		} else {
			let status = bitcoind.tx_status(txid)?;
			let ret = IndexedTx::new_as(*txid, register(), status.into());
			self.tx_map.write().await.insert(*txid, ret.clone());
			Ok(ret)
		}

	}

	/// Register a new tx in the index and return the tx handle.
	pub async fn register_as(&self, tx: Transaction, status: TxStatus) -> Tx {
		let txid = tx.compute_txid();
		let mut tx_map = self.tx_map.write().await;
		if let Some(original) = tx_map.get(&txid) {
			if original.tx != tx {
				slog!(DifferentDuplicate, txid,
					raw_tx_original: serialize(&original.tx),
					raw_tx_duplicate: serialize(&tx),
				);
			}
			original.clone()
		} else {
			let ret = IndexedTx::new_as(txid, tx, status);
			tx_map.insert(txid, ret.clone());
			ret
		}
	}

	/// Register a new tx in the index and return the tx handle.
	/// The status will be requested from bitcoind before adding it to the index
	pub async fn register_with_bitcoind(&self, tx: Transaction, bitcoind: &BitcoinRpcClient) -> anyhow::Result<Tx> {
		let txid = tx.compute_txid();
		let status = match bitcoind.tx_status(&txid)? {
			bitcoin_ext::rpc::TxStatus::Confirmed(block_ref)  => TxStatus::ConfirmedIn(block_ref),
			bitcoin_ext::rpc::TxStatus::Mempool => TxStatus::MempoolSince(chrono::Local::now()),
			bitcoin_ext::rpc::TxStatus::NotFound => TxStatus::Unseen,
		};

		Ok(self.register_as(tx, status).await)
	}

	/// Register a new tx in the index and return the tx handle.
	pub async fn register_incomplete(&self, tx: Transaction) -> Tx {
		let txid = tx.compute_txid();
		let mut tx_map = self.tx_map.write().await;
		if let Some(tx) = tx_map.get(&txid) {
			tx.clone()
		} else {
			let ret = IndexedTx::new_incomplete(txid, tx);
			tx_map.insert(txid, ret.clone());
			ret
		}
	}

	/// Unregister a transaction
	pub async fn unregister(&self, tx: impl TxOrTxid) {
		let mut tx_map = self.tx_map.write().await;
		let tx = tx_map.remove(&tx.txid());
		drop(tx_map);
		if let Some(tx) = tx {
			*tx.status.lock().await = TxStatus::Unregistered;
		}
	}

	/// Unregister a batch of transactions at once.
	pub async fn unregister_batch(&self, txs: impl IntoIterator<Item = impl TxOrTxid>) {
		let mut tx_map = self.tx_map.write().await;
		let mut unregister = Vec::new();
		for tx in txs {
			let txid = tx.txid();
			if let Some(tx) = tx_map.remove(&txid) {
				unregister.push(tx);
			}
		}
		drop(tx_map);
		for tx in unregister {
			*tx.status.lock().await = TxStatus::Unregistered;
		}
	}

	pub fn new(base: BlockRef) -> TxIndex {
		TxIndex {
			tx_map: Arc::new(RwLock::new(HashMap::new())),
			block_index: Arc::new(RwLock::new(BlockIndex::from_base(base))),
		}
	}

	/// Adds a new block to the [TxIndex].
	///
	/// It will assume that all blocks with a higher index are evicted
	pub async fn process_block(
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
			let mut status = tx.status.lock().await;
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

	pub async fn process_mempool(&self, mempool_data: RawMempool) {
		// Put the current mempool into a HashSet
		let txids = mempool_data.txids.into_iter().collect::<HashSet<_>>();

		// Go over all transactions of the index and update them
		for (txid, index) in self.tx_map.read().await.iter() {
			let mut current_status = index.status.lock().await;
			if txids.contains(txid) {
				current_status.update_mempool(mempool_data.observed_at);
			} else {
				current_status.update_not_in_mempool(mempool_data.observed_at);
			}
		}
	}

	pub fn start(
		deep_tip: BlockRef,
		rtmgr: RuntimeManager,
		bitcoind: BitcoinRpcClient,
		interval: Duration,
	) -> TxIndex {
		let txindex = TxIndex::new(deep_tip);
		let proc = TxIndexProcess {
			rtmgr,
			bitcoind,
			interval,
			txindex: txindex.clone(),
		};

		tokio::spawn( async move {
			proc.run().await.context("txindex exited with error")?;
			info!("TxIndex shut down");
			Ok::<(), anyhow::Error>(())
		});

		txindex
	}
}

struct TxIndexProcess {
	bitcoind: BitcoinRpcClient,
	interval: Duration,
	txindex: TxIndex,
	rtmgr: RuntimeManager,
}

impl TxIndexProcess {
	pub fn new(
		rtmgr: RuntimeManager,
		initial_block: BlockRef,
		bitcoind: BitcoinRpcClient,
		interval: Duration,
	) -> Self {
		let txindex = TxIndex::new(initial_block);
		Self {
			rtmgr, bitcoind, interval, txindex,
		}
	}

	pub fn get_index(&self) -> TxIndex {
		self.txindex.clone()
	}


	pub async fn update_mempool(&self) -> () {
		match self.bitcoind.get_raw_mempool() {
			Ok(mempool_txids) => {
				let mempool = RawMempool {
					observed_at: chrono::Local::now(),
					txids: mempool_txids,
				};

				self.txindex.process_mempool(mempool).await;
			}
			Err(err) => {
				warn!("Failed to download mempool from bitcoind");
			}
		}
	}

	pub async fn update_blocks(&self) -> anyhow::Result<()> {
		let bitcoind_tip = self.bitcoind.tip().context("Failed to get tip from bitcoind")?;

		let index_start = self.txindex.block_index.read().await.first().height;
		let index_tip = self.txindex.block_index.read().await.tip();

		// Nothing to do
		// The index is up-to-date
		if bitcoind_tip == index_tip {
			return Ok(())
		}

		let mut new_blocks = vec![];

		// The chain has a new tip
		// This is potentially a re-org or multiple blocks
		// have been found at the same time.
		let block_hash = index_tip.hash;
		for iii in (index_start..=bitcoind_tip.height).rev() {
			let block_hash = self.bitcoind.get_block_hash(iii as u64)?;
			let block_info = self.bitcoind.get_block_info(&block_hash)?;
			let block_ref  = BlockRef { height: iii, hash: block_hash};
			let prev_hash = block_info.previousblockhash.unwrap();

			new_blocks.push(block_info);

			if self.txindex.block_index.read().await.would_accept(block_ref, prev_hash) {
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

			self.txindex.process_block(data).await?;
		};

		Ok(())
	}

	/// Run the txindex.
	///
	/// This method will only return once the txindex stops, so it should be called
	/// in a context that allows it to keep running.
	pub async fn run(mut self) -> anyhow::Result<()> {
		let _worker = self.rtmgr.spawn_critical("TxIndex");

		// Sleep just a little for our txindex to be filled by processes.
		// TODO(stevenroose) this can be removed when we persist the txindex
		tokio::time::sleep(Duration::from_secs(1)).await;

		let mut interval = tokio::time::interval(self.interval);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		loop {
			tokio::select! {
				_ = interval.tick() => {
					trace!("Starting update of all txs...");
					self.update_blocks().await;
					self.update_mempool().await;
					slog!(TxIndexUpdateFinished);
				},
				_ = self.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting tx index loop...");
					return Ok(());
				}
			}
		}
	}
}


#[cfg(test)]
mod test {

	use super::*;
	use block::BlockData;
	use block::test::dummy_block;
	use chrono::TimeZone;


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
		let index = TxIndex::new(first_block);

		// Register the transaction and verify
		// it has been registered
		index.register_as(tx.clone(), TxStatus::Unseen).await;
		let tx_handle = index.get(&txid).await.expect("Transaction in index");
		assert_eq!(tx_handle.status().await, TxStatus::Unseen);

		// Register the transaction again
		index.register_as(tx.clone(), TxStatus::Unseen).await;
		assert_eq!(tx_handle.status().await, TxStatus::Unseen);
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
		let index = TxIndex::new(block_ref_a0);
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
		}).await;

		let t3 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_a2,
			prev_hash: block_ref_a1.hash,
			txids: vec![tx_a2_1.txid, tx_a2_2.txid],
			observed_at: t3,
		}).await;

		let t4 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_a3,
			prev_hash: block_ref_a2.hash,
			txids: vec![tx_a3_1.txid, tx_a3_2.txid],
			observed_at: t4,
		}).await;

		assert_eq!(tx_a1_1.status().await, TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a2_1.status().await, TxStatus::ConfirmedIn(block_ref_a2));
		assert_eq!(tx_a3_1.status().await, TxStatus::ConfirmedIn(block_ref_a3));

		// Now we do a reorg by introducing block_ref_b2
		// ai_1 transactions will be in the new block
		// ai_2 transactions will be evicted
		let t5 = chrono::Local::now();
		index.process_block(BlockData {
			block_ref: block_ref_b2,
			prev_hash: block_ref_a1.hash,
			txids: vec![tx_b2_1.txid, tx_a2_1.txid, tx_a3_1.txid],
			observed_at: t5,
		}).await;

		assert_eq!(tx_a1_1.status().await, TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a1_2.status().await, TxStatus::ConfirmedIn(block_ref_a1));
		assert_eq!(tx_a2_1.status().await, TxStatus::ConfirmedIn(block_ref_b2));
		assert_eq!(tx_a2_2.status().await, TxStatus::MempoolSince(t5));
		assert_eq!(tx_a3_1.status().await, TxStatus::ConfirmedIn(block_ref_b2));
		assert_eq!(tx_a3_2.status().await, TxStatus::MempoolSince(t5));
		assert_eq!(old_tx.status().await,TxStatus::ConfirmedIn(old_block));
	}
}
