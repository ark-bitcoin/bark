//TODO(stevenroose) remove after Jiri's txindex refactor
#![allow(unused)]
pub mod block;
pub mod broadcast;

use std::{cmp, fmt};
use std::collections::HashMap;
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
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::system::RuntimeManager;

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
	status: Mutex<Option<TxStatus>>,
}
//TODO(stevenroose) consider adding some stats about confirmation times
// like the time it got first broadcast and then we can log how long it took to be confirmed

impl IndexedTx {
	fn new_as(txid: Txid, tx: Transaction, status: TxStatus) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				incomplete: false,
				status: Mutex::new(Some(status)),
			}
		)
	}

	fn new_incomplete(txid: Txid, tx: Transaction) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				incomplete: true,
				status: Mutex::new(Some(TxStatus::Unseen)),
			}
		)
	}

	fn new(txid: Txid, tx: Transaction) -> Tx {
		Arc::new(
			IndexedTx {
				txid, tx,
				incomplete: false,
				status: Mutex::new(None),
			}
		)
	}

	/// Check the transaction's status.
	pub async fn status(&self) -> TxStatus {
		//TODO(stevenroose) we can do await with this wait once we persist the txindex
		loop {
			if let Some(s) = *self.status.lock().await {
				return s;
			}
			trace!("waiting for tx status of {}...", self.txid);
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
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
	broadcast_pkg: Option<mpsc::UnboundedSender<Vec<Txid>>>,
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

	/// Quick getter for the status of a tx by txid.
	///
	/// Returns [None] for a tx not in the index.
	pub async fn status_of(&self, txid: &Txid) -> Option<TxStatus> {
		let tx_map = self.tx_map.read().await;
		let tx = tx_map.get(txid).cloned();
		drop(tx_map);
		if let Some(tx) = tx {
			Some(tx.status().await)
		} else {
			None
		}
	}

	/// Get a tx from the index or insert when not present.
	pub async fn get_or_insert(&self, txid: &Txid, register: impl FnOnce() -> Transaction) -> Tx {
		let tx_map_read_lock = self.tx_map.read().await;
		if let Some(tx) = tx_map_read_lock.get(txid) {
			tx.clone()
		} else {
			drop(tx_map_read_lock);
			let tx = register();
			let ret = IndexedTx::new(*txid, tx);
			self.tx_map.write().await.insert(*txid, ret.clone());
			ret
		}
	}

	/// Register a new tx in the index and return the tx handle.
	pub async fn register(&self, tx: Transaction) -> Tx {
		let txid = tx.compute_txid();
		let mut tx_map = self.tx_map.write().await;
		if let Some(tx) = tx_map.get(&txid) {
			tx.clone()
		} else {
			let ret = IndexedTx::new(txid, tx);
			tx_map.insert(txid, ret.clone());
			ret
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

	/// Register a batch of transactions at once.
	pub async fn register_batch(&self, txs: impl IntoIterator<Item = Transaction>) {
		let mut tx_map = self.tx_map.write().await;
		for tx in txs {
			let txid = tx.compute_txid();
			tx_map.entry(txid).or_insert_with(|| IndexedTx::new(txid, tx));
		}
	}

	/// Unregister a transaction
	pub async fn unregister(&self, tx: impl TxOrTxid) {
		let mut tx_map = self.tx_map.write().await;
		let tx = tx_map.remove(&tx.txid());
		drop(tx_map);
		if let Some(tx) = tx {
			*tx.status.lock().await = Some(TxStatus::Unregistered);
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
			*tx.status.lock().await = Some(TxStatus::Unregistered);
		}
	}

	pub fn new() -> TxIndex {
		TxIndex {
			tx_map: Arc::new(RwLock::new(HashMap::new())),
			broadcast_pkg: None,
		}
	}

	/// Start the tx index.
	pub fn start(
		&mut self,
		rtmgr: RuntimeManager,
		bitcoind: BitcoinRpcClient,
		interval: Duration,
	) -> JoinHandle<anyhow::Result<()>> {
		let (broadcast_tx, broadcast_rx) = mpsc::unbounded_channel();
		self.broadcast_pkg = Some(broadcast_tx);

		let proc = TxIndexProcess {
			rtmgr, bitcoind, interval, broadcast_rx,
			txs: self.tx_map.clone(),
			broadcast: Vec::new(),
		};
		tokio::spawn(async move {
			proc.run().await.context("txindex exited with error")?;
			info!("TxIndex shut down.");
			Ok(())
		})
	}
}

struct TxIndexProcess {
	bitcoind: BitcoinRpcClient,
	interval: Duration,

	txs: Arc<RwLock<HashMap<Txid, Tx>>>,
	broadcast: Vec<Vec<Txid>>,

	broadcast_rx: mpsc::UnboundedReceiver<Vec<Txid>>,
	rtmgr: RuntimeManager,
}

impl TxIndexProcess {
	async fn update_txs(&mut self) {
		trace!("Starting TxIndexProcess::update_txs...");
		for (txid, tx) in self.txs.read().await.iter() {
			//TODO(stevenroose) entirely rewrite this based on zmq
			// because right now it's super inefficient and sets the same status over and over
			match self.bitcoind.custom_get_raw_transaction_info(txid, None) {
				Ok(Some(info)) => {
					if let Some(block) = info.blockhash {
						// Confirmed!
						match self.bitcoind.get_block_header_info(&block) {
							Ok(h) => {
								let block_index = BlockRef {
									height: h.height as BlockHeight,
									hash: h.hash,
								};
								let new = TxStatus::ConfirmedIn(block_index);
								*tx.status.lock().await = Some(new);
							}
							Err(e) => warn!("Failed to fetch block header of txinfo hash: {}", e),
						}
					} else {
						// Still in mempool.
						match &mut *tx.status.lock().await {
							v @ None => { *v = Some(TxStatus::MempoolSince(Local::now())) },
							Some(s) => s.update_mempool(Local::now()),
						}
					}
				},
				Ok(None) => *tx.status.lock().await = Some(TxStatus::Unseen),
				Err(e) => warn!("bitcoin error: {}", e),
			}
		}
		trace!("Finished TxIndexProcess::update_txs");
	}

	///
	/// This method will only return once the txindex stops, so it should be called
	/// in a context that allows it to keep running.
	async fn run(mut self) -> anyhow::Result<()> {
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
					self.update_txs().await;
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
