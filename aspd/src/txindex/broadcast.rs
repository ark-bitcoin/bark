use std::collections::HashMap;

use bitcoin::{Txid, Transaction, Wtxid};
use bitcoin::consensus::encode::serialize;
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, RpcApi};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use log::{trace, debug, info, warn};
use tokio::sync::mpsc;

use crate::system::RuntimeManager;
use crate::txindex::{Tx, TxStatus, TxIndex};

#[derive(Clone, Debug)]
pub struct TxBroadcastHandle {
	sender: mpsc::UnboundedSender<Vec<Txid>>,
	index: TxIndex,
}

impl TxBroadcastHandle {
	/// Adds the transaction to TxIndex and ensures
	/// it will be broadcast
	pub async fn broadcast_tx(&self, tx: Transaction) -> Tx {
		let ret = self.index.register_as(tx, TxStatus::Unseen).await;
		self.inner_broadcast(vec![ret.txid]);
		ret
	}

	/// Adds the package to TxIndex and ensures it
	/// will be broadcast
	pub async fn broadcast_pkg(&self, pkg: impl Into<Vec<Transaction>>) -> Vec<Tx> {
		let pkg = pkg.into();
		let mut ret = Vec::with_capacity(pkg.len());
		for tx in pkg {
			ret.push(self.index.register_as(tx, TxStatus::Unseen).await);
		}
		let txids = ret.iter().map(|t| t.txid).collect::<Vec<_>>();
		log::debug!("Registering tx package for broadcast: {:?}", txids);
		self.inner_broadcast(txids);
		ret
	}

	/// Adds the transaction to the queue for broadcasting
	fn inner_broadcast(&self, pkg: impl Into<Vec<Txid>>) {
		self.sender
			.send(pkg.into()).expect("txindex shut down");
	}
}

pub struct TxNursery {
	txindex: TxIndex,
	bitcoind: BitcoinRpcClient,
	sender: mpsc::UnboundedSender<Vec<Txid>>,
	receiver: mpsc::UnboundedReceiver<Vec<Txid>>,
	broadcast: Vec<Vec<Txid>>,
	rtmgr: RuntimeManager,
	interval: std::time::Duration,
}

impl TxNursery {

	pub fn new(
		rtmgr: RuntimeManager,
		txindex: TxIndex,
		bitcoind: BitcoinRpcClient,
		interval: std::time::Duration,
	) -> Self {
		let (sender, receiver) = mpsc::unbounded_channel();
		Self {
			rtmgr, txindex, sender, receiver, bitcoind, interval,
			broadcast: vec![],
		}
	}

	pub fn broadcast_handle(&self) -> TxBroadcastHandle {
		TxBroadcastHandle {
			sender: self.sender.clone(),
			index: self.txindex.clone(),
		}
	}

	pub async fn run(mut self) -> anyhow::Result<()> {
		let mut interval = tokio::time::interval(self.interval);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

		loop {
			tokio::select! {
				msg = self.receiver.recv() => {
					match msg {
						Some(pkg) => {self.broadcast(&pkg).await;}
						None => {}
					}
				},
				_ = interval.tick() => {
					trace!("Starting to rebroadcast all transactions");
					self.rebroadcast().await;
				},
				_ = self.rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting rebroadcast loop...");
					return Ok(())
				}
			}
		}
	}

	async fn broadcast(&self, pkg: &[Txid]) {
		if pkg.len() == 1 {
			let txid = pkg[0];
			let lock = self.txindex.tx_map.read().await;
			let tx = lock.get(&txid).cloned();
			drop(lock);
			if let Some(tx) = tx {
				if !tx.status().await.confirmed() {
					slog!(BroadcastingTx, txid: tx.txid, raw_tx: serialize(&tx.tx));
					self.broadcast_tx(&tx).await;
				}
			} else {
				debug!("Instructed to broadcast a tx we don't know: {}", txid);
				return;
			}
		} else {
			let txs = self.txindex.get_batch(pkg).await;
			for (txid, opt_tx) in pkg.iter().zip(&txs) {
				if let Some(tx) = opt_tx {
					if ! tx.status().await.confirmed() {
						slog!(BroadcastingTx, txid: *txid, raw_tx: serialize(&tx.tx));
					}
				} else {
					debug!("Instructed to broadcast a tx we don't know: {}", txid);
				}
			}

			// Filter out all txs that are None
			let broadcast = txs.iter().filter_map(|tx| tx.clone()).collect::<Vec<_>>();
			self.broadcast_pkg(&broadcast).await;
		}
	}

	async fn rebroadcast(&mut self) {
		let mut i = 0;
		'outer: while i < self.broadcast.len() {
			let pkg = &self.broadcast[i];
			let txs = self.txindex.tx_map.read().await;
			for txid in pkg.iter() {
				let res = txs.get(txid);
				if res.is_none() || res.unwrap().status().await == TxStatus::Unregistered {
					debug!("Broadcast pkg has unknown or unregistered tx {}. Dropping", txid);
					self.broadcast.swap_remove(i);
					continue 'outer;
				}
			}
			self.broadcast(pkg).await;
			i += 1;
		}
	}

	async fn broadcast_tx(&self, tx: &Tx) {
		// Skip if tx already in mempool or confirmed.
		if tx.seen().await {
			return;
		}

		let bytes = serialize(&tx.tx);
		if let Err(e) = self.bitcoind.send_raw_transaction(&bytes) {
			log::warn!("Error when re-broadcasting one of our txs: {}", e);
			slog!(TxBroadcastError, txid: tx.txid, raw_tx: bytes, error: e.to_string());
		} else {
			log::trace!("Broadcasted tx {}", tx.txid);
		}
	}

	async fn broadcast_pkg(&self, pkg: &[Tx]) {
		// Skip if all txs in mempool.
		let mut skip = true;
		for tx in pkg {
			if !tx.seen().await {
				skip = false;
			}
		}
		if skip {
			return;
		}

		#[derive(Debug, Deserialize)]
		struct PackageTxInfo {
			txid: Txid,
			error: Option<String>,
		}
		#[derive(Debug, Deserialize)]
		struct SubmitPackageResponse {
			#[serde(rename = "tx-results")]
			tx_results: HashMap<Wtxid, PackageTxInfo>,
			package_msg: String,
		}

		let hexes = pkg.iter()
			.map(|t| bitcoin::consensus::encode::serialize_hex(&t.tx))
			.collect::<Vec<_>>();
		match self.bitcoind.call::<SubmitPackageResponse>("submitpackage", &[hexes.into()]) {
			Ok(r) if r.package_msg != "success" => {
				let errors = r.tx_results.values().map(|tx| {
					let raw_tx = pkg.iter().find(|t| t.txid == tx.txid)
						.map(|t| serialize(&t.tx))
						.expect("tx is part of our package");
					let error = tx.error.as_ref().map(|s| s.as_str()).unwrap_or("(no error)");
					slog!(TxBroadcastError, txid: tx.txid, raw_tx, error: error.to_owned());
					format!("tx {}: {}", tx.txid, error)
				}).collect::<Vec<_>>();
				warn!("Error broadcasting tx package: msg: '{}', errors: {:?}",
					r.package_msg, errors,
				);
			}
			Err(e) => {
				warn!("Error broadcasting tx package: {}", e);
			},
			Ok(_) => {},
		}
	}
}
