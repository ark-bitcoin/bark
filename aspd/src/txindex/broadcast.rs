use std::collections::HashMap;

use bitcoin::{Txid, Transaction, Wtxid};
use bitcoin::consensus::encode::serialize;
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bitcoin_ext::rpc::BitcoinRpcClient;
use log::{trace, debug, info, warn};
use tokio::sync::mpsc;

use crate::system::RuntimeManager;
use crate::txindex::{Tx, TxIndex};

#[derive(Clone)]
pub struct TxBroadcastHandle {
	sender: mpsc::UnboundedSender<Vec<Txid>>,
	txindex: TxIndex,
}

impl TxBroadcastHandle {
	/// Adds the transaction to TxIndex and ensures
	/// it will be broadcast
	pub async fn broadcast_tx(&self, tx: Transaction) -> anyhow::Result<Tx> {
		let ret = self.txindex.register(tx).await?;
		self.inner_broadcast(vec![ret.txid]);
		Ok(ret)
	}

	/// Adds the package to TxIndex and ensures it
	/// will be broadcast
	pub async fn broadcast_pkg(&self, pkg: impl Into<Vec<Transaction>>) -> anyhow::Result<Vec<Tx>> {
		let pkg = pkg.into();
		let mut ret = Vec::with_capacity(pkg.len());
		for tx in pkg {
			ret.push(self.txindex.register(tx).await?);
		}
		let txids = ret.iter().map(|t| t.txid).collect::<Vec<_>>();
		log::debug!("Registering tx package for broadcast: {:?}", txids);
		self.inner_broadcast(txids);
		Ok(ret)
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
			txindex: self.txindex.clone(),
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
			match self.txindex.get(txid).await {
				Ok(Some(tx)) => {
					if !tx.status().confirmed() {
						slog!(BroadcastingTx, txid: tx.txid, raw_tx: serialize(&tx.tx));
						self.broadcast_tx(&tx).await;
					}
				},
				Ok(None) => debug!("instructed to broadcast a tx we don't know: {}", txid),
				Err(e) => debug!("Error while fetching tx that must be broadcast {txid}: {e}"),
			}
		} else {
			let txs = self.txindex.get_batch(pkg).await;

			if let Err(e) = txs {
				debug!("Error while fetching broadcast pkg {pkg:?}: {e}");
				return
			}

			let txs = txs.expect("No error");

			for (txid, opt_tx) in pkg.iter().zip(&txs) {
				if let Some(tx) = opt_tx {
					if ! tx.status().confirmed() {
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
			let indexed_package = self.txindex.get_batch(&pkg).await;

			if let Err(e) = indexed_package {
				debug!("Failed to get package from index: {e}");
				continue 'outer
			}

			for (txid, indexed_tx) in pkg.iter().zip(indexed_package.expect("No error")) {
				if indexed_tx.is_none() {
					debug!("Broadcast pkg has unknown tx {}. Dropping", txid);
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
		if tx.seen() {
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
			if !tx.seen() {
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
