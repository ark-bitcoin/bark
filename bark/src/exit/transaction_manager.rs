use std::collections::HashMap;
use std::sync::{Arc, Weak};

use bitcoin::{Network, Transaction, Txid};
use log::{debug, error, info, trace, warn};
use tokio::sync::RwLock;

use ark::vtxo::Full;
use ark::Vtxo;
use bitcoin_ext::{BlockHeight, TransactionExt, TxStatus, DEEPLY_CONFIRMED};

use crate::chain::{BroadcastError, ChainSource};
use crate::exit::models::{
	ChildTransactionInfo, ExitChildStatus, ExitError, ExitTransactionPackage, ExitTxOrigin, FeeInfo,
	TransactionInfo,
};
use crate::persist::BarkPersister;

pub struct ExitTransactionManager {
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSource>,
	packages: Vec<Arc<RwLock<ExitTransactionPackage>>>,
	index: HashMap<Txid, Weak<RwLock<ExitTransactionPackage>>>,
	status: HashMap<Txid, TxStatus>,
	/// How many tracked exits reference each exit (parent) transaction. Sibling VTXOs share
	/// ancestor transactions in the exit tree, so a tx may be needed by several exits at once.
	refcount: HashMap<Txid, usize>,
}

impl ExitTransactionManager {
	pub fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSource>,
	) -> anyhow::Result<Self> {
		Ok(ExitTransactionManager {
			persister,
			chain_source,
			packages: Vec::new(),
			index: HashMap::new(),
			status: HashMap::new(),
			refcount: HashMap::new(),
		})
	}

	pub fn network(&self) -> Network {
		self.chain_source.network()
	}

	pub async fn track_vtxo_exits(
		&mut self,
		vtxo: &Vtxo<Full>,
	) -> anyhow::Result<Vec<Txid>, ExitError> {
		let exit_txs = vtxo.transactions();
		let mut txids = Vec::with_capacity(exit_txs.len());
		for tx in exit_txs {
			txids.push(self.track_exit_tx(tx.tx).await?);
		}
		Ok(txids)
	}

	pub async fn track_exit_tx(
		&mut self,
		tx: Transaction,
	) -> anyhow::Result<Txid, ExitError> {
		let txid = tx.compute_txid();
		if self.index.contains_key(&txid) {
			*self.refcount.entry(txid).or_insert(0) += 1;
			return Ok(txid);
		}

		trace!("Tracking exit tx {}", txid);

		let package = {
			let info = TransactionInfo { txid, tx };
			let child = self.find_child_in_database(&info).await?;
			trace!("Found local child for exit tx {}: {}", txid, child.is_some());
			ExitTransactionPackage {
				child,
				exit: info,
			}
		};
		let (status, child_txid) = match package.child.as_ref() {
			None => (TxStatus::NotFound, None),
			Some(child) => {
				if let Some(block) = child.origin.confirmed_in() {
					(TxStatus::Confirmed(block), Some(child.info.txid))
				}
				else {
					(TxStatus::Mempool, Some(child.info.txid))
				}
			}
		};
		let package = Arc::new(RwLock::new(package));
		self.index.insert(txid, Arc::downgrade(&package));
		if let Some(child_txid) = child_txid {
			self.index.insert(child_txid, Arc::downgrade(&package));
		}
		self.status.insert(txid, status);
		self.packages.push(package);
		*self.refcount.entry(txid).or_insert(0) += 1;
		Ok(txid)
	}

	/// Drops references to the given exit (parent) transactions, removing each from memory once
	/// no tracked exit references it any more. Used when an exit is canceled so we stop syncing
	/// its transactions; ancestor transactions still needed by sibling exits are retained.
	///
	/// `exit_txids` should be the txids returned by [Self::track_vtxo_exits] for the canceled exit.
	pub async fn untrack_vtxo_exits(&mut self, exit_txids: &[Txid]) {
		for txid in exit_txids {
			let remaining = match self.refcount.get_mut(txid) {
				Some(count) => {
					*count = count.saturating_sub(1);
					*count
				},
				None => {
					warn!("Attempt to untrack exit tx {} that isn't tracked", txid);
					continue;
				},
			};
			if remaining > 0 {
				trace!("Exit tx {} still referenced by {} exit(s), keeping it", txid, remaining);
				continue;
			}

			trace!("Dropping exit tx {} from the transaction manager", txid);
			self.refcount.remove(txid);

			// Grab the package (and its child txid) before we drop it so we can purge every
			// index entry that points at it.
			let package = self.index.get(txid).and_then(|w| w.upgrade());
			let child_txid = match &package {
				Some(p) => p.read().await.child.as_ref().map(|c| c.info.txid),
				None => None,
			};

			self.index.remove(txid);
			if let Some(child_txid) = child_txid {
				self.index.remove(&child_txid);
			}
			self.status.remove(txid);
			if let Some(package) = package {
				match self.packages.iter().position(|p| Arc::ptr_eq(p, &package)) {
					Some(pos) => {
						self.packages.swap_remove(pos);
					},
					None => warn!("package with txid {} should be in the list", txid),
				}
			}
		}
	}

	pub async fn sync(&mut self) -> anyhow::Result<(), ExitError> {
		trace!("Syncing exit transaction manager");
		self.update_tx_statuses().await
	}

	async fn update_tx_statuses(&mut self) -> anyhow::Result<(), ExitError> {
		let tip = self.tip().await?;
		let keys = self.status.keys().cloned().collect::<Vec<_>>();
		for txid in keys {
			// We should query the status of every transaction unless they're already deeply
			// confirmed
			let status = self.status.get(&txid).unwrap();
			if let TxStatus::Confirmed(block) = status {
				trace!("Skipping deeply confirmed exit tx {}", txid);
				if block.height <= (tip - DEEPLY_CONFIRMED) {
					continue;
				}
			}
			// Failures for one tx should not abort the whole sync. The most common cause is
			// a race between our status check and the chain source's view (e.g. esplora
			// reports a tx as mempool while bitcoind's mempool has already evicted or
			// confirmed it). Log and move on — the next sync tick will retry. Each exit's
			// own `progress()` call surfaces fatal problems via its per-VTXO error field.
			if let Err(e) = self.update_one_tx_status(txid, tip).await {
				warn!("Failed to update status for exit tx {}: {:#}", txid, e);
			}
		}
		Ok(())
	}

	async fn update_one_tx_status(
		&mut self,
		txid: Txid,
		tip: BlockHeight,
	) -> anyhow::Result<(), ExitError> {
		match self.index.get(&txid) {
			// If the transaction is not an exit package, we can just update its status
			None => {
				trace!("Updating status for non-exit tx {}", txid);
				self.status.insert(txid, self.get_tx_status(txid).await?);
			},
			// If the transaction is a package, we must query the status of both transactions
			Some(weak_ptr) => {
				trace!("Update status for exit tx {}", txid);
				let package = weak_ptr.upgrade().ok_or_else(|| ExitError::InternalError {
					error: "index contains a stale package".into(),
				})?;
				let status = self.get_tx_status(txid).await?;
				trace!("Exit tx {} old status {:?}, new status {:?}", txid, self.status.get(&txid), Some(status));

				match status {
					TxStatus::NotFound => {
						// Broadcast the current package if we have one
						match self.broadcast_package(&*package.read().await).await {
							Ok(_) => {},
							Err(ExitError::ExitPackageBroadcastFailure { error, .. }) => {
								// We can just swallow these errors instead of stopping the
								// entire syncing process
								error!("{}", error);
							},
							Err(e) => {
								return Err(e);
							},
						}
					},
					_ => {
						// We should update/redownload from the network as a newer child
						// transaction may exist in the mempool or in a confirmed block.
						// We will skip this step once a transaction is deeply confirmed.
						trace!("Attempting to update child status from network for exit tx {}", txid);
						let status = self.update_package_from_network(
							&package,
							status.confirmed_height().unwrap_or(tip),
						).await?;
						self.status.insert(txid, status);
					},
				}
			}
		}
		Ok(())
	}

	pub async fn get_child_status(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<ExitChildStatus>, ExitError> {
		let package = self.get_package(exit_txid)?;
		let guard = package.read().await;
		if let Some(child) = &guard.child {
			Ok(Some(ExitChildStatus {
				txid: child.info.txid,
				status: self.status.get(&exit_txid).cloned().ok_or_else(|| ExitError::InternalError {
					error: "status should be set".into(),
				})?,
				fee_info: child.fee_info,
				origin: child.origin,
			}))
		} else {
			Ok(None)
		}
	}

	pub async fn get_child_txid(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<Txid>, ExitError> {
		let package = self.get_package(exit_txid)?;
		let guard = package.read().await;
		if let Some(child) = &guard.child {
			Ok(Some(child.info.txid))
		} else {
			Ok(None)
		}
	}

	pub fn get_package(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Arc<RwLock<ExitTransactionPackage>>, ExitError> {
		self.index.get(&exit_txid)
			.ok_or(ExitError::InternalError {
				error: format!("Attempt to get package for untracked exit tx: {}", exit_txid),
			})?.upgrade()
			.ok_or(ExitError::InternalError {
				error: format!("Attempt to get package for stale exit tx: {}", exit_txid),
			})
	}

	pub async fn tx_status(&mut self, txid: Txid) -> anyhow::Result<TxStatus, ExitError> {
		if let Some(status) = self.status.get(&txid) {
			Ok(status.clone())
		} else {
			let status = self.get_tx_status(txid).await?;
			self.status.insert(txid, status.clone());
			Ok(status)
		}
	}

	pub async fn set_wallet_child_tx(
		&mut self,
		exit_txid: Txid,
		child_tx: Transaction,
		origin: ExitTxOrigin,
	) -> anyhow::Result<Txid, ExitError> {
		let package = self.get_package(exit_txid)?;
		let child_txid = child_tx.compute_txid();
		package.write().await.child = Some(ChildTransactionInfo {
			info: TransactionInfo {
				txid: child_txid,
				tx: child_tx.clone(),
			},
			origin,
			// Populated by the next sync via [calculate_fee_params] once the child is in the
			// mempool. Not provided here because the API doesn't immediately require it and having
			// devs provide it could lead to incorrect data
			fee_info: None,
		});
		self.index.insert(child_txid, Arc::downgrade(&package));
		self.status.insert(exit_txid, TxStatus::NotFound);
		self.persister.store_exit_child_tx(exit_txid, &child_tx, origin).await
			.map_err(|e| ExitError::DatabaseChildStoreFailure { error: e.to_string() })?;
		Ok(child_txid)
	}

	pub async fn broadcast_package(
		&mut self,
		package: &ExitTransactionPackage,
	) -> Result<TxStatus, ExitError> {
		// Set the default status first in case we error out
		if !self.status.contains_key(&package.exit.txid) {
			self.status.insert(package.exit.txid, TxStatus::NotFound);
		}
		let status = match &package.child {
			None => {
				trace!("Skipping broadcast of exit package with no CPFP: {}", package.exit.txid);
				TxStatus::NotFound
			},
			Some(child) => {
				self.chain_source.broadcast_package(&[
						&package.exit.tx, &child.info.tx
					]).await
					.map_err(|e| ExitError::ExitPackageBroadcastFailure {
						txid: package.exit.txid,
						error: e,
					})?;

				info!("Successfully broadcast exit package: {}", package.exit.txid);
				TxStatus::Mempool
			}
		};
		self.status.insert(package.exit.txid, status);
		Ok(status)
	}

	async fn tip(&self) -> anyhow::Result<BlockHeight, ExitError> {
		self.chain_source.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })
	}

	async fn get_tx_status(&self, txid: Txid) -> anyhow::Result<TxStatus, ExitError> {
		self.chain_source.tx_status(txid).await
			.map_err(|e| ExitError::TransactionRetrievalFailure { txid, error: e.to_string() })
	}

	async fn find_child_in_database(
		&self,
		exit_info: &TransactionInfo,
	) -> Result<Option<ChildTransactionInfo>, ExitError> {
		trace!("Looking for child in database for exit tx {}", exit_info.txid);
		let result = self.persister.get_exit_child_tx(exit_info.txid).await
			.map_err(|e| ExitError::DatabaseChildRetrievalFailure { error: e.to_string() })?;
		trace!("Database lookup complete for exit tx {}", exit_info.txid);

		if let Some((tx, origin)) = result {
			Ok(Some(ChildTransactionInfo {
				info: TransactionInfo {
					txid: tx.compute_txid(),
					tx,
				},
				origin,
				// We don't persist fee info; it will be repopulated from the network on the
				// next sync if the child is still unconfirmed.
				fee_info: None,
			}))
		} else {
			Ok(None)
		}
	}

	async fn update_package_from_network(
		&self,
		package: &RwLock<ExitTransactionPackage>,
		block_scan_start: BlockHeight,
	) -> anyhow::Result<TxStatus, ExitError> {
		// Scan the mempool and chain to see if the anchor output is spent
		let outpoint = {
			let guard = package.read().await;
			let (outpoint, _) = guard.exit.tx.fee_anchor()
				.ok_or_else(|| ExitError::MissingAnchorOutput { txid: guard.exit.txid })?;
			outpoint
		};
		let spend_results = self.chain_source
			.txs_spending_inputs([outpoint.clone()], block_scan_start)
			.await
			.map_err(|e| ExitError::TransactionRetrievalFailure {
				txid: outpoint.txid, error: e.to_string(),
			})?;
		debug!("txs_spending_inputs for {}: {:?}", outpoint, spend_results);

		let Some((new_txid, status)) = spend_results.get(&outpoint) else {
			return Ok(TxStatus::NotFound);
		};
		let mut guard = package.write().await;

		// If the chain still reports our existing child, just refresh its origin (and
		// populate fee info if we don't have it yet — true for both wallet- and
		// network-sourced children).
		if let Some(c) = guard.child.as_mut() {
			if c.info.txid == *new_txid {
				let updated_origin = c.origin.with_confirmed_in(status.confirmed_in());
				trace!("Refreshing child {} for exit {}: origin {:?} -> {:?}",
					new_txid, outpoint.txid, c.origin, updated_origin,
				);
				c.origin = updated_origin;
				if status.confirmed_in().is_none() && c.fee_info.is_none() {
					c.fee_info = self.try_calculate_fee_params(*new_txid).await;
				}
				return Ok(status.clone());
			}
		}

		// The chain reports a different spending tx than our local child. If our local child
		// is wallet-built and the chain's tx is unconfirmed, try to (re-)broadcast our package
		// first. The chain may simply be lagging behind our broadcast (esplora-electrs in
		// particular indexes mempool txs out-of-band), or we may have been RBF'd — letting
		// Bitcoin Core's mempool policy decide which child wins avoids us second-guessing
		// our local fee rate. If the broadcast is rejected, accept the chain's tx.
		let local_is_wallet = guard.child.as_ref()
			.is_some_and(|c| matches!(c.origin, ExitTxOrigin::Wallet { .. }));
		if local_is_wallet && status.confirmed_in().is_none() {
			let local = guard.child.as_ref().unwrap();
			let broadcast_res = self.chain_source.broadcast_package(&[
				&guard.exit.tx, &local.info.tx,
			]).await;
			let kept = match broadcast_res {
				Ok(()) => {
					info!("Re-broadcast wallet child {} for exit {} succeeded — \
						keeping it over chain-reported tx {}",
						local.info.txid, outpoint.txid, new_txid,
					);
					true
				},
				Err(BroadcastError::AlreadyKnown) => {
					trace!("Wallet child {} already in mempool for exit {} — keeping it",
						local.info.txid, outpoint.txid,
					);
					true
				},
				Err(e) => {
					info!("Accepting chain's tx {}, wallet child {} for exit {} rejected {:#}",
						new_txid, local.info.txid, outpoint.txid, e,
					);
					false
				},
			};
			if kept {
				// Best-effort fee info population: the chain source may not have indexed the
				// just-broadcast tx yet, in which case ancestor info comes back NotFound. The
				// next sync will retry.
				if guard.child.as_ref().unwrap().fee_info.is_none() {
					let local_txid = guard.child.as_ref().unwrap().info.txid;
					if let Some(fi) = self.try_calculate_fee_params(local_txid).await {
						guard.child.as_mut().unwrap().fee_info = Some(fi);
					}
				}
				return Ok(status.clone());
			}
		}

		// At this point we must adopt the chain's tx as the new child.
		info!("Downloading child tx {} for exit {}", new_txid, outpoint.txid);
		let tx = match self.chain_source.get_tx(new_txid).await {
			Ok(Some(tx)) => Ok(tx),
			Ok(None) => Err(ExitError::TransactionRetrievalFailure {
				txid: *new_txid, error: "Spending transaction was unexpectedly missing".into(),
			}),
			Err(e) => Err(ExitError::TransactionRetrievalFailure {
				txid: *new_txid, error: e.to_string(),
			}),
		}?;
		info!("Successfully downloaded child tx {} for exit {}", new_txid, outpoint.txid);

		let (origin, fee_info) = if let Some(block) = status.confirmed_in() {
			(ExitTxOrigin::Block { confirmed_in: block }, None)
		} else {
			match self.calculate_fee_params(*new_txid).await {
				Ok(info) => (ExitTxOrigin::Mempool, Some(info)),
				Err(ExitError::AncestorRetrievalFailure { error, .. }) => {
					// The tx may have been confirmed between when we checked its status
					// and now. Re-check before treating this as a real error.
					let new_status = self.get_tx_status(*new_txid).await?;
					if let Some(block) = new_status.confirmed_in() {
						debug!("Child tx {} was confirmed while querying mempool info", new_txid);
						(ExitTxOrigin::Block { confirmed_in: block }, None)
					} else {
						return Err(ExitError::AncestorRetrievalFailure {
							txid: *new_txid, error,
						});
					}
				},
				Err(e) => return Err(e),
			}
		};

		debug!("Storing child tx {} with origin {} in database", new_txid, origin);
		if let Err(e) = self.persister.store_exit_child_tx(outpoint.txid, &tx, origin).await {
			// Not fatal: the same tx can be re-downloaded later if it hasn't been replaced.
			error!("Failed to store confirmed exit child transaction: {:#}", e);
		}

		guard.child = Some(ChildTransactionInfo {
			info: TransactionInfo { txid: *new_txid, tx },
			origin,
			fee_info,
		});
		Ok(status.clone())
	}

	/// Query the chain source for a tx's effective fee rate and total package fee.
	async fn calculate_fee_params(&self, txid: Txid) -> Result<FeeInfo, ExitError> {
		debug!("Getting mempool ancestor information for {}", txid);
		let info = self.chain_source
			.mempool_ancestor_info(txid)
			.await
			.map_err(|e| ExitError::AncestorRetrievalFailure {
				txid, error: e.to_string(),
			})?;
		let fee_rate = info.effective_fee_rate()
			.ok_or_else(|| ExitError::AncestorRetrievalFailure {
				txid,
				error: format!("unable to calculate fee rate for {}", txid),
			})?;
		Ok(FeeInfo { fee_rate, total_fee: info.total_fee })
	}

	/// Best-effort variant of [`calculate_fee_params`]: returns `None` (and logs) when the
	/// chain source can't yet produce ancestor info — typically because we just broadcast
	/// the tx and the indexer hasn't caught up. The next sync will retry.
	async fn try_calculate_fee_params(&self, txid: Txid) -> Option<FeeInfo> {
		match self.calculate_fee_params(txid).await {
			Ok(info) => Some(info),
			Err(e) => {
				debug!("Skipping fee info for {} this round: {:#}", txid, e);
				None
			},
		}
	}
}
