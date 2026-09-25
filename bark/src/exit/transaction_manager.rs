use std::collections::HashMap;
use std::sync::{Arc, Weak};

use bitcoin::{Network, OutPoint, Transaction, Txid};
use log::{debug, error, info, trace, warn};
use tokio::sync::RwLock;

use ark::vtxo::Full;
use ark::Vtxo;
use bitcoin_ext::{BlockDelta, BlockHeight, TransactionExt, TxStatus};

use crate::chain::{BroadcastError, ChainSource};
use crate::exit::models::{
	ChildTransactionInfo, ExitChildStatus, ExitError, ExitTransactionPackage, ExitTxOrigin, FeeInfo,
	TransactionInfo,
};
use crate::persist::BarkPersister;

/// How deep a spend of an exit input must be buried before it ends the exit.
///
/// Ending an exit is irreversible, so a spend that a reorg could still undo must not do it. It
/// also bounds the block scan in [ExitTransactionManager::find_conflicting_spend]: a spend the
/// scan doesn't find within this many blocks of the tip is older than the window, and therefore
/// deep enough to act on.
const SPEND_CONFIRMATIONS: BlockDelta = BlockDelta::new(6);

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
			let (child_txid, _) = match &package {
				Some(p) => {
					let guard = p.read().await;
					(
						guard.child.as_ref().map(|c| c.info.txid),
						guard.exit.tx.input.iter().map(|i| i.previous_output).collect::<Vec<_>>(),
					)
				},
				None => (None, Vec::new()),
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

	/// Refreshes the chain status of a single exit transaction and returns it.
	pub async fn sync_exit_tx(&mut self, txid: Txid) -> anyhow::Result<TxStatus, ExitError> {
		trace!("Refreshing status of exit tx {} without rebroadcasting", txid);
		let tip = self.tip().await?;
		self.update_one_tx_status(txid, tip, false).await?;
		self.tx_status(txid).await
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
				if block.height <= tip.saturating_sub(SPEND_CONFIRMATIONS) {
					continue;
				}
			}
			// Failures for one tx should not abort the whole sync. The most common cause is
			// a race between our status check and the chain source's view (e.g. esplora
			// reports a tx as mempool while bitcoind's mempool has already evicted or
			// confirmed it). Log and move on — the next sync tick will retry. Each exit's
			// own `progress()` call surfaces fatal problems via its per-VTXO error field.
			if let Err(e) = self.update_one_tx_status(txid, tip, true).await {
				warn!("Failed to update status for exit tx {}: {:#}", txid, e);
			}
		}
		Ok(())
	}

	async fn update_one_tx_status(
		&mut self,
		txid: Txid,
		tip: BlockHeight,
		broadcast_local: bool,
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
					TxStatus::NotFound if broadcast_local => {
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
							broadcast_local,
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

	/// Returns the package for an exit tx if the manager is tracking it.
	pub fn try_get_package(&self, exit_txid: Txid) -> Option<Arc<RwLock<ExitTransactionPackage>>> {
		self.index.get(&exit_txid)?.upgrade()
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

	/// Returns the inputs of `exit_txid` that something else has already spent, which makes
	/// `exit_txid` unconfirmable.
	///
	/// Only spends buried under [SPEND_CONFIRMATIONS] blocks are reported: a spend in the
	/// mempool can still be replaced, and a freshly mined one can still be reorged out, while
	/// ending an exit cannot be undone.
	///
	/// An empty result means no such spend was found, never that the lookup was inconclusive: a
	/// chain failure is reported as `Err`.
	pub async fn find_conflicting_spend(
		&mut self,
		tip: BlockHeight,
		exit_txid: Txid,
	) -> anyhow::Result<Vec<OutPoint>, ExitError> {
		let inputs = {
			let package = self.get_package(exit_txid)?;
			let guard = package.read().await;
			guard.exit.tx.input.iter().map(|i| i.previous_output).collect::<Vec<_>>()
		};

		// Until the parent confirms, the output doesn't exist on chain and nothing can have spent
		// it.
		let mut to_scan = Vec::with_capacity(inputs.len());
		for input in inputs {
			// Also what makes the utxo set usable below: `gettxout` reports a spent output and
			// one whose tx isn't mined yet alike, so only a confirmed parent makes its absence
			// mean "spent".
			let TxStatus::Confirmed(_) = self.tx_status(input.txid).await? else {
				// We are only called once every input has confirmed. Skipping quietly would
				// report "no conflicting spend" for an input we never looked at.
				warn!("Exit tx {} has unconfirmed input {}, skipping it while looking for \
					conflicting spends", exit_txid, input,
				);
				continue;
			};
			// An input still in the utxo set has no confirmed spender, which is the whole
			// question for every input but the rare swept one. The scan below is only needed to
			// name the spender and the block it confirmed in.
			let spent = self.chain_source.outpoint_spent_confirmed(input).await
				.map_err(|e| ExitError::TransactionRetrievalFailure {
					txid: exit_txid, error: e.to_string(),
				})?;
			if !spent {
				continue;
			}
			to_scan.push(input);
		}

		// Every input is still in the utxo set, which is the answer for all but the rare swept
		// exit. Returning here is what keeps the healthy case off the chain entirely, rather than
		// walking the window and the mempool to find nothing.
		if to_scan.is_empty() {
			return Ok(Vec::new());
		}

		// The scan only has to answer how deep each spend is, not find it: the gate above already
		// established that every input here is spent. A window of the last [SPEND_CONFIRMATIONS]
		// blocks decides that, and bounds the walk to a constant instead of the whole chain since
		// the input's parent confirmed.
		let scan_start = tip.saturating_sub(SPEND_CONFIRMATIONS);

		// One scan covers every input: the bitcoind backend walks blocks from the start height
		// looking for the whole set at once, so asking per input would walk them once each.
		let spends = self.chain_source
			.txs_spending_inputs(to_scan.clone(), scan_start).await
			.map_err(|e| ExitError::TransactionRetrievalFailure {
				txid: exit_txid, error: e.to_string(),
			})?;

		// Reading the scan the other way round: every input here is spent, so finding its spender
		// in the window means the spend is recent and a reorg could still undo it, while not
		// finding one means the spend predates the window and is settled.
		let mut deeply_spent = Vec::with_capacity(to_scan.len());
		for input in to_scan {
			match spends.get(&input) {
				Some((txid, TxStatus::Confirmed(_) | TxStatus::Mempool)) => {
					warn!("Exit tx {} has a spend of input {} by {} within the last {} blocks, \
						too recent to end the exit on", exit_txid, input, txid, SPEND_CONFIRMATIONS,
					);
				},
				// The scan only records spends it found, so it never reports this. Spelled out
				// rather than folded into a catch-all so that changing that is a compile error
				// here: a status we can't interpret must not end an exit.
				Some((_, TxStatus::NotFound)) => {
					warn!("Exit tx {} got an unexpected NotFound spend status for input {}, \
						leaving the exit running", exit_txid, input,
					);
				},
				None => deeply_spent.push(input),
			}
		}

		// A confirmed exit tx spends its own inputs, and once it is older than the window the
		// scan can no longer tell that apart from a sweep - it finds no spender either way. The
		// caller refreshes statuses before asking, so a confirmed exit tx shouldn't reach here,
		// but reading that off the chain rather than the cache keeps a successful exit from
		// terminating as swept if it ever does.
		if !deeply_spent.is_empty() {
			if let TxStatus::Confirmed(block) = self.get_tx_status(exit_txid).await? {
				warn!("Exit tx {} confirmed in block {} while its inputs looked spent, so the \
					spends are its own", exit_txid, block.height,
				);
				self.status.insert(exit_txid, TxStatus::Confirmed(block));
				return Ok(Vec::new());
			}
		}

		Ok(deeply_spent)
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
		self.status.insert(exit_txid, TxStatus::Mempool);
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

	/// Broadcast a freshly-built CPFP `child_tx` for `exit_txid` and commit it to the
	/// exit package **only if it was accepted**.
	///
	/// Returns whether the child was committed.
	pub async fn broadcast_and_set_child(
		&mut self,
		exit_txid: Txid,
		child_tx: Transaction,
		origin: ExitTxOrigin,
	) -> Result<bool, ExitError> {
		let parent_tx = self.get_package(exit_txid)?.read().await.exit.tx.clone();
		match self.chain_source.broadcast_package(&[&parent_tx, &child_tx]).await {
			Ok(()) => {
				info!("Successfully broadcast exit package: {}", exit_txid);
				self.set_wallet_child_tx(exit_txid, child_tx, origin).await?;
				Ok(true)
			},
			// An input is already spent by a confirmed tx, so this CPFP can never confirm —
			// for a freshly-built CPFP that's our own fee input, consumed by a sibling exit
			// tx's CPFP that reused the same wallet UTXO. Don't commit it: the exit stays in
			// AwaitingCpfpBroadcast and a fresh CPFP is built next tick. (A competing CPFP
			// contesting the *shared anchor* instead surfaces as a mempool conflict and is
			// resolved by `update_package_from_network`, which RBFs or adopts it — so it
			// doesn't reach here, and not committing is safe either way.)
			Err(BroadcastError::MissingOrSpentInputs) => {
				warn!("Discarding exit CPFP for {}: an input is already spent — will rebuild \
					from spendable UTXOs", exit_txid,
				);
				Ok(false)
			},
			// An equivalent CPFP is already in the mempool, or RBF rejected our bump: commit
			// ours anyway, the in-mempool package will confirm the exit.
			Err(ref e) if e.is_mempool_conflict() => {
				warn!("CPFP broadcast conflict for {}: {} — another CPFP may already be in \
					mempool", exit_txid, e,
				);
				self.set_wallet_child_tx(exit_txid, child_tx, origin).await?;
				Ok(true)
			},
			Err(e) => Err(ExitError::ExitPackageBroadcastFailure { txid: exit_txid, error: e }),
		}
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
		broadcast_local: bool,
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
				// Persist transitions so a wallet reload reports the correct
				// confirmation state before its first successful chain sync.
				if updated_origin != c.origin {
					let store_result = self.persister
						.store_exit_child_tx(outpoint.txid, &c.info.tx, updated_origin).await;
					if let Err(e) = store_result {
						// Not fatal: the in-memory origin is correct and the row will be
						// refreshed by a later transition or child adoption.
						error!("Failed to store updated exit child transaction: {:#}", e);
					}
				}
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
			let kept = if !broadcast_local { false } else {
				let broadcast_res = self.chain_source.broadcast_package(&[
					&guard.exit.tx, &local.info.tx,
				]).await;
				match broadcast_res {
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
				}
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

// The manager needs a persister, and the sqlite one is the only in-memory implementation we
// have. That rules these out for the wasm builds, which are compiled without that feature.
#[cfg(all(test, feature = "sqlite"))]
mod test {
	use bitcoin::hashes::Hash;
	use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
	use rusqlite::Connection;

	use bitcoin_ext::BlockRef;

	use crate::persist::sqlite::SqliteClient;
	use crate::persist::sqlite::helpers::in_memory_db;

	use super::*;

	fn txid(n: u8) -> Txid {
		Txid::from_byte_array([n; 32])
	}

	fn block(height: u32) -> BlockRef {
		BlockRef {
			height: BlockHeight::new(height),
			hash: bitcoin::BlockHash::from_byte_array([7; 32]),
		}
	}

	fn confirmed(height: u32) -> TxStatus {
		TxStatus::Confirmed(block(height))
	}

	/// An exit tx spending each of `parents`, which stand in for the outputs of the tx above it
	/// in the exit chain.
	fn exit_tx(parents: &[OutPoint]) -> Transaction {
		Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: parents.iter().map(|p| TxIn {
				previous_output: *p,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
				witness: Witness::new(),
			}).collect(),
			output: vec![TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::new() }],
		}
	}

	/// A manager whose chain source is unroutable, so any call that reaches the chain fails
	/// instead of passing quietly. The connection is returned because dropping it drops the
	/// in-memory database with it.
	fn manager() -> (ExitTransactionManager, Connection) {
		let (path, conn) = in_memory_db();
		let db = SqliteClient::open(path).unwrap();
		let chain = Arc::new(ChainSource::offline_for_test(Network::Regtest));
		(ExitTransactionManager::new(Arc::new(db), chain).unwrap(), conn)
	}

	#[tokio::test]
	async fn an_uncached_confirmed_input_reaches_for_the_chain() {
		let (mut mgr, _conn) = manager();
		let parent = OutPoint::new(txid(1), 0);
		let exit = mgr.track_exit_tx(exit_tx(&[parent])).await.unwrap();
		mgr.status.insert(parent.txid, confirmed(100));
		// Passed in rather than fetched, so the failure under test is the lookup's own and not
		// the tip fetch panicking on the same unroutable source before we get there.
		let tip = BlockHeight::new(200);

		// A confirmed parent is the one case that has to ask the chain. Reaching the unroutable
		// chain source fails, which is what keeps this from passing by never getting that far.
		assert!(mgr.find_conflicting_spend(tip, exit).await.is_err());
	}
}
