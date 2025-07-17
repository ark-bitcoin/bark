use std::collections::HashMap;
use std::sync::{Arc, Weak};

use bdk_wallet::chain::ChainPosition;
use bitcoin::{Network, Transaction, Txid};
use log::{debug, error, info, trace};
use tokio::sync::RwLock;

use ark::Vtxo;
use bitcoin_ext::{BlockHeight, BlockRef, TransactionExt, DEEPLY_CONFIRMED};
use bitcoin_ext::rpc::TxStatus;
use json::exit::error::ExitError;
use json::exit::package::{ChildTransactionInfo, ExitTransactionPackage, TransactionInfo};
use json::exit::states::ExitTxOrigin;

use crate::onchain::{self, ChainSourceClient};
use crate::persist::BarkPersister;

#[derive(Clone, Copy, Debug,  Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitChildStatus {
	pub txid: Txid,
	pub status: TxStatus,
	pub origin: ExitTxOrigin,
}

pub struct ExitTransactionManager {
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSourceClient>,
	packages: Vec<Arc<RwLock<ExitTransactionPackage>>>,
	index: HashMap<Txid, Weak<RwLock<ExitTransactionPackage>>>,
	status: HashMap<Txid, TxStatus>,
}

impl ExitTransactionManager {
	pub fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSourceClient>,
	) -> anyhow::Result<Self> {
		Ok(ExitTransactionManager {
			persister,
			chain_source,
			packages: Vec::new(),
			index: HashMap::new(),
			status: HashMap::new(),
		})
	}

	pub fn network(&self) -> Network {
		self.chain_source.network()
	}

	pub async fn track_vtxo_exits(
		&mut self,
		vtxo: &Vtxo,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<Vec<Txid>, ExitError> {
		let exit_txs = vtxo.transactions();
		let mut txids = Vec::with_capacity(exit_txs.len());
		for tx in exit_txs {
			txids.push(self.track_exit_tx(tx.tx, onchain).await?);
		}
		Ok(txids)
	}

	pub async fn track_exit_tx(
		&mut self,
		tx: Transaction,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<Txid, ExitError> {
		let txid = tx.compute_txid();
		if self.index.contains_key(&txid) {
			return Ok(txid);
		}

		// We should check the wallet/database to see if we have a child transaction stored locally
		let package = ExitTransactionPackage {
			exit: TransactionInfo { txid, tx },
			child: self.find_child_locally(txid, onchain)?,
		};
		let (status, child_txid) = match package.child.as_ref() {
			None => (TxStatus::NotFound, None),
			Some(child) => {
				if let Some(block) = child.confirmed_in {
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
		Ok(txid)
	}

	pub async fn sync(&mut self) -> anyhow::Result<(), ExitError> {
		let tip = self.tip().await?;

		let keys = self.status.keys().cloned().collect::<Vec<_>>();
		for txid in keys {
			// We should query the status of every transaction unless they're already deeply
			// confirmed
			let status = self.status.get(&txid).unwrap();
			if let TxStatus::Confirmed(block) = status {
				if block.height <= (tip - DEEPLY_CONFIRMED) {
					continue;
				}
			}
			match self.index.get(&txid) {
				// If the transaction is not an exit package, we can just update its status
				None => {
					self.status.insert(txid, self.get_tx_status(txid).await?);
				},
				// If the transaction is a package, we must query the status of both transactions
				Some(weak_ptr) => {
					let package = weak_ptr.upgrade().expect("index contains a stale package");
					let status = self.get_tx_status(txid).await?;
					match status {
						TxStatus::NotFound => {
							// Broadcast the current package if we have one
							match self.broadcast_package(&*package.read().await).await {
								Ok(()) => continue,
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
							let status = self.update_child_from_network(
								&package,
								status.confirmed_height().unwrap_or(tip),
							).await?;
							self.status.insert(txid, status);
						},
					}
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
				status: self.status.get(&exit_txid).cloned().expect("status should be set"),
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

	pub async fn update_child_tx(
		&mut self,
		exit_txid: Txid,
		child_tx: Transaction,
	) -> anyhow::Result<Txid, ExitError> {
		let package = self.get_package(exit_txid)?;
		let child_txid = child_tx.compute_txid();
		package.write().await.child = Some(ChildTransactionInfo {
			info: TransactionInfo {
				txid: child_txid,
				tx: child_tx,
			},
			origin: ExitTxOrigin::Wallet,
			confirmed_in: None
		});
		self.index.insert(child_txid, Arc::downgrade(&package));
		self.status.insert(exit_txid, TxStatus::NotFound);
		Ok(child_txid)
	}

	pub async fn broadcast_package(
		&mut self,
		package: &ExitTransactionPackage,
	) -> Result<(), ExitError> {
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
						error: e.to_string(),
					})?;

				info!("Successfully broadcast exit package: {}", package.exit.txid);
				TxStatus::Mempool
			}
		};
		self.status.insert(package.exit.txid, status);
		Ok(())
	}

	async fn tip(&self) -> anyhow::Result<BlockHeight, ExitError> {
		self.chain_source.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })
	}

	async fn get_tx_status(&self, txid: Txid) -> anyhow::Result<TxStatus, ExitError> {
		self.chain_source.tx_status(&txid).await
			.map_err(|e| ExitError::TransactionRetrievalFailure { txid, error: e.to_string() })
	}

	fn find_child_locally(
		&self,
		exit_txid: Txid,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<Option<ChildTransactionInfo>, ExitError> {
		let wallet = Self::find_child_in_wallet(exit_txid, onchain)?;
		if wallet.is_some() {
			Ok(wallet)
		} else {
			self.find_child_in_database(exit_txid)
		}
	}

	fn find_child_in_wallet(
		exit_txid: Txid,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<Option<ChildTransactionInfo>, ExitError> {
		// Check if we have a CPFP tx in our wallet
		if let Some(child_tx) = onchain.get_spending_tx(exit_txid) {
			let child_txid = child_tx.compute_txid();
			let child_wallet_tx = onchain.wallet.get_tx(child_txid)
				.ok_or(ExitError::InvalidWalletState {
					error: format!("no corresponding WalletTx for CPFP: {}", child_txid),
				})?;

			// Check whether it is confirmed or not
			let block = match child_wallet_tx.chain_position {
				ChainPosition::Confirmed { anchor, .. } => Some(BlockRef::from(anchor.block_id)),
				_ => None,
			};
			Ok(Some(ChildTransactionInfo {
				info: TransactionInfo {
					txid: child_txid,
					tx: (*child_tx).clone(),
				},
				origin: ExitTxOrigin::Wallet,
				confirmed_in: block,
			}))
		} else {
			Ok(None)
		}
	}

	fn find_child_in_database(
		&self,
		exit_txid: Txid,
	) -> Result<Option<ChildTransactionInfo>, ExitError> {
		let result = self.persister.get_exit_child_tx(exit_txid)
			.map_err(|e| ExitError::DatabaseChildRetrievalFailure { error: e.to_string() })?;
		if let Some((tx, block)) = result {
			Ok(Some(ChildTransactionInfo::from_block(
				TransactionInfo {
					txid: tx.compute_txid(),
					tx,
				},
				block,
			)))
		} else {
			Ok(None)
		}
	}

	async fn update_child_from_network(
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

		// Check if we need to download a new child or update the status of the current child
		if let Some((txid, status)) = spend_results.get(&outpoint) {
			let mut guard = package.write().await;

			// We only need to update the confirmation block for wallet transactions which haven't
			// been replaced
			let current_txid = if let Some(child) = guard.child.as_mut() {
				if matches!(child.origin, ExitTxOrigin::Wallet) && child.info.txid == *txid {
					child.confirmed_in = status.confirmed_in();
					return Ok(status.clone());
				}
				Some(child.info.txid.clone())
			} else {
				None
			};

			// We should download a newer transaction if necessary
			let tx = if current_txid.is_none() || current_txid.is_some_and(|t| t != *txid) {
				info!("Downloading child tx {} for exit {}", txid, outpoint.txid);
				let tx = self.chain_source.get_tx(txid)
					.await
					.map_err(|e| ExitError::TransactionRetrievalFailure {
						txid: *txid, error: e.to_string(),
					})?.expect("Spending transaction should exist");
				info!("Successfully downloaded child tx {} for exit {}", txid, outpoint.txid);
				tx
			} else {
				debug!("Skipping download of child txid {} for exit {}", txid, outpoint.txid);
				guard.child.as_ref().unwrap().info.tx.clone()
			};

			// Update the transaction we store in the database
			let block = status.confirmed_in();
			let r = self.persister.store_exit_child_tx(
				outpoint.txid, &tx, block,
			);
			if let Err(e) = r {
				error!("Failed to store confirmed exit child transaction: {}", e);
			}

			// Finally, update the child transaction
			guard.child = Some(ChildTransactionInfo::from_block(
				TransactionInfo { txid: *txid, tx },
				block,
			));
			Ok(status.clone())
		} else {
			Ok(TxStatus::NotFound)
		}
	}
}
