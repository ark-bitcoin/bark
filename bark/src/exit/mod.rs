pub(crate) mod progress;
pub(crate) mod transaction_manager;
pub mod vtxo;

use std::cmp;
use std::sync::Arc;

use bitcoin::Amount;
use log::{info, error, warn};

use ark::{Vtxo, VtxoId};
use bitcoin_ext::BlockHeight;
use json::cli::{ExitProgressStatus, ExitTransactionStatus};
use json::exit::ExitState;
use json::exit::error::ExitError;

use crate::exit::transaction_manager::ExitTransactionManager;
use crate::exit::vtxo::{ExitEntry, ExitVtxo};
use crate::onchain::{self, ChainSource, ChainSourceClient};
use crate::persist::BarkPersister;

/// Handle the process of ongoing VTXO exits
pub struct Exit {
	exit_vtxos: Vec<ExitVtxo>,
	tx_manager: ExitTransactionManager,
	persister: Arc<dyn BarkPersister>,
	chain_source: ChainSourceClient,
}

impl Exit {
	pub (crate) async fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: ChainSource,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<Exit> {
		let chain_source_client = ChainSourceClient::new(chain_source.clone())?;
		let mut tx_manager = ExitTransactionManager::new(persister.clone(), chain_source)?;

		// Gather the database entries for our exit and convert them into ExitVtxo structs
		let exit_vtxo_entries = persister.get_exit_vtxo_entries()?;
		let mut exit_vtxos = Vec::with_capacity(exit_vtxo_entries.len());
		for entry in exit_vtxo_entries {
			if let Some(vtxo) = persister.get_wallet_vtxo(entry.vtxo_id)? {
				let txids = tx_manager.track_vtxo_exits(&vtxo.vtxo, onchain).await?;
				exit_vtxos.push(ExitVtxo::from_parts(vtxo.vtxo, txids, entry.state, entry.history));
			} else {
				error!("VTXO {} is marked for exit but it's missing from the database", entry.vtxo_id);
			}
		}
		Ok(Exit {
			exit_vtxos,
			tx_manager,
			persister,
			chain_source: chain_source_client,
		})
	}

	pub async fn get_exit_status(
		&self,
		vtxo_id: VtxoId,
		include_history: bool,
		include_transactions: bool,
	) -> Result<Option<ExitTransactionStatus>, ExitError> {
		match self.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id) {
			None => Ok(None),
			Some(exit) => {
				let transactions = if include_transactions {
					let mut vec = Vec::with_capacity(exit.txids().len());
					for txid in exit.txids() {
						vec.push(self.tx_manager.get_package(*txid)?.read().await.clone());
					}
					Some(vec)
				} else {
					None
				};
				Ok(Some(ExitTransactionStatus {
					vtxo_id: exit.id(),
					state: exit.state().clone(),
					history: if include_history && !exit.history().is_empty() {
						Some(exit.history().clone())
					} else {
						None
					},
					transactions,
				}))
			},
		}
	}

	pub fn get_exit_vtxo(&self, vtxo_id: VtxoId) -> Option<&ExitVtxo> {
		self.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id)
	}

	pub fn get_exit_vtxos(&self) -> &Vec<ExitVtxo> {
		&self.exit_vtxos
	}

	pub fn has_pending_exits(&self) -> bool {
		self.exit_vtxos.iter().any(|ev| ev.state().is_pending())
	}

	/// Returns the total amount of all VTXOs requiring more txs to be confirmed
	pub async fn pending_total(&self) -> anyhow::Result<Amount> {
		let amount = self.exit_vtxos
			.iter()
			.filter_map(|ev| {
				if ev.state().is_pending() {
					Some(ev.vtxo().spec().amount)
				} else {
					None
				}
			}).sum();

		Ok(amount)
	}

	/// The height at which all exits will be spendable.
	///
	/// If None, some VTXOs require more transactions to be broadcast
	pub async fn all_spendable_at_height(&self) -> Option<BlockHeight> {
		let mut highest_spendable_height = None;
		for exit in &self.exit_vtxos {
			if matches!(exit.state(), ExitState::Spent(..)) {
				continue;
			}
			match exit.state().spendable_height() {
				Some(h) => highest_spendable_height = cmp::max(highest_spendable_height, Some(h)),
				None => return None,
			}
		}
		highest_spendable_height
	}

	/// Add all vtxos in the current wallet to the exit process.
	///
	/// It is recommended to sync with ASP before calling this
	pub async fn start_exit_for_entire_wallet(
		&mut self,
		onchain: &onchain::Wallet,
	) -> anyhow::Result<()> {
		let vtxos = self.persister.get_all_spendable_vtxos()?;
		self.start_exit_for_vtxos(&vtxos, onchain).await?;

		Ok(())
	}

	/// Add provided vtxo to the exit process.
	pub async fn start_exit_for_vtxos(
		&mut self,
		vtxos: &[Vtxo],
		onchain: &onchain::Wallet,
	) -> anyhow::Result<()> {
		if vtxos.is_empty() {
			warn!("There are VTXOs to exit!");
			return Ok(());
		}

		let tip = self.chain_source.tip().await?;
		for vtxo in vtxos {
			if self.exit_vtxos.iter().any(|ev| ev.id() == vtxo.id()) {
				warn!("VTXO {} is already in the exit process", vtxo.id());
				continue;
			} else {
				// The idea is to convert all our vtxos into an exit process structure
				// that we then store in the database, and we can gradually proceed on.
				let txids = self.tx_manager.track_vtxo_exits(vtxo, onchain).await?;
				let exit = ExitVtxo::new(vtxo.clone(), txids, tip);
				self.persister.store_exit_vtxo_entry(&ExitEntry::new(&exit))?;
				self.exit_vtxos.push(exit);
			}
		}
		Ok(())
	}

	/// Reset exit to an empty state. Should be called when dropping VTXOs
	///
	/// Note: _This method is **dangerous** and can lead to funds loss. Be cautious._
	pub (crate) fn clear_exit(&mut self) -> anyhow::Result<()> {
		for exit in &self.exit_vtxos {
			self.persister.remove_exit_vtxo_entry(&exit.id())?;
		}
		self.exit_vtxos.clear();
		Ok(())
	}

	/// Iterates over each registered VTXO and attempts to progress their unilateral exit
	///
	/// ### Arguments
	///
	/// - `onchain` is used to build the CPFP transaction package we use to broadcast
	///   the unilateral exit transaction
	///
	/// ### Return
	///
	/// The exit status of each VTXO being exited that has not yet been spent
	pub async fn progress_exit(
		&mut self,
		onchain: &mut onchain::Wallet,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		self.tx_manager.sync().await?;
		let mut exit_statuses = Vec::with_capacity(self.exit_vtxos.len());
		for ev in self.exit_vtxos.iter_mut() {
			info!("Progressing exit for VTXO {}", ev.id());
			let error = match ev.progress(
				&self.chain_source, &mut self.tx_manager, &*self.persister, onchain
			).await {
				Ok(_) => None,
				Err(e) => {
					match &e {
						ExitError::InsufficientConfirmedFunds { .. } => {
							warn!("Can't progress exit for VTXO {} at this time: {}", ev.id(), e);
						},
						_ => {
							error!("Error progressing exit for VTXO {}: {}", ev.id(), e);
						}
					}
					Some(e)
				}
			};
			if !matches!(ev.state(), ExitState::Spent(..)) {
				exit_statuses.push(ExitProgressStatus {
					vtxo_id: ev.id(),
					state: ev.state().clone(),
					error,
				});
			}
		}
		Ok(Some(exit_statuses))
	}

	/// For use when syncing.
	/// This progresses any unilateral exit in a state that needs updating on sync such as a
	/// spendable exit may have been spent on-chain.
	pub (crate) async fn sync_exit(&mut self, onchain: &mut onchain::Wallet) -> anyhow::Result<()> {
		self.tx_manager.sync().await?;
		for exit in &mut self.exit_vtxos {
			// If the exit is waiting for new blocks, we should trigger an update
			if exit.state().requires_network_update() {
				if let Err(e) = exit.progress(
					&self.chain_source, &mut self.tx_manager, &*self.persister, onchain,
				).await {
					error!("Error syncing exit for VTXO {}: {}", exit.id(), e);
				}
			}
		}
		Ok(())
	}
}
