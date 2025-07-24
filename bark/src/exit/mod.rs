pub(crate) mod progress;
pub(crate) mod transaction_manager;
pub mod vtxo;

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use ark::util::SECP;
use bitcoin::{sighash, Address, Amount, FeeRate, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use log::{error, info, warn};

use ark::{Vtxo, VtxoId};
use bitcoin_ext::BlockHeight;
use json::cli::{ExitProgressStatus, ExitTransactionStatus};
use json::exit::ExitState;
use json::exit::error::ExitError;

use crate::exit::transaction_manager::ExitTransactionManager;
use crate::exit::vtxo::{ExitEntry, ExitVtxo};
use crate::onchain::{ChainSourceClient, ExitUnilaterally};
use crate::persist::BarkPersister;
use crate::psbtext::PsbtInputExt;
use crate::Wallet;

/// Handle the process of ongoing VTXO exits
pub struct Exit {
	tx_manager: ExitTransactionManager,
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSourceClient>,

	vtxos_to_exit: HashSet<VtxoId>,
	exit_vtxos: Vec<ExitVtxo>,
}

impl Exit {
	pub (crate) async fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSourceClient>,
	) -> anyhow::Result<Exit> {
		let tx_manager = ExitTransactionManager::new(persister.clone(), chain_source.clone())?;

		// Gather the database entries for our exit and convert them into ExitVtxo structs
		let exit_vtxo_entries = persister.get_exit_vtxo_entries()?;

		Ok(Exit {
			vtxos_to_exit: HashSet::new(),
			exit_vtxos: Vec::with_capacity(exit_vtxo_entries.len()),
			tx_manager,
			persister,
			chain_source,
		})
	}

	pub (crate) async fn load<W: ExitUnilaterally>(
		&mut self,
		onchain: &W,
	) -> anyhow::Result<()> {
		let exit_vtxo_entries = self.persister.get_exit_vtxo_entries()?;
		for entry in exit_vtxo_entries {
			if let Some(vtxo) = self.persister.get_wallet_vtxo(entry.vtxo_id)? {
				let txids = self.tx_manager.track_vtxo_exits(&vtxo.vtxo, onchain).await?;
				self.exit_vtxos.push(ExitVtxo::from_parts(vtxo.vtxo, txids, entry.state, entry.history));
			} else {
				error!("VTXO {} is marked for exit but it's missing from the database", entry.vtxo_id);
			}
		}

		Ok(())
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
	pub fn pending_total(&self) -> anyhow::Result<Amount> {
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
	pub async fn start_exit_for_entire_wallet<W: ExitUnilaterally>(
		&mut self,
		onchain: &W,
	) -> anyhow::Result<()> {
		let vtxos = self.persister.get_all_spendable_vtxos()?;
		self.start_exit_for_vtxos(&vtxos, onchain).await?;

		Ok(())
	}

	/// Mark a list of vtxos for exit and start the exit process.
	pub async fn start_exit_for_vtxos<W: ExitUnilaterally>(
		&mut self,
		vtxos: &[Vtxo],
		onchain: &W,
	) -> anyhow::Result<()> {
		self.mark_vtxos_for_exit(vtxos)?;
		self.start_vtxo_exits(onchain).await?;
		Ok(())
	}

	/// Mark a vtxo for exit.
	///
	/// This is used as a buffer to mark vtxos for exit without having to provide an onchain wallet.
	/// The actual exit process is started by `start_vtxo_exits`.
	pub fn mark_vtxos_for_exit(&mut self, vtxos: &[Vtxo]) -> anyhow::Result<()> {
		for vtxo in vtxos {
			if self.exit_vtxos.iter().any(|ev| ev.id() == vtxo.id()) {
				warn!("VTXO {} is already in the exit process", vtxo.id());
				continue;
			}
			self.vtxos_to_exit.insert(vtxo.id());
		}

		Ok(())
	}

	pub fn list_vtxos_to_exit(&self) -> Vec<VtxoId> {
		self.vtxos_to_exit.iter().cloned().collect()
	}

	async fn maybe_start_exit_for_vtxos(&mut self, onchain: &impl ExitUnilaterally) -> anyhow::Result<()> {
		if !self.vtxos_to_exit.is_empty() {
			self.start_vtxo_exits(onchain).await?;
		}

		Ok(())
	}

	/// Add marked vtxos to the exit process.
	pub (crate) async fn start_vtxo_exits(&mut self, onchain: &impl ExitUnilaterally) -> anyhow::Result<()> {
		let tip = self.chain_source.tip().await?;
		if self.vtxos_to_exit.is_empty() {
			warn!("There are VTXOs to exit!");
			return Ok(());
		}

		let cloned = self.vtxos_to_exit.clone().into_iter().collect::<Vec<_>>();
		for vtxo_id in cloned {
			let vtxo = match self.persister.get_wallet_vtxo(vtxo_id)? {
				Some(vtxo) => vtxo.vtxo,
				None => {
					error!("Could not find vtxo to exit {}", vtxo_id);
					continue;
				}
			};

			if self.exit_vtxos.iter().any(|ev| ev.id() == vtxo.id()) {
				warn!("VTXO {} is already in the exit process", vtxo.id());
				continue;
			} else {
				// The idea is to convert all our vtxos into an exit process structure
				// that we then store in the database, and we can gradually proceed on.
				let txids = self.tx_manager.track_vtxo_exits(&vtxo, onchain).await?;
				let exit = ExitVtxo::new(vtxo.clone(), txids, tip);
				self.persister.store_exit_vtxo_entry(&ExitEntry::new(&exit))?;
				self.exit_vtxos.push(exit);
			}

			self.vtxos_to_exit.remove(&vtxo_id);
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
	pub async fn progress_exit<W: ExitUnilaterally>(
		&mut self,
		onchain: &mut W,
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
	pub (crate) async fn sync_exit<W: ExitUnilaterally>(
		&mut self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		self.tx_manager.sync().await?;
		self.maybe_start_exit_for_vtxos(onchain).await?;
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

	/// List all exits that are spendable
	pub fn list_spendable(&self) -> anyhow::Result<Vec<&ExitVtxo>> {
		let mut outputs = Vec::new();
		for exit in &self.exit_vtxos {
			if matches!(exit.state(), ExitState::Spendable(..)) {
				outputs.push(exit);
			}
		}

		Ok(outputs)
	}

	/// Sign any inputs of the PSBT that is an exit claim input
	///
	/// Can take the result PSBT of [`bdk_wallet::TxBuilder::finish`] on which
	/// [`crate::onchain::TxBuilderExt::add_exit_claim_inputs`] has been used
	///
	/// Note: This doesn't mark the exit output as spent, it's up to the caller to
	/// do that or it will be done once the transaction is seen in the network
	pub fn sign_exit_claim_inputs(&self, psbt: &mut Psbt, wallet: &Wallet) -> anyhow::Result<()> {
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);

		let spendable = self.list_spendable()?.into_iter().map(|v| (v.vtxo().id(), v)).collect::<HashMap<_, _>>();

		let mut spent = Vec::new();
		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let vtxo = input.get_exit_claim_input();

			if let Some(vtxo) = vtxo {
				let exit_vtxo = *spendable.get(&vtxo.id()).context("vtxo is not exited yet")?;

				let (keychain, keypair_idx) = wallet.db.get_vtxo_key(&vtxo)?;
				let keypair = wallet.vtxo_seed.derive_keychain(keychain, keypair_idx);

				input.maybe_sign_exit_claim_input(
					&SECP,
					&mut shc,
					&prevouts,
					i,
					&keypair
				)?;

				spent.push(exit_vtxo);
			}
		}

		Ok(())
	}

	/// Prepare and sign a PSBT to drain all spendable VTXOs to provided address
	pub fn drain_spendable_outputs(&self, wallet: &Wallet, address: Address, fee_rate: FeeRate) -> anyhow::Result<Psbt> {
		let inputs = self.list_spendable()?;

		let output_amount = inputs.iter().map(|v| v.vtxo().spec().amount).sum();

		let mut tx = Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: inputs.iter().map(|v| TxIn {
				previous_output: v.vtxo().point(),
				script_sig: ScriptBuf::default(),
				sequence: Sequence::from_height(v.vtxo().exit_delta()),
				witness: Witness::new(),
			}).collect(),
			output: vec![
				TxOut {
					script_pubkey: address.script_pubkey(),
					value: output_amount,
				},
			],
		};

		// We adjust drain amount to cover the fee
		let fee_amount = fee_rate * tx.weight();
		tx.output[0].value -= fee_amount;

		let mut psbt = Psbt::from_unsigned_tx(tx)?;
		psbt.inputs.iter_mut().zip(inputs).for_each(|(i, v)| {
			i.set_exit_claim_input(&v.vtxo());
			i.witness_utxo = Some(v.vtxo().txout())
		});

		self.sign_exit_claim_inputs(&mut psbt, wallet)?;

		Ok(psbt)
	}
}
