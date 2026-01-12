//! Unilateral exit management
//!
//! This module coordinates unilateral exits of VTXOs back to on-chain bitcoin without
//! requiring any third-party cooperation. It tracks which VTXOs should be exited, prepares
//! and signs the required transactions, and drives the process forward until the funds are
//! confirmed and claimable.
//!
//! What this module provides
//! - Discovery, tracking, and persistence of the exit state for VTXOs.
//! - Initiation of exits for the entire wallet or a selected set of VTXOs.
//! - Periodic progress of exits (broadcasting, fee-bumping, and state updates).
//! - APIs to inspect the current exit status, history, and related transactions.
//! - Construction and signing of a final claim (drain) transaction once exits become claimable.
//!
//! When to use this module
//! - Whenever VTXOs must be unilaterally moved on-chain, e.g., during counterparty unavailability,
//!   or when the counterparty turns malicious.
//!
//! When not to use this module
//! - If the server is cooperative. You can always offboard or pay onchain in a way that is much
//!   cheaper and faster.
//!
//! Core types
//! - [Exit]: High-level coordinator for the exit workflow. It persists state and advances
//!   unilateral exits until they are claimable.
//! - [ExitVtxo]: A VTXO marked for, and progressing through, unilateral exit. Each instance exposes
//!   its current state and related metadata.
//!
//! Typical lifecycle
//! 1) Choose what to exit
//!    - Mark individual VTXOs for exit with [Exit::start_exit_for_vtxos], or exit everything with
//!      [Exit::start_exit_for_entire_wallet].
//! 2) Drive progress
//!    - Use either [Exit::sync] or [Exit::sync_no_progress] to update the state of tracked exits.
//!    - Periodically call [Exit::progress_exits] to advance the exit process. This will create or
//!      update transactions, adjust fees for existing transactions, and refresh the status of each
//!      unilateral exit until it has been confirmed and subsequentially spent onchain.
//! 3) Inspect status
//!    - Use [Exit::get_exit_status] for detailed per-VTXO status (optionally including
//!      history and transactions).
//!    - Use [Exit::get_exit_vtxos] or [Exit::list_claimable] to browse tracked exits and locate
//!      those that are fully confirmed onchain.
//! 4) Claim the exited funds (optional)
//!    - Once your transaction is confirmed onchain the funds are fully yours. However, recovery
//!      from seed is not supported. By claiming your VTXO you move them to your onchain wallet.
//!    - Once claimable, construct a PSBT to drain them with [Exit::drain_exits].
//!    - Alternatively, you can use [Exit::sign_exit_claim_inputs] to sign the inputs of a given
//!      PSBT if any are the outputs of a claimable unilateral exit.
//!
//! Fees rates
//! - Suitable fee rates will be calculated based on the current network conditions, however, if you
//!   wish to override this, you can do so by providing your own [FeeRate] in [Exit::progress_exits]
//!   and [Exit::drain_exits]
//!
//! Error handling and persistence
//! - The coordinator surfaces operational errors via [anyhow::Result] and domain-specific errors
//!   via [ExitError] where appropriate. Persistent state is kept via the configured persister and
//!   refreshed against the current chain view provided by the chain source client.
//!
//! Minimal example (high-level):
//! ```no_run
//! # use std::sync::Arc;
//! # use std::str::FromStr;
//! # use std::path::PathBuf;
//! #
//! # use bitcoin::Network;
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, SqliteClient};
//! # use bark::onchain::OnchainWallet;
//! #
//! # async fn get_wallets() -> (Wallet, OnchainWallet) {
//! #   let datadir = PathBuf::from("./bark");
//! #   let config = Config::network_default(bitcoin::Network::Bitcoin);
//! #   let db = Arc::new(SqliteClient::open(datadir.join("db.sqlite")).unwrap());
//! #   let mnemonic_str = fs::read_to_string(datadir.join("mnemonic")).await.unwrap();
//! #   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! #   let bark_wallet = Wallet::open(&mnemonic, db.clone(), config).await.unwrap();
//! #   let seed = mnemonic.to_seed("");
//! #   let onchain_wallet = OnchainWallet::load_or_create(Network::Regtest, seed, db).await.unwrap();
//! #   (bark_wallet, onchain_wallet)
//! # }
//! #
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let (mut bark_wallet, mut onchain_wallet) = get_wallets().await;
//!
//! // Get lock on exit system
//! let mut exit_lock = bark_wallet.exit.write().await;
//!
//! // Mark all VTXOs for exit.
//! exit_lock.start_exit_for_entire_wallet().await?;
//!
//! // Transactions will be broadcast and require confirmations so keep periodically calling this.
//! exit_lock.sync_no_progress(&onchain_wallet).await?;
//! exit_lock.progress_exits(&bark_wallet, &mut onchain_wallet, None).await?;
//!
//! // Once all VTXOs are claimable, construct a PSBT to drain them.
//! let drain_to = bitcoin::Address::from_str("bc1p...")?.assume_checked();
//! let claimable_outputs = exit_lock.list_claimable();
//! let drain_psbt = exit_lock.drain_exits(
//!   &claimable_outputs,
//!   &bark_wallet,
//!   drain_to,
//!   None,
//! ).await?;
//!
//! // Next you should broadcast the PSBT, once it's confirmed the unilateral exit is complete.
//! // broadcast_psbt(drain_psbt).await?;
//! #   Ok(())
//! # }
//! ```

mod models;
mod vtxo;
pub(crate) mod progress;
pub(crate) mod transaction_manager;

pub use self::models::{
	ExitTransactionPackage, TransactionInfo, ChildTransactionInfo, ExitError, ExitState,
	ExitTx, ExitTxStatus, ExitTxOrigin, ExitStartState, ExitProcessingState, ExitAwaitingDeltaState,
	ExitClaimableState, ExitClaimInProgressState, ExitClaimedState, ExitProgressStatus,
	ExitTransactionStatus,
};
pub use self::vtxo::ExitVtxo;

use std::borrow::Borrow;
use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{
	Address, Amount, FeeRate, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, sighash
};
use bitcoin::consensus::Params;
use log::{error, info, trace, warn};

use ark::{Vtxo, VtxoId};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, P2TR_DUST};

use crate::Wallet;
use crate::chain::ChainSource;
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::movement::{MovementDestination, MovementStatus, PaymentMethod};
use crate::movement::manager::MovementManager;
use crate::movement::update::MovementUpdate;
use crate::onchain::ExitUnilaterally;
use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;
use crate::psbtext::PsbtInputExt;
use crate::subsystem::{ExitMovement, Subsystem};
use crate::vtxo::{VtxoState, VtxoStateKind};

/// Handles the process of ongoing VTXO exits.
pub struct Exit {
	tx_manager: ExitTransactionManager,
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSource>,
	movement_manager: Arc<MovementManager>,

	exit_vtxos: Vec<ExitVtxo>,
}

impl Exit {
	pub (crate) async fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSource>,
		movement_manager: Arc<MovementManager>,
	) -> anyhow::Result<Exit> {
		let tx_manager = ExitTransactionManager::new(persister.clone(), chain_source.clone())?;

		Ok(Exit {
			exit_vtxos: Vec::new(),
			tx_manager,
			persister,
			chain_source,
			movement_manager,
		})
	}

	pub (crate) async fn load(
		&mut self,
		onchain: &dyn ExitUnilaterally,
	) -> anyhow::Result<()> {
		let exit_vtxo_entries = self.persister.get_exit_vtxo_entries().await?;
		self.exit_vtxos.reserve(exit_vtxo_entries.len());

		for entry in exit_vtxo_entries {
			if let Some(vtxo) = self.persister.get_wallet_vtxo(entry.vtxo_id).await? {
				let mut exit = ExitVtxo::from_entry(entry, &vtxo);
				exit.initialize(&mut self.tx_manager, &*self.persister, onchain).await?;
				self.exit_vtxos.push(exit);
			} else {
				error!("VTXO {} is marked for exit but it's missing from the database", entry.vtxo_id);
			}
		}
		Ok(())
	}

	/// Returns the unilateral exit status for a given VTXO, if any.
	///
	/// # Parameters
	/// - vtxo_id: The ID of the VTXO to check.
	/// - include_history: Whether to include the full state machine history of the exit
	/// - include_transactions: Whether to include the full set of transactions related to the exit.
	pub async fn get_exit_status(
		&self,
		vtxo_id: VtxoId,
		include_history: bool,
		include_transactions: bool,
	) -> Result<Option<ExitTransactionStatus>, ExitError> {
		match self.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id) {
			None => Ok(None),
			Some(exit) => {
				let mut txs = Vec::new();
				if include_transactions {
					if let Some(txids) = exit.txids() {
						txs.reserve(txids.len());
						for txid in txids {
							txs.push(self.tx_manager.get_package(*txid)?.read().await.clone());
						}
					} else {
						let exit_vtxo = exit.get_vtxo(&*self.persister).await?;
						// Realistically, the only way an exit isn't initialized is if it has been
						// marked for exit, and we haven't synced the exit system yet. On this basis
						// we can just return the VTXO transactions since there shouldn't be any
						// children.
						for tx in exit_vtxo.vtxo.transactions() {
							txs.push(ExitTransactionPackage {
								exit: TransactionInfo {
									txid: tx.tx.compute_txid(),
									tx: tx.tx,
								},
								child: None,
							})
						}
					}
				}
				Ok(Some(ExitTransactionStatus {
					vtxo_id: exit.id(),
					state: exit.state().clone(),
					history: if include_history { Some(exit.history().clone()) } else { None },
					transactions: txs,
				}))
			},
		}
	}

	/// Returns a reference to the tracked [ExitVtxo] if it exists.
	pub fn get_exit_vtxo(&self, vtxo_id: VtxoId) -> Option<&ExitVtxo> {
		self.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id)
	}

	/// Returns all known unilateral exits in this wallet.
	pub fn get_exit_vtxos(&self) -> &Vec<ExitVtxo> {
		&self.exit_vtxos
	}

	/// True if there are any unilateral exits which have been started but are not yet claimable.
	pub fn has_pending_exits(&self) -> bool {
		self.exit_vtxos.iter().any(|ev| ev.state().is_pending())
	}

	/// Returns the total amount of all VTXOs requiring more txs to be confirmed
	pub fn pending_total(&self) -> Amount {
		self.exit_vtxos
			.iter()
			.filter_map(|ev| {
				if ev.state().is_pending() {
					Some(ev.amount())
				} else {
					None
				}
			}).sum()
	}

	/// Returns the earliest block height at which all tracked exits will be claimable
	pub async fn all_claimable_at_height(&self) -> Option<BlockHeight> {
		let mut highest_claimable_height = None;
		for exit in &self.exit_vtxos {
			if matches!(exit.state(), ExitState::Claimed(..)) {
				continue;
			}
			match exit.state().claimable_height() {
				Some(h) => highest_claimable_height = cmp::max(highest_claimable_height, Some(h)),
				None => return None,
			}
		}
		highest_claimable_height
	}

	/// Starts the unilateral exit process for the entire wallet (all eligible VTXOs).
	///
	/// It does not block until completion, you must use [Exit::progress_exits] to advance each exit.
	///
	/// It's recommended to sync the wallet, by using something like [Wallet::maintenance] being
	/// doing this.
	pub async fn start_exit_for_entire_wallet(&mut self) -> anyhow::Result<()> {
		let vtxos = self.persister.get_vtxos_by_state(&VtxoStateKind::UNSPENT_STATES).await?.into_iter()
			.map(|v| v.vtxo)
			.collect::<Vec<_>>();
		self.start_exit_for_vtxos(&vtxos).await?;

		Ok(())
	}

	/// Starts the unilateral exit process for the given VTXOs.
	///
	/// It does not block until completion, you must use [Exit::progress_exits] to advance each exit.
	///
	/// It's recommended to sync the wallet, by using something like [Wallet::maintenance] being
	/// doing this.
	pub async fn start_exit_for_vtxos<'a>(
		&mut self,
		vtxos: &[impl Borrow<Vtxo>],
	) -> anyhow::Result<()> {
		if vtxos.is_empty() {
			return Ok(());
		}
		let tip = self.chain_source.tip().await?;
		let params = Params::new(self.chain_source.network());
		for vtxo in vtxos {
			let vtxo = vtxo.borrow();
			let vtxo_id = vtxo.id();
			if self.exit_vtxos.iter().any(|ev| ev.id() == vtxo_id) {
				warn!("VTXO {} is already in the exit process", vtxo_id);
				continue;
			}

			// We avoid composing the TXID vector since that requires access to the onchain wallet,
			// as such the ExitVtxo will be considered uninitialized.
			trace!("Starting exit for VTXO: {}", vtxo_id);
			let exit = ExitVtxo::new(vtxo, tip);
			self.persister.store_exit_vtxo_entry(&StoredExit::new(&exit)).await?;
			self.persister.update_vtxo_state_checked(
				vtxo_id, VtxoState::Spent, &VtxoStateKind::UNSPENT_STATES,
			).await?;
			self.exit_vtxos.push(exit);
			trace!("Exit for VTXO started successfully: {}", vtxo_id);

			// Register the movement now so users can be aware of where their funds have gone.
			let balance = -vtxo.amount().to_signed()?;
			let script_pubkey = vtxo.output_script_pubkey();
			let payment_method = match Address::from_script(&script_pubkey, &params) {
				Ok(addr) => PaymentMethod::Bitcoin(addr.into_unchecked()),
				Err(e) => {
					warn!("Unable to convert script pubkey to address: {:#}", e);
					PaymentMethod::OutputScript(script_pubkey)
				}
			};

			// A big reason for creating a finished movement is that we currently don't support
			// canceling exits. When we do, we can leave this in pending until it's either finished
			// or canceled by the user.
			self.movement_manager.new_finished_movement(
				Subsystem::EXIT,
				ExitMovement::Exit.to_string(),
				MovementStatus::Successful,
				MovementUpdate::new()
					.intended_and_effective_balance(balance)
					.consumed_vtxo(vtxo_id)
					.sent_to([MovementDestination::new(payment_method, vtxo.amount())]),
			).await.context("Failed to register exit movement")?;
		}
		Ok(())
	}

	/// Reset exit to an empty state. Should be called when dropping VTXOs
	///
	/// Note: _This method is **dangerous** and can lead to funds loss. Be cautious._
	pub (crate) async fn dangerous_clear_exit(&mut self) -> anyhow::Result<()> {
		for exit in &self.exit_vtxos {
			self.persister.remove_exit_vtxo_entry(&exit.id()).await?;
		}
		self.exit_vtxos.clear();
		Ok(())
	}

	/// Iterates over each registered VTXO and attempts to progress their unilateral exit. Note that
	/// [Exit::sync] or [Exit::sync_no_progress] should be called before calling this method.
	///
	/// # Parameters
	///
	/// - `onchain` is used to build the CPFP transaction package we use to broadcast
	///   the unilateral exit transaction
	/// - `fee_rate_override` sets the desired fee-rate in sats/kvB to use broadcasting exit
	///   transactions. Note that due to rules imposed by the network with regard to RBF fee bumping,
	///   replaced transactions may have a higher fee rate than you specify here.
	///
	/// # Returns
	///
	/// The exit status of each VTXO being exited which has also not yet been spent
	pub async fn progress_exits(
		&mut self,
		wallet: &Wallet,
		onchain: &mut dyn ExitUnilaterally,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		let mut exit_statuses = Vec::with_capacity(self.exit_vtxos.len());
		for ev in self.exit_vtxos.iter_mut() {
			if !ev.is_initialized() {
				warn!("Skipping progress of uninitialized unilateral exit {}", ev.id());
				continue;
			}

			info!("Progressing exit for VTXO {}", ev.id());
			let error = match ev.progress(
				wallet,
				&mut self.tx_manager,
				onchain,
				fee_rate_override,
				true,
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
			if !matches!(ev.state(), ExitState::Claimed(..)) {
				exit_statuses.push(ExitProgressStatus {
					vtxo_id: ev.id(),
					state: ev.state().clone(),
					error,
				});
			}
		}
		Ok(Some(exit_statuses))
	}

	/// For use when syncing. Pending exits will be initialized, the network status of each
	/// [ExitTransactionPackage] will be updated, and finally, any unilateral exits that are waiting
	/// for network updates will be progressed.
	pub async fn sync(
		&mut self,
		wallet: &Wallet,
		onchain: &mut dyn ExitUnilaterally,
	) -> anyhow::Result<()> {
		self.sync_no_progress(onchain).await?;
		for exit in &mut self.exit_vtxos {
			// If the exit is waiting for new blocks, we should trigger an update
			if exit.state().requires_network_update() {
				if let Err(e) = exit.progress(
					wallet, &mut self.tx_manager, onchain, None, false,
				).await {
					error!("Error syncing exit for VTXO {}: {}", exit.id(), e);
				}
			}
		}
		Ok(())
	}

	/// For use when syncing. Initializes pending exits and syncs any confirmed or broadcast child
	/// transactions. This differs from [Exit::sync] in that it doesn't update the [ExitState]
	/// of a unilateral exit. This must be done manually by calling [Exit::progress_exits]. This
	/// permits the use of a read-only reference to the onchain wallet.
	pub async fn sync_no_progress(
		&mut self,
		onchain: &dyn ExitUnilaterally,
	) -> anyhow::Result<()> {
		for exit in &mut self.exit_vtxos {
			if !exit.is_initialized() {
				match exit.initialize(&mut self.tx_manager, &*self.persister, onchain).await {
					Ok(()) => continue,
					Err(e) => {
						error!("Error initializing exit for VTXO {}: {:#}", exit.id(), e);
					}
				}
			}
		}
		self.tx_manager.sync().await?;
		Ok(())
	}

	/// Lists all exits that are claimable
	pub fn list_claimable(&self) -> Vec<&ExitVtxo> {
		self.exit_vtxos.iter().filter(|ev| ev.is_claimable()).collect()
	}

	/// Sign any inputs of the PSBT that is an exit claim input
	///
	/// Can take the result PSBT of [`bdk_wallet::TxBuilder::finish`] on which
	/// [`crate::onchain::TxBuilderExt::add_exit_claim_inputs`] has been used
	///
	/// Note: This doesn't mark the exit output as spent, it's up to the caller to
	/// do that, or it will be done once the transaction is seen in the network
	pub async fn sign_exit_claim_inputs(&self, psbt: &mut Psbt, wallet: &Wallet) -> anyhow::Result<()> {
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);

		let claimable = self.list_claimable()
			.into_iter()
			.map(|e| (e.id(), e))
			.collect::<HashMap<_, _>>();

		let mut spent = Vec::new();
		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let vtxo = input.get_exit_claim_input();

			if let Some(vtxo) = vtxo {
				let exit_vtxo = *claimable.get(&vtxo.id()).context("vtxo is not claimable yet")?;

				let witness = wallet.sign_input(&vtxo, i, &mut shc, &prevouts).await
					.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;

				input.final_script_witness = Some(witness);
				spent.push(exit_vtxo);
			}
		}

		Ok(())
	}

	/// Builds a PSBT that drains the provided claimable unilateral exits to the given address.
	///
	/// - `inputs`: Claimable unilateral exits.
	/// - `wallet`: The bark wallet containing the keys needed to spend the unilateral exits.
	/// - `address`: Destination address for the claim.
	/// - `fee_rate_override`: Optional fee rate to use.
	///
	/// Returns a PSBT ready to be broadcast.
	pub async fn drain_exits<'a>(
		&self,
		inputs: &[impl Borrow<ExitVtxo>],
		wallet: &Wallet,
		address: Address,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Psbt, ExitError> {
		let tip = self.chain_source.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })?;

		if inputs.is_empty() {
			return Err(ExitError::ClaimMissingInputs);
		}
		let mut vtxos = HashMap::with_capacity(inputs.len());
		for input in inputs {
			let i = input.borrow();
			let vtxo = i.get_vtxo(&*self.persister).await?;
			vtxos.insert(i.id(), vtxo);
		}

		let mut tx = {
			let mut output_amount = Amount::ZERO;
			let mut tx_ins = Vec::with_capacity(inputs.len());
			for input in inputs {
				let input = input.borrow();
				let vtxo = &vtxos[&input.id()];
				if !matches!(input.state(), ExitState::Claimable(..)) {
					return Err(ExitError::VtxoNotClaimable { vtxo: input.id() });
				}

				output_amount += vtxo.amount();

				let clause = wallet.find_signable_clause(vtxo).await
					.ok_or(ExitError::ClaimMissingSignableClause { vtxo: vtxo.id() })?;

				tx_ins.push(TxIn {
					previous_output: vtxo.point(),
					script_sig: ScriptBuf::default(),
					sequence: clause.sequence().unwrap_or(Sequence::ZERO),
					witness: Witness::new(),
				});
			}

			let locktime = bitcoin::absolute::LockTime::from_height(tip)
				.map_err(|e| ExitError::InvalidLocktime { tip, error: e.to_string() })?;

			Transaction {
				version: bitcoin::transaction::Version(3),
				lock_time: locktime,
				input: tx_ins,
				output: vec![
					TxOut {
						script_pubkey: address.script_pubkey(),
						value: output_amount,
					},
				],
			}
		};

		// Create a PSBT to determine the weight of the transaction so we can deduct a tx fee
		let create_psbt = |tx: Transaction| async {
			let mut psbt = Psbt::from_unsigned_tx(tx)
				.map_err(|e| ExitError::InternalError {
					error: format!("Failed to create exit claim PSBT: {}", e),
				})?;
			psbt.inputs.iter_mut().zip(inputs).for_each(|(i, e)| {
				let v = &vtxos[&e.borrow().id()];
				i.set_exit_claim_input(&v.vtxo);
				i.witness_utxo = Some(v.vtxo.txout())
			});
			self.sign_exit_claim_inputs(&mut psbt, wallet).await
				.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;
			Ok(psbt)
		};
		let fee_amount = {
			let fee_rate = fee_rate_override
				.unwrap_or(self.chain_source.fee_rates().await.regular);
			fee_rate * create_psbt(tx.clone()).await?
				.extract_tx()
				.map_err(|e| ExitError::InternalError {
					error: format!("Failed to get tx from signed exit claim PSBT: {}", e),
				})?
				.weight()
		};

		// We adjust the drain output to cover the fee
		let needed = fee_amount + P2TR_DUST;
		if needed > tx.output[0].value {
			return Err(ExitError::ClaimFeeExceedsOutput {
				needed, output: tx.output[0].value,
			});
		}
		tx.output[0].value -= fee_amount;

		// Now create the final signed PSBT
		create_psbt(tx).await
	}
}
