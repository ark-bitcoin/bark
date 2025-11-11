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
//!    - Periodically call [Exit::progress_exits] to advance the exit process. This will create or
//!      update transactions, adjust fees for existing transactions, and refresh the status of each
//!      unilateral exit until it has been confirmed and subsequentially spent onchain.
//!    - [Exit::sync_exit] can be used to re-sync state with the blockchain and mempool without
//!      taking progress actions.
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
//! #   let onchain_wallet = OnchainWallet::load_or_create(Network::Regtest, seed, db).unwrap();
//! #   (bark_wallet, onchain_wallet)
//! # }
//! #
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let (mut bark_wallet, mut onchain_wallet) = get_wallets().await;
//!
//! // Mark all VTXOs for exit.
//! bark_wallet.exit.get_mut().start_exit_for_entire_wallet(&onchain_wallet).await?;
//!
//! // Transactions will be broadcast and require confirmations so keep periodically calling this.
//! bark_wallet.exit.get_mut().progress_exits(&mut onchain_wallet, None).await?;
//!
//! // Once all VTXOs are claimable, construct a PSBT to drain them.
//! let drain_to = bitcoin::Address::from_str("bc1p...")?.assume_checked();
//! let exit = bark_wallet.exit.read().await;
//! let drain_psbt = exit.drain_exits(
//!   &exit.list_claimable(),
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

pub mod models;

pub(crate) mod progress;
pub(crate) mod transaction_manager;

pub use vtxo::ExitVtxo;

mod vtxo;

use std::borrow::Borrow;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{
	sighash, Address, Amount, FeeRate, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use log::{error, info, warn};

use ark::{Vtxo, VtxoId, SECP};
use bitcoin_ext::{BlockHeight, P2TR_DUST};

use crate::Wallet;
use crate::exit::models::{ExitError, ExitProgressStatus, ExitState, ExitTransactionStatus};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain::{ChainSource, ExitUnilaterally};
use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;
use crate::psbtext::PsbtInputExt;
use crate::vtxo::state::UNSPENT_STATES;

/// Handles the process of ongoing VTXO exits.
pub struct Exit {
	tx_manager: ExitTransactionManager,
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSource>,

	vtxos_to_exit: HashSet<VtxoId>,
	exit_vtxos: Vec<ExitVtxo>,
}

impl Exit {
	pub (crate) async fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSource>,
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

	/// Returns the unilateral exit status for a given VTXO, if any.
	///
	/// - vtxo_id: The ID of the VTXO to check.
	/// - include_history: Whether to include the full state machine history of the exit
	/// - include_transactions: Whether to include the full set of transactions related to the exit.
	/// Errors if status retrieval fails.
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
					vec
				} else {
					vec![]
				};
				Ok(Some(ExitTransactionStatus {
					vtxo_id: exit.id(),
					state: exit.state().clone(),
					history: if include_history { Some(exit.history().clone()) } else { None },
					transactions,
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
					Some(ev.vtxo().spec().amount)
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
	pub async fn start_exit_for_entire_wallet<W: ExitUnilaterally>(
		&mut self,
		onchain: &W,
	) -> anyhow::Result<()> {
		let vtxos: Vec<Vtxo> = self.persister.get_vtxos_by_state(&UNSPENT_STATES)?.into_iter()
			.map(|v| v.vtxo).collect();
		self.start_exit_for_vtxos(&vtxos, onchain).await?;

		Ok(())
	}

	/// Starts the unilateral exit process for the given VTXOs.
	///
	/// It does not block until completion, you must use [Exit::progress_exits] to advance each exit.
	///
	/// It's recommended to sync the wallet, by using something like [Wallet::maintenance] being
	/// doing this.
	pub async fn start_exit_for_vtxos<W: ExitUnilaterally>(
		&mut self,
		vtxos: &[Vtxo],
		onchain: &W,
	) -> anyhow::Result<()> {
		self.mark_vtxos_for_exit(vtxos);
		self.start_vtxo_exits(onchain).await?;
		Ok(())
	}

	/// Lists the IDs of VTXOs marked for unilateral exit.
	pub fn list_vtxos_to_exit(&self) -> Vec<VtxoId> {
		self.vtxos_to_exit.iter().cloned().collect()
	}

	/// Mark a vtxo for unilateral exit.
	///
	/// This is a lower level primitive used as a buffer to mark vtxos for exit without having to
	/// provide an onchain wallet. The actual exit process is started with [Exit::start_vtxo_exits].
	pub fn mark_vtxos_for_exit(&mut self, vtxos: &[Vtxo]) -> () {
		for vtxo in vtxos {
			if self.exit_vtxos.iter().any(|ev| ev.id() == vtxo.id()) {
				warn!("VTXO {} is already in the exit process", vtxo.id());
				continue;
			}
			self.vtxos_to_exit.insert(vtxo.id());
		}
	}

	/// Starts the unilateral exit process for any VTXOs marked for exit.
	///
	/// This is a lower level primitive to be used in conjunction with [Exit::mark_vtxos_for_exit].
	pub async fn start_vtxo_exits(&mut self, onchain: &impl ExitUnilaterally) -> anyhow::Result<()> {
		if self.vtxos_to_exit.is_empty() {
			return Ok(());
		}

		let tip = self.chain_source.tip().await?;

		let cloned = self.vtxos_to_exit.iter().cloned().collect::<Vec<_>>();
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
				self.persister.store_exit_vtxo_entry(&StoredExit::new(&exit))?;
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

	/// Returns a list of per-VTXO progress statuses if any changes occurred, or None if there was nothing to do.
	///
	/// Iterates over each registered VTXO and attempts to progress their unilateral exit
	///
	/// ### Arguments
	///
	/// - `onchain` is used to build the CPFP transaction package we use to broadcast
	///   the unilateral exit transaction
	/// - `fee_rate_override` sets the desired fee-rate in sats/kvB to use broadcasting exit
	///   transactions. Note that due to rules imposed by the network with regard to RBF fee bumping,
	///   replaced transactions may have a higher fee rate than you specify here.
	///
	/// ### Return
	///
	/// The exit status of each VTXO being exited which has also not yet been spent
	pub async fn progress_exits<W: ExitUnilaterally>(
		&mut self,
		onchain: &mut W,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		self.tx_manager.sync().await?;
		let mut exit_statuses = Vec::with_capacity(self.exit_vtxos.len());
		for ev in self.exit_vtxos.iter_mut() {
			info!("Progressing exit for VTXO {}", ev.id());
			let error = match ev.progress(
				&self.chain_source,
				&mut self.tx_manager,
				&*self.persister,
				onchain,
				fee_rate_override,
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

	/// For use when syncing. This progresses any unilateral exit in a state that needs updating
	/// such as a when claimable exit may have been spent onchain.
	pub async fn sync_exit<W: ExitUnilaterally>(
		&mut self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		self.tx_manager.sync().await?;
		self.start_vtxo_exits(onchain).await?;
		for exit in &mut self.exit_vtxos {
			// If the exit is waiting for new blocks, we should trigger an update
			if exit.state().requires_network_update() {
				if let Err(e) = exit.progress(
					&self.chain_source, &mut self.tx_manager, &*self.persister, onchain, None,
				).await {
					error!("Error syncing exit for VTXO {}: {}", exit.id(), e);
				}
			}
		}
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
	pub fn sign_exit_claim_inputs(&self, psbt: &mut Psbt, wallet: &Wallet) -> anyhow::Result<()> {
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);

		let claimable = self.list_claimable()
			.into_iter()
			.map(|v| (v.vtxo().id(), v))
			.collect::<HashMap<_, _>>();

		let mut spent = Vec::new();
		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let vtxo = input.get_exit_claim_input();

			if let Some(vtxo) = vtxo {
				let exit_vtxo = *claimable.get(&vtxo.id()).context("vtxo is not exited yet")?;

				let keypair = wallet.get_vtxo_key(&vtxo)?;

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
		if inputs.is_empty() {
			return Err(ExitError::ClaimMissingInputs);
		}
		let mut tx = {
			let mut output_amount = Amount::ZERO;
			let mut tx_ins = Vec::with_capacity(inputs.len());
			for input in inputs {
				let input = input.borrow();
				if !matches!(input.state(), ExitState::Claimable(..)) {
					return Err(ExitError::VtxoNotClaimable { vtxo: input.id() });
				}
				output_amount += input.vtxo().amount();
				tx_ins.push(TxIn {
					previous_output: input.vtxo().point(),
					script_sig: ScriptBuf::default(),
					sequence: Sequence::from_height(input.vtxo().exit_delta()),
					witness: Witness::new(),
				});
			}
			Transaction {
				version: bitcoin::transaction::Version(3),
				lock_time: bitcoin::absolute::LockTime::ZERO,
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
		let create_psbt = |tx: Transaction| {
			let mut psbt = Psbt::from_unsigned_tx(tx)
				.map_err(|e| ExitError::InternalError {
					error: format!("Failed to create exit claim PSBT: {}", e),
				})?;
			psbt.inputs.iter_mut().zip(inputs).for_each(|(i, v)| {
				i.set_exit_claim_input(&v.borrow().vtxo());
				i.witness_utxo = Some(v.borrow().vtxo().txout())
			});
			self.sign_exit_claim_inputs(&mut psbt, wallet)
				.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;
			Ok(psbt)
		};
		let fee_amount = {
			let fee_rate = fee_rate_override
				.unwrap_or(self.chain_source.fee_rates().await.regular);
			fee_rate * create_psbt(tx.clone())?
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
		create_psbt(tx)
	}
}
