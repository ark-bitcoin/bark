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
//!    - Call [Exit::progress_exits] to advance the wallet-agnostic state machine for each exit.
//!    - To create or fee-bump CPFP transactions using an onchain wallet, call
//!      [Exit::exits_needing_cpfp] to get pending requests, provide signed CPFPs via
//!      [Exit::provide_cpfp_tx], then call [Exit::progress_exits] again. Alternatively, use the
//!      [Exit::progress_exits_with_bdk] if you have a BDK-backed onchain wallet.
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
//! Fee rates
//! - Suitable fee rates will be calculated based on the current network conditions. To override,
//!   pass your own [FeeRate] to [Exit::progress_exits_with_bdk] or [Exit::drain_exits].
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
//! # use bark::{Config, Wallet, WalletSeed, OpenWalletArgs};
//! # use bark::lock_manager::memory::MemoryLockManager;
//! # use bark::onchain::OnchainWallet;
//! # use bark::persist::sqlite::SqliteClient;
//! #
//! # async fn get_wallets() -> (Wallet, OnchainWallet) {
//! #   let datadir = PathBuf::from("./bark");
//! #   let config = Config::network_default(bitcoin::Network::Bitcoin);
//! #   let db = Arc::new(SqliteClient::open(datadir.join("db.sqlite")).unwrap());
//! #   let mnemonic_str = fs::read_to_string(datadir.join("mnemonic")).await.unwrap();
//! #   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! #   let seed = WalletSeed::new_from_mnemonic(Network::Signet, &mnemonic);
//! #   let bark_wallet = Wallet::open(Network::Signet, seed, config, OpenWalletArgs {
//! #   	persister: Some(db.clone()),
//! #   	..Default::default()
//! #   }).await.unwrap();
//! #   let seed = mnemonic.to_seed("");
//! #   let onchain_wallet = OnchainWallet::load_or_create(Network::Regtest, seed, db).await.unwrap();
//! #   (bark_wallet, onchain_wallet)
//! # }
//! #
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! let (mut bark_wallet, mut onchain_wallet) = get_wallets().await;
//!
//! // Mark all VTXOs for exit.
//! bark_wallet.exit_mgr().start_exit_for_entire_wallet().await?;
//!
//! // Transactions will be broadcast and require confirmations so keep periodically calling this.
//! bark_wallet.exit_mgr().progress_exits_with_bdk(&bark_wallet, &mut onchain_wallet, None).await?;
//!
//! // Once all VTXOs are claimable, construct a PSBT to drain them.
//! let drain_to = bitcoin::Address::from_str("bc1p...")?.assume_checked();
//! let claimable_outputs = bark_wallet.exit_mgr().list_claimable().await;
//! let drain_psbt = bark_wallet.exit_mgr().drain_exits(
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
pub mod bdk;
pub(crate) mod progress;
pub(crate) mod transaction_manager;

pub use self::models::{
	ExitCpfpRequest, ExitTransactionPackage, FeeInfo, RbfRequirement, TransactionInfo,
	ChildTransactionInfo, ExitError, ExitState, ExitTx, ExitTxStatus, ExitTxOrigin, ExitStartState,
	ExitProcessingState, ExitAwaitingDeltaState, ExitClaimableState, ExitClaimInProgressState,
	ExitClaimedState, ExitVtxoAlreadySpentState, ExitCanceledState, ExitProgressStatus,
	ExitTransactionStatus,
};
pub use self::vtxo::ExitVtxo;

use std::borrow::Borrow;
use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{
	Address, Amount, FeeRate, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, sighash
};
use bitcoin::consensus::Params;
use log::{error, info, trace, warn};

use ark::{Vtxo, VtxoId};
use ark::vtxo::Bare;
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, P2TR_DUST};

use crate::Wallet;
use crate::chain::ChainSource;
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::movement::{MovementDestination, MovementStatus, PaymentMethod};
use crate::movement::manager::MovementManager;
use crate::movement::update::MovementUpdate;

use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;
use crate::psbtext::PsbtInputExt;
use crate::subsystem::{ExitMovement, Subsystem};
use crate::vtxo::VtxoStateKind;

/// Handles the process of ongoing VTXO exits.
pub(crate) struct ExitInner {
	tx_manager: ExitTransactionManager,
	persister: Arc<dyn BarkPersister>,
	chain_source: Arc<ChainSource>,
	movement_manager: Arc<MovementManager>,

	exit_vtxos: Vec<ExitVtxo>,
}

impl ExitInner {
	/// Starts exits for the given vtxos.
	/// Used by both [Exit::start_exit_for_vtxos] and [Exit::start_exit_for_entire_wallet].
	async fn start_exit_for_vtxos(
		&mut self,
		vtxos: &[impl Borrow<Vtxo<Bare>>],
		skip_standardness_checks: bool,
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

			if !skip_standardness_checks {
				// Pre-flight check: Prevent exiting dust, which causes "zombie" states
				if vtxo.amount() < P2TR_DUST {
					return Err(ExitError::DustLimit {
						vtxo: vtxo.amount(),
						dust: P2TR_DUST,
					}.into());
				}

				// Pre-flight check: refuse to start an exit whose chain is not
				// standardness-compliant. The exit chain is what we'd broadcast to
				// claim the funds; if any tx in it carries a sub-dust or
				// unrecognised-script output the broadcast will be rejected by
				// public-network relay, so committing CPFP budget to it would just
				// burn fees. Fetch the genesis via the persister since the
				// Vtxo<Bare> we get here only carries the leaf info.
				let full_vtxo = self.persister.get_full_vtxo(vtxo_id).await?
					.ok_or_else(|| ExitError::InvalidWalletState {
						error: format!("missing genesis for VTXO {vtxo_id}"),
					})?;
				if let Err(error) = full_vtxo.check_standard() {
					return Err(ExitError::NonStandardVtxo { vtxo: vtxo_id, error }.into());
				}
			}

			// Create the movement in a Pending state. It transitions to Successful once the
			// exit completes (Claimed), or Canceled if we discover the VTXO was already
			// consumed by something else. We don't touch the VTXO's own state here — that
			// happens in `progress_exits` once we've actually broadcast the exit chain.
			let balance = -vtxo.amount().to_signed()?;
			let script_pubkey = vtxo.output_script_pubkey();
			let payment_method = match Address::from_script(&script_pubkey, &params) {
				Ok(addr) => PaymentMethod::Bitcoin(addr.into_unchecked()),
				Err(e) => {
					warn!("Unable to convert script pubkey to address: {:#}", e);
					PaymentMethod::OutputScript(script_pubkey)
				}
			};

			let movement_id = self.movement_manager.new_movement_with_update(
				Subsystem::EXIT,
				ExitMovement::Exit.to_string(),
				MovementUpdate::new()
					.intended_and_effective_balance(balance)
					.consumed_vtxo(vtxo_id)
					.sent_to([MovementDestination::new(payment_method, vtxo.amount())]),
			).await.context("Failed to register exit movement")?;

			// We avoid composing the TXID vector since that requires access to the onchain wallet,
			// as such the ExitVtxo will be considered uninitialized.
			trace!("Starting exit for VTXO: {}", vtxo_id);
			let exit = ExitVtxo::new(vtxo, tip, Some(movement_id));
			self.persister.store_exit_vtxo_entry(&StoredExit::new(&exit)).await?;
			self.exit_vtxos.push(exit);
			trace!("Exit for VTXO started successfully: {}", vtxo_id);
		}
		Ok(())
	}

	/// Initializes pending exits and refreshes the chain view of their transaction packages.
	async fn refresh_tx_state(&mut self) -> anyhow::Result<()> {
		let mut exit_vtxos = std::mem::take(&mut self.exit_vtxos);
		for exit in &mut exit_vtxos {
			if !exit.is_initialized() {
				match exit.initialize(&mut self.tx_manager, &*self.persister).await {
					Ok(()) => continue,
					Err(e) => {
						error!("Error initializing exit for VTXO {}: {:#}", exit.id(), e);
					}
				}
			}
		}
		self.exit_vtxos = exit_vtxos;
		self.tx_manager.sync().await?;
		Ok(())
	}

	/// Signs exit claim inputs on a PSBT.
	/// Used by both [Exit::sign_exit_claim_inputs] and [Exit::drain_exits].
	async fn sign_exit_claim_inputs(
		&self,
		psbt: &mut Psbt,
		wallet: &Wallet,
	) -> anyhow::Result<()> {
		let prevouts = psbt.inputs.iter()
			.map(|i| i.witness_utxo.clone().unwrap())
			.collect::<Vec<_>>();

		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut shc = sighash::SighashCache::new(&psbt.unsigned_tx);

		let claimable = self.exit_vtxos.iter()
			.filter(|ev| ev.is_claimable())
			.map(|e| (e.id(), e))
			.collect::<HashMap<_, _>>();

		for (i, input) in psbt.inputs.iter_mut().enumerate() {
			let vtxo = input.get_exit_claim_input();

			if let Some(vtxo) = vtxo {
				let exit_vtxo = claimable.get(&vtxo.id()).context("vtxo is not claimable yet")?;

				let witness = wallet.sign_input(&vtxo, i, &mut shc, &prevouts).await
					.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;

				input.final_script_witness = Some(witness);
				let _ = exit_vtxo;
			}
		}

		Ok(())
	}
}

/// Public handle to the exit subsystem. Wraps `ExitInner` in an `Arc<RwLock>` so all
/// locking is internal — callers never need to acquire the lock directly.
pub struct Exit {
	inner: Arc<tokio::sync::RwLock<ExitInner>>,
}

impl Exit {
	pub(crate) async fn new(
		persister: Arc<dyn BarkPersister>,
		chain_source: Arc<ChainSource>,
		movement_manager: Arc<MovementManager>,
	) -> anyhow::Result<Exit> {
		let tx_manager = ExitTransactionManager::new(persister.clone(), chain_source.clone())?;
		let inner = ExitInner {
			exit_vtxos: Vec::new(),
			tx_manager,
			persister,
			chain_source,
			movement_manager,
		};
		Ok(Exit { inner: Arc::new(tokio::sync::RwLock::new(inner)) })
	}

	pub(crate) async fn load(&self) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		let inner = &mut *guard;
		let exit_vtxo_entries = inner.persister.get_exit_vtxo_entries().await?;
		inner.exit_vtxos.reserve(exit_vtxo_entries.len());

		for entry in exit_vtxo_entries {
			if let Some(vtxo) = inner.persister.get_wallet_vtxo(entry.vtxo_id).await? {
				let mut exit = ExitVtxo::from_entry(entry, &vtxo);
				exit.initialize(&mut inner.tx_manager, &*inner.persister).await?;
				inner.exit_vtxos.push(exit);
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
		let guard = self.inner.read().await;
		match guard.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id) {
			None => Ok(None),
			Some(exit) => {
				let mut txs = Vec::new();
				if include_transactions {
					if let Some(txids) = exit.txids() {
						txs.reserve(txids.len());
						for txid in txids {
							txs.push(guard.tx_manager.get_package(*txid)?.read().await.clone());
						}
					} else {
						// Realistically, the only way an exit isn't initialized is if it has been
						// marked for exit, and we haven't synced the exit system yet. On this basis
						// we can just return the VTXO transactions since there shouldn't be any
						// children. We need the full VTXO here for `transactions()`.
						let exit_vtxo = exit.get_full_vtxo(&*guard.persister).await?;
						for tx in exit_vtxo.transactions() {
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

	/// Returns a clone of the tracked [ExitVtxo] if it exists.
	pub async fn get_exit_vtxo(&self, vtxo_id: VtxoId) -> Option<ExitVtxo> {
		let guard = self.inner.read().await;
		guard.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id).cloned()
	}

	/// Returns the IDs of all active unilateral exits in this wallet.
	pub async fn get_exit_vtxo_ids(&self) -> Vec<VtxoId> {
		let guard = self.inner.read().await;
		guard.exit_vtxos.iter().map(|ev| ev.id()).collect()
	}

	/// Returns clones of all known unilateral exits in this wallet.
	pub async fn get_exit_vtxos(&self) -> Vec<ExitVtxo> {
		let guard = self.inner.read().await;
		guard.exit_vtxos.clone()
	}

	/// Returns whether a VTXO has an active or completed unilateral exit.
	pub async fn is_exiting(&self, vtxo_id: VtxoId) -> bool {
		let guard = self.inner.read().await;
		let state = guard.exit_vtxos.iter().find(|ev| ev.id() == vtxo_id).map(|ev| ev.state());
		match state {
			Some(ExitState::Start(_)) => true,
			Some(ExitState::Processing(_)) => true,
			Some(ExitState::AwaitingDelta(_)) => true,
			Some(ExitState::Claimable(_)) => true,
			Some(ExitState::ClaimInProgress(_)) => true,
			Some(ExitState::Claimed(_)) => true,
			Some(ExitState::VtxoAlreadySpent(_)) => false,
			Some(ExitState::Canceled(_)) => false,
			None => false,
		}
	}

	/// True if there are any unilateral exits which have been started but are not yet claimable.
	pub async fn has_pending_exits(&self) -> bool {
		let guard = self.inner.read().await;
		guard.exit_vtxos.iter().any(|ev| ev.state().is_pending())
	}

	/// Total balance held in VTXOs whose exit chain is confirmed onchain but hasn't yet
	/// been drained back into the onchain wallet (exit state in `{AwaitingDelta,
	/// Claimable, ClaimInProgress}` — i.e. the VTXO is `Exited` but not yet `Claimed`).
	///
	/// Returns [None] if the lock is currently held by a writer.
	pub fn try_pending_total(&self) -> Option<Amount> {
		self.inner.try_read().ok().map(|guard| {
			guard.exit_vtxos.iter()
				.filter(|ev| matches!(
					ev.state(),
					ExitState::AwaitingDelta(_)
					| ExitState::Claimable(_)
					| ExitState::ClaimInProgress(_),
				))
				.map(|ev| ev.amount())
				.sum()
		})
	}

	/// Returns the earliest block height at which all tracked exits will be claimable
	pub async fn all_claimable_at_height(&self) -> Option<BlockHeight> {
		let guard = self.inner.read().await;
		let mut highest_claimable_height = None;
		for exit in &guard.exit_vtxos {
			match exit.state().claimable_height() {
				Some(h) => highest_claimable_height = cmp::max(highest_claimable_height, Some(h)),
				None => continue,
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
	pub async fn start_exit_for_entire_wallet(&self) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		let all_vtxos = guard.persister.get_vtxos_by_state(&VtxoStateKind::UNSPENT_STATES).await?
			.into_iter();

		// Partition: separate eligible VTXOs from dust
		let total_vtxos = all_vtxos.len();
		let mut eligible = Vec::with_capacity(total_vtxos);
		for v in all_vtxos {
			// Skip non-standard VTXOs
			match guard.persister.get_full_vtxo(v.id()).await {
				Ok(Some(full)) => match full.check_standard() {
					Ok(()) => eligible.push(v.vtxo),
					Err(e) => warn!("Skipping non-standard VTXO {}: {:#}", v.id(), e),
				},
				Ok(None) => error!("Failed to retrieve full VTXO: {}", v.id()),
				Err(e) => error!("Failed to retrieve full VTXO {}: {:#}", v.id(), e),
			}
		}

		// If everything is dust.
		let ineligible = total_vtxos - eligible.len();
		if eligible.is_empty() && ineligible > 0 {
			warn!(
				"Exit not started: all {} VTXOs are non-standard. To exit and consolidate you \
				should try refreshing your VTXOs first",
				ineligible,
			);
			return Ok(());
		}

		guard.start_exit_for_vtxos(&eligible, false).await
	}

	/// Starts the unilateral exit process for the given VTXOs.
	///
	/// It does not block until completion, you must use [Exit::progress_exits] to advance each exit.
	///
	/// It's recommended to sync the wallet, by using something like [Wallet::maintenance] being
	/// doing this.
	pub async fn start_exit_for_vtxos(
		&self,
		vtxos: &[impl Borrow<Vtxo<Bare>>],
	) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		guard.start_exit_for_vtxos(vtxos, false).await
	}

	/// Similar to [Exit::start_exit_for_vtxos], but it skips any dust/standardness checks.
	///
	/// This should only be used when you are sure that the VTXOs are already onchain, or you are
	/// able to broadcast to a node which will accept non-standard transactions.
	pub async fn start_exit_for_vtxos_including_non_standard(
		&self,
		vtxos: &[impl Borrow<Vtxo<Bare>>],
	) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		guard.start_exit_for_vtxos(vtxos, true).await
	}

	/// Reset exit to an empty state. Should be called when dropping VTXOs
	///
	/// Note: _This method is **dangerous** and can lead to funds loss. Be cautious._
	pub(crate) async fn dangerous_clear_exit(&self) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		for exit in &guard.exit_vtxos {
			guard.persister.remove_exit_vtxo_entry(&exit.id()).await?;
		}
		guard.exit_vtxos.clear();
		Ok(())
	}

	/// Iterates over each registered VTXO and attempts to progress their unilateral exit.
	///
	/// Initializes any pending exits and refreshes the chain view of exit transactions
	/// before advancing state.
	///
	/// If you need to create CPFP transactions using a BDK-backed wallet, call
	/// [Exit::exits_needing_cpfp] after this, supply the signed CPFPs via [Exit::provide_cpfp_tx],
	/// then call this method again to advance the state past [ExitTxStatus::AwaitingCpfpBroadcast].
	///
	/// # Returns
	///
	/// The exit status of each VTXO being exited which has also not yet been spent
	pub async fn progress_exits(
		&self,
		wallet: &Wallet,
	) -> anyhow::Result<Option<Vec<ExitProgressStatus>>> {
		let mut guard = self.inner.write().await;
		guard.refresh_tx_state().await?;
		let mut exit_vtxos = std::mem::take(&mut guard.exit_vtxos);
		let mut exit_statuses = Vec::with_capacity(exit_vtxos.len());

		for ev in exit_vtxos.iter_mut() {
			if !ev.is_initialized() {
				warn!("Skipping progress of uninitialized unilateral exit {}", ev.id());
				continue;
			}

			info!("Progressing exit for VTXO {}", ev.id());
			let pre_state = ev.state().clone();
			let error = match ev.progress(
				wallet,
				&mut guard.tx_manager,
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

			let state_changed = ev.state() != &pre_state;
			Self::reconcile_vtxo_and_movement(
				wallet, &guard.movement_manager, ev, state_changed,
			).await;

			if !matches!(ev.state(), ExitState::Claimed(..)) {
				exit_statuses.push(ExitProgressStatus {
					vtxo_id: ev.id(),
					state: ev.state().clone(),
					error,
				});
			}
		}

		guard.exit_vtxos = exit_vtxos;
		Ok(Some(exit_statuses))
	}

	/// Maps the current exit state onto the VTXO and movement bookkeeping:
	/// - mark the VTXO `Exited` once every exit transaction has been broadcast (i.e. past
	///   `Start`, with `Processing` having all txs broadcast or beyond),
	/// - finish the movement as `Successful` when we reach `Claimed`,
	/// - finish the movement as `Canceled` when we detect the VTXO was already spent.
	///
	/// All updates are best-effort: failures are logged and don't abort progress. The VTXO
	/// transition is idempotent; the movement transitions only fire on a fresh state change
	/// to avoid notification spam.
	async fn reconcile_vtxo_and_movement(
		wallet: &Wallet,
		movements: &MovementManager,
		ev: &ExitVtxo,
		state_changed: bool,
	) {
		if ev.state().warrants_exited_vtxo() {
			if let Err(e) = wallet.mark_vtxos_as_exited([ev.id()]).await {
				error!("Failed to mark VTXO {} as Exited: {:#}", ev.id(), e);
			}
		}

		if !state_changed {
			return;
		}
		let Some(movement_id) = ev.movement_id() else { return };
		let new_status = match ev.state() {
			ExitState::Claimed(_) => MovementStatus::Successful,
			ExitState::VtxoAlreadySpent(_) => MovementStatus::Canceled,
			_ => return,
		};
		if let Err(e) = movements.finish_movement(movement_id, new_status).await {
			error!(
				"Failed to finalize exit movement {} as {:?}: {:#}",
				movement_id, new_status, e,
			);
		}
	}

	/// For use when syncing. Pending exits will be initialized, the network status of each
	/// [ExitTransactionPackage] will be updated, and finally, any unilateral exits that are waiting
	/// for network updates will be progressed.
	pub async fn sync(
		&self,
		wallet: &Wallet,
	) -> anyhow::Result<()> {
		let mut guard = self.inner.write().await;
		guard.refresh_tx_state().await?;
		let mut exit_vtxos = std::mem::take(&mut guard.exit_vtxos);
		for exit in &mut exit_vtxos {
			if !exit.is_initialized() {
				warn!("Skipping progress of uninitialized unilateral exit {}", exit.id());
				continue;
			}

			let pre_state = exit.state().clone();
			if let Err(e) = exit.progress(
				wallet, &mut guard.tx_manager, true,
			).await {
				error!("Error syncing exit for VTXO {}: {}", exit.id(), e);
			}
			let state_changed = exit.state() != &pre_state;
			Self::reconcile_vtxo_and_movement(
				wallet, &guard.movement_manager, exit, state_changed,
			).await;
		}
		guard.exit_vtxos = exit_vtxos;
		Ok(())
	}


	/// Returns one [ExitCpfpRequest] for each exit transaction that needs a CPFP child.
	///
	/// A request with `rbf_requirement = None` means no CPFP exists yet. A request with
	/// `rbf_requirement = Some(...)` means a third-party CPFP is already in the mempool;
	/// the caller can optionally provide a replacement with a higher fee rate.
	/// Call [Exit::provide_cpfp_tx] to submit the child.
	pub async fn exits_needing_cpfp(&self) -> Vec<ExitCpfpRequest> {
		let guard = self.inner.read().await;
		let mut requests = Vec::new();
		for ev in &guard.exit_vtxos {
			let ExitState::Processing(s) = ev.state() else { continue };
			for tx in &s.transactions {
				let rbf_requirement = match &tx.status {
					ExitTxStatus::AwaitingCpfpBroadcast => None,
					ExitTxStatus::AwaitingConfirmation {..} => {
						// Read mempool RBF info from the transaction manager; fee info is
						// tracked on the child independently of its origin. If we don't have
						// it yet (e.g. ancestor info call hasn't run), skip this round — the
						// next sync will populate it.
						match guard.tx_manager.get_child_status(tx.txid).await {
							Ok(Some(c)) => match c.fee_info {
								Some(fi) => Some(RbfRequirement {
									min_fee_rate: fi.fee_rate,
									current_package_fee: fi.total_fee,
								}),
								None => continue,
							},
							_ => continue,
						}
					},
					_ => continue,
				};
				let package = match guard.tx_manager.get_package(tx.txid) {
					Ok(p) => p,
					Err(_) => continue,
				};
				let exit_tx = package.read().await.exit.tx.clone();
				requests.push(ExitCpfpRequest {
					vtxo_id: ev.id(),
					exit_tx,
					rbf_requirement,
				});
			}
		}
		requests
	}

	/// Submit a signed CPFP child transaction for a given exit transaction.
	///
	/// The child must spend the P2A anchor output of the parent exit transaction identified by
	/// `exit_txid`. The package is broadcast immediately and the state advances to
	/// [ExitTxStatus::AwaitingConfirmation]. The child is persisted so it survives restarts.
	///
	/// # TODO
	/// `wallet` is required here only because [ExitVtxo::progress] calls `get_vtxo(&wallet.db)`
	/// and `tip_height()` unconditionally, even though neither is needed for the
	/// `AwaitingCpfpBroadcast → AwaitingConfirmation` transition. The fix is to make [ExitVtxo::progress]
	/// take `persister` and `chain_source` separately instead of the full wallet, and call
	/// `tip_height()` lazily only where needed.
	pub async fn provide_cpfp_tx(
		&self,
		wallet: &Wallet,
		exit_txid: Txid,
		child_tx: Transaction,
	) -> anyhow::Result<(), ExitError> {
		let origin = ExitTxOrigin::Wallet { confirmed_in: None };
		let mut guard = self.inner.write().await;
		let inner = &mut *guard;
		inner.tx_manager.set_wallet_child_tx(exit_txid, child_tx, origin).await?;

		let package = inner.tx_manager.get_package(exit_txid)?;
		let pkg_guard = package.read().await;
		match inner.tx_manager.broadcast_package(&*pkg_guard).await {
			Ok(_) => {},
			Err(ExitError::ExitPackageBroadcastFailure { ref error, .. })
				if error.is_mempool_conflict() =>
			{
				warn!("CPFP broadcast conflict for {}: {} — another CPFP may already be in mempool", exit_txid, error);
			},
			Err(e) => return Err(e),
		}
		drop(pkg_guard);

		for ev in inner.exit_vtxos.iter_mut() {
			let ExitState::Processing(s) = ev.state() else { continue };
			let has_tx = s.transactions.iter().any(|tx| tx.txid == exit_txid);
			if has_tx {
				if let Err(e) = ev.progress(wallet, &mut inner.tx_manager, false).await {
					warn!("Failed to progress exit for {} after CPFP: {}", exit_txid, e);
				}
				break;
			}
		}

		Ok(())
	}

	/// Lists all exits that are claimable
	pub async fn list_claimable(&self) -> Vec<ExitVtxo> {
		let guard = self.inner.read().await;
		guard.exit_vtxos.iter().filter(|ev| ev.is_claimable()).cloned().collect()
	}

	/// Sign any inputs of the PSBT that is an exit claim input
	///
	/// Can take the result PSBT of [`bdk_wallet::TxBuilder::finish`] on which
	/// [`crate::onchain::TxBuilderExt::add_exit_claim_inputs`] has been used
	///
	/// Note: This doesn't mark the exit output as spent, it's up to the caller to
	/// do that, or it will be done once the transaction is seen in the network
	pub async fn sign_exit_claim_inputs(&self, psbt: &mut Psbt, wallet: &Wallet) -> anyhow::Result<()> {
		let guard = self.inner.read().await;
		guard.sign_exit_claim_inputs(psbt, wallet).await
	}

	/// Builds a PSBT that drains the provided claimable unilateral exits to the given address.
	///
	/// - `inputs`: Claimable unilateral exits.
	/// - `wallet`: The bark wallet containing the keys needed to spend the unilateral exits.
	/// - `address`: Destination address for the claim.
	/// - `fee_rate_override`: Optional fee rate to use.
	///
	/// Returns a PSBT ready to be broadcast.
	pub async fn drain_exits(
		&self,
		inputs: &[impl Borrow<ExitVtxo>],
		wallet: &Wallet,
		address: Address,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<Psbt, ExitError> {
		let guard = self.inner.read().await;

		let tip = guard.chain_source.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })?;

		if inputs.is_empty() {
			return Err(ExitError::ClaimMissingInputs);
		}
		let mut vtxos = HashMap::with_capacity(inputs.len());
		for input in inputs {
			let i = input.borrow();
			let vtxo = i.get_full_vtxo(&*guard.persister).await?;
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
				version: bitcoin::transaction::Version::TWO,
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
				i.set_exit_claim_input(v);
				i.witness_utxo = Some(v.txout())
			});
			guard.sign_exit_claim_inputs(&mut psbt, wallet).await
				.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;
			Ok(psbt)
		};
		let fee_amount = {
			let fee_rate = fee_rate_override
				.unwrap_or(guard.chain_source.fee_rates().await.regular);
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

