//! Unilateral exit tracking and progression for individual VTXOs.
//!
//! This module defines types that track the lifecycle of a single [Vtxo] exit, including its current
//! state, onchain transaction IDs, and a history of prior states for auditing and troubleshooting.
//!
//! The primary type is [ExitVtxo], which provides an async [`ExitVtxo::progress`] method to advance
//! the unilateral exit state machine until completion or until the next step actionable step such
//! as requiring more onchain funds or waiting for a confirmation.
//!
//! See [ExitModel] for persisting the state machine in a database.

use bitcoin::{Amount, FeeRate, Txid};
use log::{debug, trace};

use ark::{Vtxo, VtxoId};

use crate::chain::ChainSource;
use crate::exit::models::{ExitError, ExitState};
use crate::exit::progress::{ExitStateProgress, ProgressContext, ProgressStep};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain::ExitUnilaterally;
use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;
use crate::WalletVtxo;

/// Tracks the exit lifecycle for a single [Vtxo].
///
/// An `ExitVtxo` maintains:
/// - the underlying [Vtxo] being exited,
/// - the set of related onchain transaction IDs in topographical order,
/// - the current state [ExitState],
/// - and a history of prior states for debugging and auditing.
///
/// Use [ExitVtxo::progress] to drive the state machine forward. The method is idempotent and will
/// only persist when a logical state transition occurs.
#[derive(Debug, Clone)]
pub struct ExitVtxo {
	vtxo_id: VtxoId,
	amount: Amount,
	state: ExitState,
	history: Vec<ExitState>,
	txids: Option<Vec<Txid>>,
}

impl ExitVtxo {
	/// Create a new instance for the given [VtxoId] with an initial state of [ExitState::Start].
	/// The unilateral exit can't progress until [ExitVtxo::initialize] is called.
	///
	/// # Parameters
	/// - `vtxo_id`: the [VtxoId] being exited.
	/// - `tip`: current chain tip used to initialize the starting state.
	pub fn new(vtxo: &Vtxo, tip: u32) -> Self {
		Self {
			vtxo_id: vtxo.id(),
			amount: vtxo.amount(),
			state: ExitState::new_start(tip),
			history: vec![],
			txids: None,
		}
	}

	/// Reconstruct an `ExitVtxo` from its parts. This leaves the instance in an uninitialized
	/// state. Useful when loading a tracked exit from storage.
	///
	/// # Parameters
	/// - `entry`: The persisted data to reconstruct this instance from.
	/// - `vtxo`: The [Vtxo] that this exit is tracking.
	pub fn from_entry(entry: StoredExit, vtxo: &Vtxo) -> Self {
		assert_eq!(entry.vtxo_id, vtxo.id());
		ExitVtxo {
			vtxo_id: entry.vtxo_id,
			amount: vtxo.amount(),
			state: entry.state,
			history: entry.history,
			txids: None,
		}
	}

	/// Returns the ID of the tracked [Vtxo].
	pub fn id(&self) -> VtxoId {
		self.vtxo_id
	}

	/// Returns the amount being exited.
	pub fn amount(&self) -> Amount {
		self.amount
	}

	/// Returns the current state of the unilateral exit.
	pub fn state(&self) -> &ExitState {
		&self.state
	}

	/// Returns the history of the exit machine in the order that states were observed.
	pub fn history(&self) -> &Vec<ExitState> {
		&self.history
	}

	/// Returns the set of exit-related transaction IDs, these may not be broadcast yet. If the
	/// instance is not yet initialized, None will be returned.
	pub fn txids(&self) -> Option<&Vec<Txid>> {
		self.txids.as_ref()
	}

	/// True if the exit is currently [ExitState::Claimable] and can be claimed/spent.
	pub fn is_claimable(&self) -> bool {
		matches!(self.state, ExitState::Claimable(..))
	}

	/// True if [ExitVtxo::initialize] has been called and the exit is ready to progress.
	pub fn is_initialized(&self) -> bool {
		self.txids.is_some()
	}

	/// Prepares an [ExitVtxo] for progression by querying the list of transactions required to
	/// process the unilateral exit and adds them to the exit transaction manager.
	pub async fn initialize(
		&mut self,
		tx_manager: &mut ExitTransactionManager,
		persister: &dyn BarkPersister,
		onchain: &dyn ExitUnilaterally,
	) -> anyhow::Result<(), ExitError> {
		trace!("Initializing VTXO for exit {}", self.vtxo_id);
		let vtxo = self.get_vtxo(persister)?;
		self.txids = Some(tx_manager.track_vtxo_exits(&vtxo, onchain).await?);
		Ok(())
	}

	/// Advances the exit state machine for this [Vtxo].
	///
	/// The method:
	/// - Attempts to transition the unilateral exit state machine.
	/// - Persists only when a logical state change occurs.
	///
	/// Returns:
	/// - `Ok(())` when no more immediate work is required, such as when we're waiting for a
	///   confirmation or when the exit is complete.
	/// - `Err(ExitError)` when an unrecoverable issue occurs, such as requiring more onchain funds
	///   or if an exit transaction fails to broadcast; if the error includes a newer state, it will
	///   be committed before returning.
	///
	/// Notes:
	/// - If `fee_rate_override` is `None`, a suitable fee rate will be calculated.
	pub async fn progress(
		&mut self,
		chain_source: &ChainSource,
		tx_manager: &mut ExitTransactionManager,
		persister: &dyn BarkPersister,
		onchain: &mut dyn ExitUnilaterally,
		fee_rate_override: Option<FeeRate>,
		continue_until_finished: bool,
	) -> anyhow::Result<(), ExitError> {
		if self.txids.is_none() {
			return Err(ExitError::InternalError {
				error: String::from("Unilateral exit not yet initialized"),
			});
		}

		let wallet_vtxo = self.get_vtxo(persister)?;
		const MAX_ITERATIONS: usize = 100;
		for _ in 0..MAX_ITERATIONS {
			let mut context = ProgressContext {
				vtxo: &wallet_vtxo.vtxo,
				exit_txids: self.txids.as_ref().unwrap(),
				chain_source: &chain_source,
				fee_rate: fee_rate_override.unwrap_or(chain_source.fee_rates().await.fast),
				tx_manager,
			};
			// Attempt to move to the next state, which may or may not generate a new state
			trace!("Progressing VTXO {} at height {}", self.id(), chain_source.tip().await.unwrap());
			match self.state.clone().progress(&mut context, onchain).await {
				Ok(new_state) => {
					self.update_state_if_newer(new_state, persister)?;
					if !continue_until_finished {
						return Ok(());
					}
					match ProgressStep::from_exit_state(&self.state) {
						ProgressStep::Continue => debug!("VTXO {} can continue", self.id()),
						ProgressStep::Done => return Ok(())
					}
				},
				Err(e) => {
					// We may need to commit a new state before returning an error
					if let Some(new_state) = e.state {
						self.update_state_if_newer(new_state, persister)?;
					}
					return Err(e.error);
				}
			}
		}
		debug_assert!(false, "Exceeded maximum iterations for progressing VTXO {}", self.id());
		Ok(())
	}

	pub fn get_vtxo(&self, persister: &dyn BarkPersister) -> anyhow::Result<WalletVtxo, ExitError> {
		persister.get_wallet_vtxo(self.vtxo_id)
			.map_err(|e| ExitError::InvalidWalletState { error: e.to_string() })?
			.ok_or_else(|| ExitError::InternalError {
				error: format!("VTXO for exit couldn't be found: {}", self.vtxo_id)
			})
	}

	fn update_state_if_newer(
		&mut self,
		new: ExitState,
		persister: &dyn BarkPersister,
	) -> anyhow::Result<(), ExitError> {
		// We don't want to push a new history item unless the state has changed logically
		if new != self.state {
			self.history.push(self.state.clone());
			self.state = new;
			self.persist(persister)
		} else {
			Ok(())
		}
	}

	fn persist(&self, persister: &dyn BarkPersister) -> anyhow::Result<(), ExitError> {
		persister.store_exit_vtxo_entry(&StoredExit::new(self))
			.map_err(|e| ExitError::DatabaseVtxoStoreFailure {
				vtxo_id: self.id(), error: e.to_string(),
			})
	}
}
