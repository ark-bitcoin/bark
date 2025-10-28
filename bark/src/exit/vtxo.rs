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

use bitcoin::{FeeRate, Txid};
use log::{debug, trace};

use ark::{Vtxo, VtxoId};

use crate::exit::models::{ExitError, ExitState};
use crate::exit::progress::{ExitStateProgress, ProgressContext, ProgressStep};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain::{ChainSource, ExitUnilaterally};
use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;

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
	vtxo: Vtxo,
	txids: Vec<Txid>,
	state: ExitState,
	history: Vec<ExitState>,
}

impl ExitVtxo {
	/// Create a new instance for the given [Vtxo].
	///
	/// - `vtxo`: the [Vtxo] being exited.
	/// - `txids`: the ID of each transaction which needs broadcasting onchain in topographical
	///   order.
	/// - `tip`: current chain tip used to initialize the starting state.
	pub fn new(vtxo: Vtxo, txids: Vec<Txid>, tip: u32) -> Self {
		Self {
			vtxo,
			txids,
			state: ExitState::new_start(tip),
			history: vec![],
		}
	}

	/// Reconstruct an `ExitVtxo` from its parts.
	///
	/// Useful when loading a tracked exit from storage.
	pub fn from_parts(
		vtxo: Vtxo,
		txids: Vec<Txid>,
		state: ExitState,
		history: Vec<ExitState>,
	) -> Self {
		ExitVtxo {
			vtxo,
			txids,
			state,
			history,
		}
	}

	/// Returns the ID of the tracked [Vtxo].
	pub fn id(&self) -> VtxoId {
		self.vtxo.id()
	}

	/// Returns the underlying [Vtxo].
	pub fn vtxo(&self) -> &Vtxo {
		&self.vtxo
	}

	/// Returns the current state of the unilateral exit.
	pub fn state(&self) -> &ExitState {
		&self.state
	}

	/// Returns the history of the exit machine in the order that states were observed.
	pub fn history(&self) -> &Vec<ExitState> {
		&self.history
	}

	/// Returns the set of exit-related transaction IDs, these may not be broadcast yet.
	pub fn txids(&self) -> &Vec<Txid> {
		&self.txids
	}

	/// True if the exit is currently [ExitState::Claimable] and can be claimed/spent.
	pub fn is_claimable(&self) -> bool {
		matches!(self.state, ExitState::Claimable(..))
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
	pub async fn progress<W: ExitUnilaterally>(
		&mut self,
		chain_source: &ChainSource,
		tx_manager: &mut ExitTransactionManager,
		persister: &dyn BarkPersister,
		onchain: &mut W,
		fee_rate_override: Option<FeeRate>,
	) -> anyhow::Result<(), ExitError> {
		const MAX_ITERATIONS: usize = 100;
		for _ in 0..MAX_ITERATIONS {
			let mut context = ProgressContext {
				vtxo: &self.vtxo,
				exit_txids: &self.txids,
				chain_source: &chain_source,
				fee_rate: fee_rate_override.unwrap_or(chain_source.fee_rates().await.fast),
				persister,
				tx_manager,
			};
			// Attempt to move to the next state, which may or may not generate a new state
			trace!("Progressing VTXO {} at height {}", self.id(), chain_source.tip().await.unwrap());
			match self.state.clone().progress(&mut context, onchain).await {
				Ok(new_state) => {
					self.update_state_if_newer(new_state, persister)?;
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
