use bitcoin::{FeeRate, Txid};
use log::{debug, trace};

use ark::{Vtxo, VtxoId};
use json::exit::ExitState;
use json::exit::error::ExitError;

use crate::exit::progress::{ExitStateProgress, ProgressContext, ProgressStep};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain::{ChainSource, ExitUnilaterally};
use crate::persist::BarkPersister;
use crate::persist::models::StoredExit;

pub struct ExitVtxo {
	vtxo: Vtxo,
	txids: Vec<Txid>,
	state: ExitState,
	history: Vec<ExitState>,
}

impl ExitVtxo {
	pub fn new(vtxo: Vtxo, txids: Vec<Txid>, tip: u32) -> Self {
		Self {
			vtxo,
			txids,
			state: ExitState::new_start(tip),
			history: vec![],
		}
	}

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

	pub fn id(&self) -> VtxoId {
		self.vtxo.id()
	}

	pub fn vtxo(&self) -> &Vtxo {
		&self.vtxo
	}

	pub fn state(&self) -> &ExitState {
		&self.state
	}

	pub fn history(&self) -> &Vec<ExitState> {
		&self.history
	}

	pub fn txids(&self) -> &Vec<Txid> {
		&self.txids
	}

	pub fn is_spendable(&self) -> bool {
		matches!(self.state, ExitState::Spendable(..))
	}

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
