use bitcoin::Txid;
use log::{debug, trace};

use ark::{Vtxo, VtxoId};
use json::exit::ExitState;
use json::exit::error::ExitError;

use crate::exit::progress::{ExitStateProgress, ProgressContext, ProgressStep};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain::{self, ChainSourceClient};
use crate::persist::BarkPersister;

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

	pub async fn progress(
		&mut self,
		chain_source: &ChainSourceClient,
		tx_manager: &mut ExitTransactionManager,
		persister: &dyn BarkPersister,
		onchain: &mut onchain::Wallet,
	) -> anyhow::Result<(), ExitError> {
		const MAX_ITERATIONS: usize = 100;
		for _ in 0..MAX_ITERATIONS {
			let mut context = ProgressContext {
				vtxo: &self.vtxo,
				exit_txids: &self.txids,
				fee_rate: onchain.fee_rates.fast,
				chain_source: &chain_source,
				persister,
				onchain,
				tx_manager,
			};
			// Attempt to move to the next state, which may or may not generate a new state
			trace!("Progressing VTXO {} at height {}", self.id(), chain_source.tip().await.unwrap());
			match self.state.clone().progress(&mut context).await {
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
		persister.store_exit_vtxo_entry(&ExitEntry::new(self))
			.map_err(|e| ExitError::DatabaseVtxoStoreFailure { 
				vtxo_id: self.id(), error: e.to_string(),
			})
	}
}

pub struct ExitEntry {
	pub vtxo_id: VtxoId,
	pub state: ExitState,
	pub history: Vec<ExitState>,
}

impl ExitEntry {
	pub fn new(exit: &ExitVtxo) -> Self {
		Self {
			vtxo_id: exit.id(),
			state: exit.state().clone(),
			history: exit.history().clone(),
		}
	}
}
