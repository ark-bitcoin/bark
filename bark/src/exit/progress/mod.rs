pub(crate) mod states;
pub(crate) mod util;

use std::collections::HashSet;

use bitcoin::{FeeRate, Txid};
use log::{debug, error, warn};

use bitcoin_ext::{BlockHeight, BlockRef, TxStatus};

use crate::exit::models::{ExitError, ExitState, ExitTx, ExitTxOrigin, ExitTxStatus};
use crate::exit::transaction_manager::ExitTransactionManager;
use crate::{Wallet, WalletVtxo};

/// A trait which allows [ExitState] objects to transition from their current state to a new state
/// depending on the mempool or the blockchain. The state machine is wallet-agnostic; callers
/// use [crate::exit::Exit::exits_needing_cpfp] to query what CPFPs are needed and
/// [crate::exit::Exit::provide_cpfp_tx] to supply them.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub(crate) trait ExitStateProgress {
	async fn progress(
		self,
		ctx: &mut ProgressContext<'_>,
	) -> anyhow::Result<ExitState, ExitProgressError>;
}

pub(crate) enum ProgressStep {
	/// We can continue progressing the exit with the given state
	Continue,
	/// We should stop progressing the exit as we're waiting on external factors such as new blocks
	Done,
}

impl ProgressStep {
	pub fn from_exit_state(state: &ExitState) -> ProgressStep {
		match state {
			ExitState::Start(_) => ProgressStep::Continue,
			ExitState::Processing(s) => {
				let should_continue = s.transactions.iter().any(|tx| {
					match &tx.status {
						ExitTxStatus::VerifyInputs => true,
						ExitTxStatus::AwaitingInputConfirmation { .. } => false,
						ExitTxStatus::NeedsSignedPackage => false,
						ExitTxStatus::NeedsReplacementPackage { .. } => false,
						ExitTxStatus::NeedsBroadcasting { .. } => true,
						ExitTxStatus::BroadcastWithCpfp { .. } => false,
						// We don't need to handle the case when every transaction is confirmed as
						// we should no longer be in this state
						ExitTxStatus::Confirmed { .. } => false,
					}
				});
				if should_continue {
					ProgressStep::Continue
				} else {
					ProgressStep::Done
				}
			},
			ExitState::AwaitingDelta(_) => ProgressStep::Done,
			ExitState::Claimable(_) => ProgressStep::Done,
			ExitState::ClaimInProgress(_) => ProgressStep::Done,
			ExitState::Claimed(_) => ProgressStep::Done,
		}
	}
}

pub(crate) struct ExitProgressError {
	pub state: Option<ExitState>,
	pub error: ExitError,
}

impl From<ExitError> for ExitProgressError {
	fn from(error: ExitError) -> Self {
		Self {
			state: None,
			error,
		}
	}
}

pub(crate) struct ProgressContext<'a> {
	pub vtxo: &'a WalletVtxo,
	pub exit_txids: &'a Vec<Txid>,
	pub wallet: &'a Wallet,
	pub fee_rate: FeeRate,
	pub tx_manager: &'a mut ExitTransactionManager,
}

impl<'a> ProgressContext<'a> {
	pub async fn check_confirmed(&mut self, txid: Txid) -> bool {
		matches!(self.tx_manager.tx_status(txid).await, Ok(TxStatus::Confirmed(_)))
	}

	pub async fn check_status_from_inputs(
		&mut self, exit: &ExitTx, inputs: &HashSet<Txid>,
	) -> anyhow::Result<ExitTxStatus, ExitError> {
		let mut txids = HashSet::with_capacity(inputs.len());
		for txid in inputs.iter() {
			debug!("Checking if exit tx {} has the following confirmed input: {}",
				exit.txid, txid,
			);
			if !self.check_confirmed(*txid).await {
				debug!("Exit tx {} has unconfirmed input: {}", exit.txid, txid);
				txids.insert(*txid);
			}
		}
		if txids.is_empty() {
			debug!("All inputs are confirmed for exit tx {}", exit.txid);
			Ok(ExitTxStatus::NeedsSignedPackage)
		} else {
			debug!("Exit tx {} has {} unconfirmed inputs: {:?}", exit.txid, txids.len(), txids);
			Ok(ExitTxStatus::AwaitingInputConfirmation { txids })
		}
	}

	pub async fn get_block_ref(&self, height: BlockHeight) -> anyhow::Result<BlockRef, ExitError> {
		self.wallet.inner.chain.block_ref(height).await
			.map_err(|e| ExitError::BlockRetrievalFailure { height, error: e.to_string() })
	}

	pub async fn get_exit_child_status(
		&mut self,
		exit: &ExitTx,
		child_txid: Txid,
	) -> anyhow::Result<ExitTxStatus, ExitError> {
		let current_child_txid = self.tx_manager.get_child_txid(exit.txid).await?;
		if let Some(current) = current_child_txid {
			if current != child_txid {
				warn!("Exit CPFP tx {} for exit tx {} has been replaced by {}", child_txid, exit.txid, current);
			}
			debug!("Updating CPFP tx status {} for exit tx {}", current, exit.txid);
			self.get_exit_tx_status(exit).await
		} else {
			error!("Exit CPFP tx {} for exit tx {} has disappeared", child_txid, exit.txid);
			Ok(ExitTxStatus::NeedsSignedPackage)
		}
	}

	pub async fn get_exit_tx_status(
		&mut self,
		exit: &ExitTx,
	) -> anyhow::Result<ExitTxStatus, ExitError> {
		if let Some(child) = self.tx_manager.get_child_status(exit.txid).await? {
			match child.status {
				TxStatus::NotFound => Ok(ExitTxStatus::NeedsBroadcasting {
					child_txid: child.txid,
					origin: child.origin,
				}),
				TxStatus::Mempool => {
					// Check if we need to RBF
					match child.origin {
						ExitTxOrigin::Wallet { .. } => {
							Ok(ExitTxStatus::BroadcastWithCpfp {
								child_txid: child.txid,
								origin: child.origin,
							})
						},
						ExitTxOrigin::Mempool { fee_rate, total_fee } => {
							if fee_rate < self.fee_rate {
								Ok(ExitTxStatus::NeedsReplacementPackage {
									min_fee_rate: fee_rate,
									min_fee: total_fee,
								})
							} else {
								Ok(ExitTxStatus::BroadcastWithCpfp {
									child_txid: child.txid,
									origin: child.origin,
								})
							}
						},
						ExitTxOrigin::Block { .. } => Err(ExitError::InternalError {
							error: format!("TxStatus was {:?} when origin is {}, this should never happen", child.status, child.origin),
						})
					}

				},
				TxStatus::Confirmed(b) => Ok(ExitTxStatus::Confirmed {
					child_txid: child.txid,
					block: b,
					origin: child.origin,
				})
			}
		} else {
			Ok(ExitTxStatus::NeedsSignedPackage)
		}
	}

	pub(crate) async fn get_unique_inputs(
		&self,
		exit_txid: Txid,
	) -> Result<HashSet<Txid>, ExitError> {
		let package = self.tx_manager.get_package(exit_txid)?;
		let guard = package.read().await;
		Ok(guard.exit.tx.input
			.iter()
			.map(|i| i.previous_output.txid)
			.collect::<HashSet<_>>()
		)
	}

	pub async fn tip_height(&self) -> anyhow::Result<u32, ExitError> {
		self.wallet.inner.chain.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })
	}
}
