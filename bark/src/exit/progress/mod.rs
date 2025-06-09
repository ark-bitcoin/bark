pub(crate) mod states;
pub(crate) mod util;

use std::collections::HashSet;

use bitcoin::{Address, FeeRate, Transaction, Txid};
use bitcoin::params::Params;
use log::{debug, error, info, warn};
use tonic::async_trait;

use ark::Vtxo;
use bitcoin_ext::bdk::{CpfpError, WalletExt};
use bitcoin_ext::{BlockHeight, BlockRef};
use bitcoin_ext::rpc::TxStatus;
use json::exit::error::ExitError;
use json::exit::ExitState;
use json::exit::states::{ExitTx, ExitTxStatus};

use crate::exit::transaction_manager::ExitTransactionManager;
use crate::onchain;
use crate::onchain::ChainSourceClient;
use crate::persist::BarkPersister;

/// A trait which allows [ExitState] objects to transition from their current state to a new state
/// depending on the contents of the users wallet, the mempool or the blockchain. E.g. Calling
/// [ExitStateProgress::progress] on [json::exit::states::ExitStartState] should return an
/// [json::exit::states::ExitProcessingState] if the VTXO can be exited.
#[async_trait]
pub(crate) trait ExitStateProgress {
	async fn progress(
		self,
		ctx: &mut ProgressContext,
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
			ExitState::Processing(ref s) => {
				let should_continue = s.transactions.iter().any(|tx| {
					match &tx.status {
						ExitTxStatus::VerifyInputs => true,
						ExitTxStatus::AwaitingInputConfirmation { .. } => false,
						ExitTxStatus::NeedsSignedPackage => true,
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
			ExitState::Spendable(_) => ProgressStep::Done,
			ExitState::SpendInProgress(_) => ProgressStep::Done,
			ExitState::Spent(_) => ProgressStep::Done,
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
	pub vtxo: &'a Vtxo,
	pub exit_txids: &'a Vec<Txid>,
	pub chain_source: &'a ChainSourceClient,
	pub fee_rate: FeeRate,
	pub persister: &'a dyn BarkPersister,
	pub onchain: &'a mut onchain::Wallet,
	pub tx_manager: &'a mut ExitTransactionManager,
}

impl ProgressContext<'_> {
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
			info!("All inputs are confirmed for exit tx {}", exit.txid);
			Ok(ExitTxStatus::NeedsSignedPackage)
		} else {
			debug!("Exit tx {} has {} unconfirmed inputs: {:?}", exit.txid, txids.len(), txids);
			Ok(ExitTxStatus::AwaitingInputConfirmation { txids })
		}
	}

	pub fn create_exit_cpfp_tx(
		&mut self,
		exit_tx: &Transaction,
	) -> anyhow::Result<Transaction, ExitError> {
		let psbt = self.onchain.wallet.make_cpfp(&[&exit_tx], self.fee_rate)
			.map_err(|e| match e {
				// An exit transaction must have a fee anchor, if not we can't create a CPFP package.
				CpfpError::NoFeeAnchor(_) => ExitError::InternalError { error: e.to_string() },
				// This is thrown when the wallet doesn't have any confirmed UTXOs to use.
				CpfpError::InsufficientConfirmedFunds(f) => ExitError::InsufficientConfirmedFunds {
					needed: f.needed, available: f.available,
				},
			})?;
		self.onchain.finish_tx(psbt)
			.map_err(|e| ExitError::ExitPackageFinalizeFailure { error: e.to_string() })
	}

	pub async fn get_block_ref(&self, height: BlockHeight) -> anyhow::Result<BlockRef, ExitError> {
		self.chain_source.block_id(height).await
			.map_err(|e| ExitError::BlockRetrievalFailure { height, error: e.to_string() })
			.map(|id| id.into())
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
			info!("Updating CPFP tx status {} for exit tx {}", current, exit.txid);
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
				TxStatus::Mempool => Ok(ExitTxStatus::BroadcastWithCpfp {
					child_txid: child.txid,
					origin: child.origin,
				}),
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
		self.chain_source.tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })
	}

	pub fn vtxo_recipient(&self) -> anyhow::Result<Address, ExitError> {
		let params = Params::new(self.onchain.wallet.network());
		Ok(Address::from_script(&self.vtxo.spec().vtxo_spk(), params)?)
	}
}
