pub mod error;
pub mod package;
pub mod states;

use bitcoin::Txid;

use bitcoin_ext::{BlockHeight, BlockRef};

use crate::exit::states::{
	ExitAwaitingDeltaState, ExitProcessingState, ExitSpendInProgressState, ExitSpendableState,
	ExitSpentState, ExitStartState, ExitTx, ExitTxStatus
};

/// A utility type to wrap ExitState children so they can be easily serialized. This also helps with
/// debugging a lot!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitState {
	Start(ExitStartState),
	Processing(ExitProcessingState),
	AwaitingDelta(ExitAwaitingDeltaState),
	Spendable(ExitSpendableState),
	SpendInProgress(ExitSpendInProgressState),
	Spent(ExitSpentState),
}

impl ExitState {
	pub fn new_start(tip: BlockHeight) -> Self {
		ExitState::Start(ExitStartState { tip_height: tip })
	}

	pub fn new_processing<T: IntoIterator<Item = Txid>>(tip: BlockHeight, txids: T) -> Self {
		ExitState::Processing(ExitProcessingState {
			tip_height: tip,
			transactions: txids.into_iter()
				.map(|id| ExitTx {
					txid: id,
					status: ExitTxStatus::VerifyInputs,
				})
				.collect::<Vec<_>>(),
		})
	}

	pub fn new_processing_from_transactions(tip: BlockHeight, transactions: Vec<ExitTx>) -> Self {
		ExitState::Processing(ExitProcessingState {
			tip_height: tip,
			transactions,
		})
	}

	pub fn new_awaiting_delta(
		tip: BlockHeight, 
		confirmed_block: BlockRef, 
		spendable_height: BlockHeight
	) -> Self {
		assert!(spendable_height >= confirmed_block.height);
		ExitState::AwaitingDelta(ExitAwaitingDeltaState {
			tip_height: tip,
			confirmed_block,
			spendable_height,
		})
	}

	pub fn new_spendable(
		tip: BlockHeight, 
		spendable_since: BlockRef, 
		last_scanned_block: Option<BlockRef>
	) -> Self {
		ExitState::Spendable(ExitSpendableState {
			tip_height: tip,
			spendable_since,
			last_scanned_block,
		})
	}

	pub fn new_spend_in_progress(
		tip: BlockHeight, 
		spendable_since: BlockRef, 
		spending_txid: Txid
	) -> Self {
		ExitState::SpendInProgress(ExitSpendInProgressState {
			tip_height: tip,
			spendable_since,
			spending_txid,
		})
	}

	pub fn new_spent(tip: BlockHeight, txid: Txid, block: BlockRef) -> Self {
		ExitState::Spent(ExitSpentState {
			tip_height: tip,
			txid,
			block,
		})
	}

	pub fn is_pending(&self) -> bool {
		match self {
			ExitState::Start(_) => true,
			ExitState::Processing(_) => true,
			ExitState::AwaitingDelta(_) => true,
			_ => false,
		}
	}

	pub fn requires_confirmations(&self) -> bool {
		match self {
			ExitState::Processing(s) => {
				s.transactions.iter().any(|s| match s.status {
					ExitTxStatus::AwaitingInputConfirmation { .. } => true,
					ExitTxStatus::BroadcastWithCpfp { .. } => true,
					_ => false,
				})
			},
			ExitState::AwaitingDelta(_) => true,
			ExitState::SpendInProgress(_) => true,
			_ => false,
		}
	}

	/// Indicates whether the state relies on network updates during wallet sync to check whether
	/// the exit can be spent
	pub fn requires_network_update(&self) -> bool {
		match self {
			// If all transactions are either confirmed or already broadcast we can count Processing
			// as requiring network updates since we don't need to create more exit packages.
			ExitState::Processing(s) => s.transactions.iter().all(|s| match s.status {
				ExitTxStatus::BroadcastWithCpfp { .. } => true,
				ExitTxStatus::Confirmed { .. } => true,
				_ => false,
			}),
			ExitState::AwaitingDelta(_) => true,
			ExitState::Spendable(_) => true,
			ExitState::SpendInProgress(_) => true,
			_ => false,
		}
	}

	pub fn spendable_height(&self) -> Option<BlockHeight> {
		match self {
			ExitState::AwaitingDelta(s) => Some(s.spendable_height),
			ExitState::Spendable(s) => Some(s.spendable_since.height),
			ExitState::SpendInProgress(s) => Some(s.spendable_since.height),
			_ => None,
		}
	}
}
