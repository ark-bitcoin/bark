pub mod error;
pub mod package;
pub mod states;

use bitcoin::Txid;

use bitcoin_ext::{BlockHeight, BlockRef};

use crate::exit::states::{
	ExitAwaitingDeltaState, ExitProcessingState, ExitClaimInProgressState, ExitClaimableState,
	ExitClaimedState, ExitStartState, ExitTx, ExitTxStatus
};

/// A utility type to wrap ExitState children so they can be easily serialized. This also helps with
/// debugging a lot!
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitState {
	Start(ExitStartState),
	Processing(ExitProcessingState),
	AwaitingDelta(ExitAwaitingDeltaState),
	Claimable(ExitClaimableState),
	ClaimInProgress(ExitClaimInProgressState),
	Claimed(ExitClaimedState),
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
		claimable_height: BlockHeight
	) -> Self {
		assert!(claimable_height >= confirmed_block.height);
		ExitState::AwaitingDelta(ExitAwaitingDeltaState {
			tip_height: tip,
			confirmed_block,
			claimable_height,
		})
	}

	pub fn new_claimable(
		tip: BlockHeight,
		claimable_since: BlockRef,
		last_scanned_block: Option<BlockRef>
	) -> Self {
		ExitState::Claimable(ExitClaimableState {
			tip_height: tip,
			claimable_since,
			last_scanned_block,
		})
	}

	pub fn new_claim_in_progress(
		tip: BlockHeight,
		claimable_since: BlockRef,
		claim_txid: Txid
	) -> Self {
		ExitState::ClaimInProgress(ExitClaimInProgressState {
			tip_height: tip,
			claimable_since,
			claim_txid,
		})
	}

	pub fn new_claimed(tip: BlockHeight, txid: Txid, block: BlockRef) -> Self {
		ExitState::Claimed(ExitClaimedState {
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
			ExitState::ClaimInProgress(_) => true,
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
			ExitState::Claimable(_) => true,
			ExitState::ClaimInProgress(_) => true,
			_ => false,
		}
	}

	pub fn claimable_height(&self) -> Option<BlockHeight> {
		match self {
			ExitState::AwaitingDelta(s) => Some(s.claimable_height),
			ExitState::Claimable(s) => Some(s.claimable_since.height),
			ExitState::ClaimInProgress(s) => Some(s.claimable_since.height),
			_ => None,
		}
	}
}
