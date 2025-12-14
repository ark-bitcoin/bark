pub mod error;
pub mod package;
pub mod states;

pub use package::*;
pub use error::*;
pub use states::*;

use ark::VtxoId;
use bitcoin::Txid;

use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef, TxStatus};

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
		wait_delta: BlockDelta
	) -> Self {
		debug_assert_ne!(wait_delta, 0, "wait delta must be non-zero");
		let claimable_height = confirmed_block.height + wait_delta as BlockHeight;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitProgressResponse {
	/// Status of each pending exit transaction
	pub exits: Vec<ExitProgressStatus>,
	/// Whether all transactions have been confirmed
	pub done: bool,
	/// Block height at which all exit outputs will be spendable
	pub claimable_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitProgressStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// Any error that occurred during the exit process
	pub error: Option<ExitError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitTransactionStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// The history of each state the exit transaction has gone through
	pub history: Option<Vec<ExitState>>,
	/// Each exit transaction package required for the unilateral exit
	pub transactions: Vec<ExitTransactionPackage>,
}

#[derive(Clone, Copy, Debug,  Eq, PartialEq)]
pub struct ExitChildStatus {
	pub txid: Txid,
	pub status: TxStatus,
	pub origin: ExitTxOrigin,
}