use std::collections::HashSet;
use std::fmt;

use bitcoin::Txid;

use bitcoin_ext::{BlockHeight, BlockRef};

use crate::exit::models::ExitState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitTx {
	pub txid: Txid,
	pub status: ExitTxStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxStatus {
	#[default]
	VerifyInputs,
	AwaitingInputConfirmation {
		txids: HashSet<Txid>
	},
	AwaitingCpfpBroadcast,
	AwaitingConfirmation {
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	Confirmed {
		child_txid: Txid,
		block: BlockRef,
		origin: ExitTxOrigin,
	},
}

impl ExitTxStatus {
	pub fn child_txid(&self) -> Option<&Txid> {
		match self {
			ExitTxStatus::AwaitingConfirmation { child_txid, .. } => Some(child_txid),
			ExitTxStatus::Confirmed { child_txid, .. } => Some(child_txid),
			_ => None,
		}
	}

	pub fn confirmed_in(&self) -> Option<&BlockRef> {
		match self {
			ExitTxStatus::Confirmed { block, .. } => Some(block),
			_ => None,
		}
	}
}

impl fmt::Display for ExitTxStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxOrigin {
	Wallet {
		confirmed_in: Option<BlockRef>
	},
	Mempool,
	Block {
		confirmed_in: BlockRef
	},
}

impl ExitTxOrigin {
	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			ExitTxOrigin::Wallet { confirmed_in } => *confirmed_in,
			ExitTxOrigin::Mempool => None,
			ExitTxOrigin::Block { confirmed_in } => Some(*confirmed_in),
		}
	}

	/// Returns a copy of this origin reflecting the given confirmation state, preserving the
	/// origin kind where it makes sense. A `Wallet` origin keeps its kind (we still know it's
	/// ours) and updates its `confirmed_in`; mempool/block origins become `Block` once confirmed
	/// and `Mempool` otherwise.
	pub fn with_confirmed_in(self, confirmed_in: Option<BlockRef>) -> ExitTxOrigin {
		match (self, confirmed_in) {
			(ExitTxOrigin::Wallet { .. }, _) => ExitTxOrigin::Wallet { confirmed_in },
			(_, Some(confirmed_in)) => ExitTxOrigin::Block { confirmed_in },
			(_, None) => ExitTxOrigin::Mempool,
		}
	}
}

impl fmt::Display for ExitTxOrigin {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitStartState {
	pub tip_height: BlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitProcessingState {
	pub tip_height: BlockHeight,
	pub transactions: Vec<ExitTx>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitAwaitingDeltaState {
	pub tip_height: BlockHeight,
	pub confirmed_block: BlockRef,
	pub claimable_height: BlockHeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimableState {
	pub tip_height: BlockHeight,
	pub claimable_since: BlockRef,
	pub last_scanned_block: Option<BlockRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimInProgressState {
	pub tip_height: BlockHeight,
	pub claimable_since: BlockRef,
	pub claim_txid: Txid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitClaimedState {
	pub tip_height: BlockHeight,
	pub txid: Txid,
	pub block: BlockRef,
}

/// Terminal state reached when the exit cannot proceed because the VTXO has already been
/// consumed by something other than this exit (e.g. the server forfeited it in a round).
/// No exit transactions can be broadcast at this point; the caller should cancel the
/// associated movement and remove the exit from active tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitVtxoAlreadySpentState {
	pub tip_height: BlockHeight,
}

/// Resumable state for the current exit attempt: the user explicitly canceled the exit while
/// it was still in its abortable window (before any exit transaction was broadcast).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExitCanceledState {
	pub tip_height: BlockHeight,
}

impl Into<ExitState> for ExitStartState {
	fn into(self) -> ExitState {
		ExitState::Start(self)
	}
}

impl Into<ExitState> for ExitProcessingState {
	fn into(self) -> ExitState {
		ExitState::Processing(self)
	}
}

impl Into<ExitState> for ExitAwaitingDeltaState {
	fn into(self) -> ExitState {
		ExitState::AwaitingDelta(self)
	}
}

impl Into<ExitState> for ExitClaimableState {
	fn into(self) -> ExitState {
		ExitState::Claimable(self)
	}
}

impl Into<ExitState> for ExitClaimInProgressState {
	fn into(self) -> ExitState {
		ExitState::ClaimInProgress(self)
	}
}

impl Into<ExitState> for ExitClaimedState {
	fn into(self) -> ExitState {
		ExitState::Claimed(self)
	}
}

impl Into<ExitState> for ExitVtxoAlreadySpentState {
	fn into(self) -> ExitState {
		ExitState::VtxoAlreadySpent(self)
	}
}

impl Into<ExitState> for ExitCanceledState {
	fn into(self) -> ExitState {
		ExitState::Canceled(self)
	}
}
