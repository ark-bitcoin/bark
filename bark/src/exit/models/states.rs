use std::collections::HashSet;
use std::fmt;

use bitcoin::{Amount, FeeRate, Txid};

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
	NeedsSignedPackage,
	NeedsReplacementPackage {
		min_fee_rate: FeeRate,
		min_fee: Amount,
	},
	NeedsBroadcasting {
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	BroadcastWithCpfp {
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
			ExitTxStatus::NeedsBroadcasting { child_txid, .. } => Some(child_txid),
			ExitTxStatus::BroadcastWithCpfp { child_txid, .. } => Some(child_txid),
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
	Mempool {
		/// This is the effective fee rate of the transaction (including CPFP ancestors)
		#[serde(rename = "fee_rate_kwu")]
		fee_rate: FeeRate,
		/// This includes the fees of the CPFP ancestors
		total_fee: Amount,
	},
	Block {
		confirmed_in: BlockRef
	},
}

impl ExitTxOrigin {
	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			ExitTxOrigin::Wallet { confirmed_in } => *confirmed_in,
			ExitTxOrigin::Mempool { .. } => None,
			ExitTxOrigin::Block { confirmed_in } => Some(*confirmed_in),
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
