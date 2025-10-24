use std::collections::HashSet;
use std::fmt;

use bitcoin::{Amount, FeeRate, Txid};

use bitcoin_ext::{BlockHeight, BlockRef};
#[cfg(feature = "open-api")]
use utoipa::ToSchema;

use crate::exit::ExitState;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitTx {
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub txid: Txid,
	pub status: ExitTxStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxStatus {
	#[default]
	VerifyInputs,
	AwaitingInputConfirmation {
		#[cfg_attr(feature = "open-api", schema(value_type = Vec<String>))]
		txids: HashSet<Txid>
	},
	NeedsSignedPackage,
	NeedsReplacementPackage {
		#[serde(rename = "min_fee_rate_kwu")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		min_fee_rate: FeeRate,
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		min_fee: Amount,
	},
	NeedsBroadcasting {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	BroadcastWithCpfp {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	Confirmed {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		child_txid: Txid,
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxOrigin {
	Wallet {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		confirmed_in: Option<BlockRef>
	},
	Mempool {
		/// This is the effective fee rate of the transaction (including CPFP ancestors)
		#[serde(rename = "fee_rate_kwu")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		fee_rate: FeeRate,
		/// This includes the fees of the CPFP ancestors
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		total_fee: Amount,
	},
	Block {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitStartState {
	pub tip_height: BlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitProcessingState {
	pub tip_height: BlockHeight,
	pub transactions: Vec<ExitTx>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitAwaitingDeltaState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub confirmed_block: BlockRef,
	pub claimable_height: BlockHeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitClaimableState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub claimable_since: BlockRef,
	#[cfg_attr(feature = "open-api", schema(value_type = String, nullable = true))]
	pub last_scanned_block: Option<BlockRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitClaimInProgressState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub claimable_since: BlockRef,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub claim_txid: Txid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitClaimedState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub txid: Txid,
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
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
