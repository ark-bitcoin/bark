use std::collections::HashSet;
use std::fmt;

use bitcoin::{Amount, FeeRate, Txid};

use bitcoin_ext::{BlockHeight, BlockRef};

use crate::exit::ExitState;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitTx {
	pub txid: Txid,
	pub status: ExitTxStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxStatus {
	#[default]
	VerifyInputs,
	AwaitingInputConfirmation { txids: HashSet<Txid> },
	NeedsSignedPackage,
	NeedsBroadcasting { child_txid: Txid, origin: ExitTxOrigin, },
	BroadcastWithCpfp { child_txid: Txid, origin: ExitTxOrigin, },
	Confirmed { child_txid: Txid, block: BlockRef, origin: ExitTxOrigin, },
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
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxOrigin {
	Wallet { confirmed_in: Option<BlockRef> },
	Mempool {
		/// This is the effective fee rate of the transaction (including CPFP ancestors)
		#[serde(rename = "fee_rate_kwu")]
		fee_rate: FeeRate,
		/// This includes the fees of the CPFP ancestors
		total_fee: Amount,
	},
	Block { confirmed_in: BlockRef },
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
pub struct ExitStartState {
	pub tip_height: BlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitProcessingState {
	pub tip_height: BlockHeight,
	pub transactions: Vec<ExitTx>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitAwaitingDeltaState {
	pub tip_height: BlockHeight,
	pub confirmed_block: BlockRef,
	pub spendable_height: BlockHeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitSpendableState {
	pub tip_height: BlockHeight,
	pub spendable_since: BlockRef,
	pub last_scanned_block: Option<BlockRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitSpendInProgressState {
	pub tip_height: BlockHeight,
	pub spendable_since: BlockRef,
	pub spending_txid: Txid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitSpentState {
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

impl Into<ExitState> for ExitSpendableState {
	fn into(self) -> ExitState {
		ExitState::Spendable(self)
	}
}

impl Into<ExitState> for ExitSpendInProgressState {
	fn into(self) -> ExitState {
		ExitState::SpendInProgress(self)
	}
}

impl Into<ExitState> for ExitSpentState {
	fn into(self) -> ExitState {
		ExitState::Spent(self)
	}
}
