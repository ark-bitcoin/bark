use std::collections::HashSet;
use std::fmt;

use bitcoin::{Amount, FeeRate, Txid};

use bitcoin_ext::{BlockHeight, BlockRef};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitTx {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Txid,
	pub status: ExitTxStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxStatus {
	#[default]
	VerifyInputs,
	AwaitingInputConfirmation {
		#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
		txids: HashSet<Txid>
	},
	NeedsSignedPackage,
	NeedsReplacementPackage {
		#[serde(rename = "min_fee_rate_kwu")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		min_fee_rate: FeeRate,
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		min_fee: Amount,
	},
	NeedsBroadcasting {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	BroadcastWithCpfp {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		child_txid: Txid,
		origin: ExitTxOrigin,
	},
	Confirmed {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		child_txid: Txid,
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		block: BlockRef,
		origin: ExitTxOrigin,
	},
}

impl fmt::Display for ExitTxStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl From<bark::exit::models::ExitTxStatus> for ExitTxStatus {
	fn from(v: bark::exit::models::ExitTxStatus) -> Self {
		match v {
			bark::exit::models::ExitTxStatus::VerifyInputs => {
				ExitTxStatus::VerifyInputs
			},
			bark::exit::models::ExitTxStatus::AwaitingInputConfirmation { txids } => {
				ExitTxStatus::AwaitingInputConfirmation { txids }
			},
			bark::exit::models::ExitTxStatus::NeedsSignedPackage => {
				ExitTxStatus::NeedsSignedPackage
			},
			bark::exit::models::ExitTxStatus::NeedsReplacementPackage { min_fee_rate, min_fee } => {
				ExitTxStatus::NeedsReplacementPackage { min_fee_rate, min_fee }
			},
			bark::exit::models::ExitTxStatus::NeedsBroadcasting { child_txid, origin } => {
				ExitTxStatus::NeedsBroadcasting { child_txid, origin: origin.into() }
			},
			bark::exit::models::ExitTxStatus::BroadcastWithCpfp { child_txid, origin } => {
				ExitTxStatus::BroadcastWithCpfp { child_txid, origin: origin.into() }
			},
			bark::exit::models::ExitTxStatus::Confirmed { child_txid, block, origin } => {
				ExitTxStatus::Confirmed { child_txid, block, origin: origin.into() }
			},
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitTxOrigin {
	Wallet {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		confirmed_in: Option<BlockRef>
	},
	Mempool {
		/// This is the effective fee rate of the transaction (including CPFP ancestors)
		#[serde(rename = "fee_rate_kwu")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		fee_rate: FeeRate,
		/// This includes the fees of the CPFP ancestors
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		total_fee: Amount,
	},
	Block {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		confirmed_in: BlockRef
	},
}

impl fmt::Display for ExitTxOrigin {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

impl From<bark::exit::models::ExitTxOrigin> for ExitTxOrigin {
	fn from(v: bark::exit::models::ExitTxOrigin) -> Self {
		match v {
			bark::exit::models::ExitTxOrigin::Wallet { confirmed_in } => {
				ExitTxOrigin::Wallet { confirmed_in }
			},
			bark::exit::models::ExitTxOrigin::Mempool { fee_rate, total_fee } => {
				ExitTxOrigin::Mempool { fee_rate, total_fee }
			},
			bark::exit::models::ExitTxOrigin::Block { confirmed_in } => {
				ExitTxOrigin::Block { confirmed_in }
			},
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitStartState {
	pub tip_height: BlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitProcessingState {
	pub tip_height: BlockHeight,
	pub transactions: Vec<ExitTx>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitAwaitingDeltaState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub confirmed_block: BlockRef,
	pub claimable_height: BlockHeight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimableState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub claimable_since: BlockRef,
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub last_scanned_block: Option<BlockRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimInProgressState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub claimable_since: BlockRef,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub claim_txid: Txid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimedState {
	pub tip_height: BlockHeight,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Txid,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub block: BlockRef,
}