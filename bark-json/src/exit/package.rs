use bitcoin::{Amount, FeeRate};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::states::ExitTxOrigin;
use crate::primitives::TransactionInfo;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitTransactionPackage {
	/// The actual unilateral exit transaction containing an anchor output and a spendable amount
	pub exit: TransactionInfo,
	/// The child transaction used to spend, and thus confirm, the exit anchor output
	pub child: Option<ChildTransactionInfo>,
}

impl From<bark::exit::ExitTransactionPackage> for ExitTransactionPackage {
	fn from(v: bark::exit::ExitTransactionPackage) -> Self {
		ExitTransactionPackage {
			exit: v.exit.into(),
			child: v.child.map(|x| x.into()),
		}
	}
}
/// Represents a child transaction for an exit transaction package with information about the origin
/// of the transaction
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ChildTransactionInfo {
	pub info: TransactionInfo,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fee_info: Option<FeeInfo>,
	pub origin: ExitTxOrigin,
}

impl From<bark::exit::ChildTransactionInfo> for ChildTransactionInfo {
	fn from(v: bark::exit::ChildTransactionInfo) -> Self {
		ChildTransactionInfo {
			info: v.info.into(),
			fee_info: v.fee_info.map(Into::into),
			origin: v.origin.into(),
		}
	}
}

/// Contains the data required to bump the fee for a given transaction (including ancestors).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct FeeInfo {
	/// The effective fee rate of the transaction (including unconfirmed CPFP ancestors), in
	/// sats per kvB. `kvb` matches the unit used elsewhere in `bark-json`
	/// (e.g. `offboard_feerate_sat_per_kvb`).
	#[serde(rename = "fee_rate_sat_per_kvb", with = "crate::serde_utils::fee_rate_sat_per_kvb")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub fee_rate: FeeRate,
	/// Sum of the transaction's own fee plus the fee of each of its unconfirmed ancestors.
	#[serde(rename = "total_fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub total_fee: Amount,
}

impl From<bark::exit::FeeInfo> for FeeInfo {
	fn from(v: bark::exit::FeeInfo) -> Self {
		FeeInfo { fee_rate: v.fee_rate, total_fee: v.total_fee }
	}
}
