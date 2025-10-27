use bitcoin::{Transaction, Txid};
#[cfg(feature = "open-api")]
use utoipa::ToSchema;

use crate::exit::states::ExitTxOrigin;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitTransactionPackage {
	/// The actual unilateral exit transaction containing an anchor output and a spendable amount
	pub exit: TransactionInfo,
	/// The child transaction used to spend, and thus confirm, the exit anchor output
	pub child: Option<ChildTransactionInfo>,
}

impl From<bark::exit::models::ExitTransactionPackage> for ExitTransactionPackage {
	fn from(v: bark::exit::models::ExitTransactionPackage) -> Self {
		ExitTransactionPackage {
			exit: v.exit.into(),
			child: v.child.map(|x| x.into()),
		}
	}
}

/// An information struct used to pair the ID of a transaction with the full transaction for ease
/// of use and readability for the user
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct TransactionInfo {
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub txid: Txid,
	#[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub tx: Transaction,
}

impl From<bark::exit::models::TransactionInfo> for TransactionInfo {
	fn from(v: bark::exit::models::TransactionInfo) -> Self {
		TransactionInfo { txid: v.txid, tx: v.tx }
	}
}
/// Represents a child transaction for an exit transaction package with information about the origin
/// of the transaction
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ChildTransactionInfo {
	pub info: TransactionInfo,
	pub origin: ExitTxOrigin,
}

impl From<bark::exit::models::ChildTransactionInfo> for ChildTransactionInfo {
	fn from(v: bark::exit::models::ChildTransactionInfo) -> Self {
		ChildTransactionInfo { info: v.info.into(), origin: v.origin.into() }
	}
}