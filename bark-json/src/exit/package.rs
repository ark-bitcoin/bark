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

impl From<bark::exit::models::ExitTransactionPackage> for ExitTransactionPackage {
	fn from(v: bark::exit::models::ExitTransactionPackage) -> Self {
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
	pub origin: ExitTxOrigin,
}

impl From<bark::exit::models::ChildTransactionInfo> for ChildTransactionInfo {
	fn from(v: bark::exit::models::ChildTransactionInfo) -> Self {
		ChildTransactionInfo { info: v.info.into(), origin: v.origin.into() }
	}
}