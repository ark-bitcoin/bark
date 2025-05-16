use bitcoin::{Transaction, Txid};

use bitcoin_ext::BlockRef;

use crate::exit::states::ExitTxOrigin;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ExitTransactionPackage {
	/// The actual unilateral exit transaction containing an anchor output and a spendable amount
	pub exit: TransactionInfo,
	/// The child transaction used to spend, and thus confirm, the exit anchor output
	pub child: Option<ChildTransactionInfo>,
}

/// An information struct used to pair the ID of a transaction with the full transaction for ease
/// of use and readability for the user
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TransactionInfo {
	pub txid: Txid,
	#[serde(with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
	pub tx: Transaction,
}

/// Represents a child transaction for an exit transaction package with information about the origin
/// of the transaction
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChildTransactionInfo {
	pub info: TransactionInfo,
	pub origin: ExitTxOrigin,
	pub confirmed_in: Option<BlockRef>,
}

impl ChildTransactionInfo {
	pub fn from_block(info: TransactionInfo, block: Option<BlockRef>) -> Self {
		if let Some(block) = block {
			ChildTransactionInfo { info, origin: ExitTxOrigin::Block, confirmed_in: Some(block) }
		} else {
			ChildTransactionInfo { info, origin: ExitTxOrigin::Mempool, confirmed_in: None }
		}
	}
}
