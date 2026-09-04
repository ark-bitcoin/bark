use std::collections::HashMap;

use ark::VtxoId;
use bitcoin::Txid;

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::primitives::TransactionInfo;

/// The exit transactions of a set of VTXOs still awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct RemainingExitTransactions {
	/// The transactions each VTXO needs confirmed to be exited, in broadcast order.
	#[cfg_attr(feature = "utoipa", schema(value_type = HashMap<String, Vec<String>>))]
	pub exits: HashMap<VtxoId, Vec<Txid>>,
	/// Every transaction referenced by `exits` exactly once, parents before children.
	pub transactions: Vec<TransactionInfo>,
}

impl From<bark::exit::RemainingExitTransactions> for RemainingExitTransactions {
	fn from(v: bark::exit::RemainingExitTransactions) -> Self {
		RemainingExitTransactions {
			exits: v.exits,
			transactions: v.transactions.into_iter().map(Into::into).collect(),
		}
	}
}
