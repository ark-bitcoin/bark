
use bitcoin::{Amount, Txid};
use crate::primitives::{VtxoInfo, UtxoInfo};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Balance {
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub offchain: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub pending_exit: Amount,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExitStatus {
	pub done: bool,
	pub height: Option<u32>,
}


pub mod onchain {
	use super::*;

	#[derive(Debug, Clone, Deserialize, Serialize)]
	pub struct Send {
		pub txid: Txid,
	}

	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct Address {
		pub address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	}

	pub type Utxos = Vec<UtxoInfo>;

	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct Balance {
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		pub total: bitcoin::Amount
	}
}

/// The output of the `bark refresh` command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refresh {
	/// A boolean indicated if the command participated
	/// in a round. If no [Vtxo] was refreshed this variable
	/// will be set to [false] and otherwise [true]
	pub participate_round: bool,
	/// The [Txid] of the round if the client participated in a round
	pub round_txid: Option<Txid>,
}

pub type Vtxos = Vec<VtxoInfo>;
