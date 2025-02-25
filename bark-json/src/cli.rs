
use bitcoin::{Amount, Txid};
use crate::primitives::{VtxoInfo, UtxoInfo};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Balance {
	#[serde(rename = "onchain_sat", with = "bitcoin::amount::serde::as_sat")]
	pub onchain: Amount,
	#[serde(rename = "offchain_sat", with = "bitcoin::amount::serde::as_sat")]
	pub offchain: Amount,
	#[serde(rename = "pending_exit_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_exit: Amount,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExitStatus {
	/// Whether or not all txs have been confirmed
	pub done: bool,
	/// Height at which all exit outputs will be spendable
	pub height: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Onboard {
	/// The [Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the onboard to succeed.
	pub funding_txid: Txid,
	/// The info for each <Vtxo> that was created
	/// in this onboard.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vec<VtxoInfo>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offboard {
	/// The [Txid] of the round in which the offboard occured
	pub round_txid: Txid,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendOnchain {
	/// The [Txid] of the round in which the send occured
	pub round_txid: Txid,
	// TODO: List the [OutPoint] and [Amount] here
}

pub type Vtxos = Vec<VtxoInfo>;
