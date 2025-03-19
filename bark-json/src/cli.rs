
use std::time::Duration;

use ark::rounds::RoundId;
use bitcoin::{Amount, Txid};
use crate::{primitives::{UtxoInfo, VtxoInfo}, serde_utils};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArkInfo {
	/// The Ark server pubkey
	pub asp_pubkey: String,
	/// The interval between each round
	#[serde(with = "serde_utils::duration")]
	pub round_interval: Duration,
	/// Number of nonces per round
	pub nb_round_nonces: usize,
	/// Expiration delta of the VTXO
	pub vtxo_expiry_delta: u16,
	/// Delta between exit confirmation and coins becoming spendable
	pub vtxo_exit_delta: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Balance {
	#[serde(rename = "onchain_sat", with = "bitcoin::amount::serde::as_sat")]
	pub onchain: Amount,
	#[serde(rename = "offchain_sat", with = "bitcoin::amount::serde::as_sat")]
	pub offchain: Amount,
	#[serde(rename = "pending_exit_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_exit: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExitStatus {
	/// Whether or not all txs have been confirmed
	pub done: bool,
	/// Height at which all exit outputs will be spendable
	pub height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Board {
	/// The [Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	pub funding_txid: Txid,
	/// The info for each <Vtxo> that was created
	/// in this board.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vec<VtxoInfo>,
}

pub mod onchain {
	use super::*;

	#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
	pub struct Send {
		pub txid: Txid,
	}

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
	pub struct Address {
		pub address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	}

	pub type Utxos = Vec<UtxoInfo>;

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
	pub struct Balance {
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		pub total: bitcoin::Amount
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offboard {
	/// The [RoundId] of the round in which the offboard occured
	pub round: RoundId,
}

/// The output of the `bark refresh` command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refresh {
	/// A boolean indicated if the command participated
	/// in a round. If no [Vtxo] was refreshed this variable
	/// will be set to [false] and otherwise [true]
	pub participate_round: bool,
	/// The [RoundId] of the round if the client participated in a round
	pub round: Option<RoundId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendOnchain {
	/// The [RoundId] of the round in which the send occured
	pub round: RoundId,
	// TODO: List the [OutPoint] and [Amount] here
}

pub type Vtxos = Vec<VtxoInfo>;
