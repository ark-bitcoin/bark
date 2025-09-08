
use std::borrow::Borrow;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, FeeRate, Txid};

use ark::rounds::RoundId;
use ark::VtxoId;
use bitcoin_ext::BlockHeight;

use crate::exit::ExitState;
use crate::exit::error::ExitError;
use crate::exit::package::ExitTransactionPackage;
use crate::primitives::{UtxoInfo, VtxoInfo, RecipientInfo};
use crate::serde_utils;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArkInfo {
	/// the network the server operates on
	pub network: bitcoin::Network,
	/// The Ark server pubkey
	pub server_pubkey: PublicKey,
	/// The interval between each round
	#[serde(with = "serde_utils::duration")]
	pub round_interval: Duration,
	/// Number of nonces per round
	pub nb_round_nonces: usize,
	/// Delta between exit confirmation and coins becoming spendable
	pub vtxo_exit_delta: u16,
	/// Expiration delta of the VTXO
	pub vtxo_expiry_delta: u16,
	/// delta between in-Ark HTLC expiry and LN HTLC expiry
	pub htlc_expiry_delta: u16,
	/// Maximum amount of a VTXO
	pub max_vtxo_amount: Option<Amount>,
	/// Maximum number of OOR transition after VTXO tree leaf
	pub max_arkoor_depth: u16,
	/// number of confirmations required to register a board vtxo
	pub required_board_confirmations: usize,
}

impl<T: Borrow<ark::ArkInfo>> From<T> for ArkInfo {
	fn from(v: T) -> Self {
		let v = v.borrow();
	    ArkInfo {
			network: v.network,
			server_pubkey: v.server_pubkey,
			round_interval: v.round_interval,
			nb_round_nonces: v.nb_round_nonces,
			vtxo_exit_delta: v.vtxo_exit_delta,
			vtxo_expiry_delta: v.vtxo_expiry_delta,
			htlc_expiry_delta: v.htlc_expiry_delta,
			max_vtxo_amount: v.max_vtxo_amount,
			max_arkoor_depth: v.max_arkoor_depth,
			required_board_confirmations: v.required_board_confirmations,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Balance {
	#[serde(rename = "spendable_sat", with = "bitcoin::amount::serde::as_sat")]
	pub spendable: Amount,
	#[serde(rename = "pending_lightning_send_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_lightning_send: Amount,
	#[serde(rename = "pending_in_round_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_in_round: Amount,
	#[serde(rename = "pending_exit_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_exit: Amount,
	#[serde(rename = "pending_board_sat", with = "bitcoin::amount::serde::as_sat")]
	pub pending_board: Amount,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
	/// Ark server address
	pub ark: String,
	/// Bitcoin Core RPC address to use for syncing
	pub bitcoind: Option<String>,
	/// Cookie to use for RPC authentication
	pub bitcoind_cookie: Option<String>,
	/// Username to use for RPC authentication
	pub bitcoind_user: Option<String>,
	/// password to use for RPC authentication
	pub bitcoind_pass: Option<String>,
	/// The Esplora REST API address to use for syncing
	pub esplora: Option<String>,
	/// How many blocks before VTXO expiration before preemptively refreshing them
	pub vtxo_refresh_expiry_threshold: BlockHeight,
	#[serde(rename = "fallback_fee_rate_kvb", with = "serde_utils::fee_rate_sats_per_kvb")]
	pub fallback_fee_rate: Option<FeeRate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExitProgressResponse {
	/// Status of each pending exit transaction
	pub exits: Vec<ExitProgressStatus>,
	/// Whether all transactions have been confirmed
	pub done: bool,
	/// Block height at which all exit outputs will be spendable
	pub spendable_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExitProgressStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// Any error that occurred during the exit process
	pub error: Option<ExitError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExitTransactionStatus {
	/// The ID of the VTXO that is being unilaterally exited
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// The history of each state the exit transaction has gone through
	pub history: Option<Vec<ExitState>>,
	/// Each exit transaction package required for the unilateral exit
	pub transactions: Option<Vec<ExitTransactionPackage>>,
}

/// Describes a completed transition of funds from onchain to offchain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Board {
	/// The [Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	pub funding_txid: Txid,
	/// The info for each [ark::Vtxo] that was created
	/// in this board.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vtxos,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Movement {
	pub id: u32,
	/// Fees paid for the movement
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vtxos,
	/// Received VTXOs from this movement
	pub receives: Vtxos,
	/// External recipients of the movement
	pub recipients: Vec<RecipientInfo>,
	/// Movement date
	pub created_at: String,
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
		/// All of them combined.
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		pub total: Amount,
		/// Get sum of trusted_pending and confirmed coins.
		///
		/// This is the balance you can spend right now that shouldn't get cancelled via another party
		/// double spending it.
		#[serde(rename="trusted_spendable_sat", with="bitcoin::amount::serde::as_sat")]
		pub trusted_spendable: Amount,
		/// All coinbase outputs not yet matured
		#[serde(rename="immature_sat", with="bitcoin::amount::serde::as_sat")]
		pub immature: Amount,
		/// Unconfirmed UTXOs generated by a wallet tx
		#[serde(rename="trusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		pub trusted_pending: Amount,
		/// Unconfirmed UTXOs received from an external wallet
		#[serde(rename="untrusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		pub untrusted_pending: Amount,
		/// Confirmed and immediately spendable balance
		#[serde(rename="confirmed_sat", with="bitcoin::amount::serde::as_sat")]
		pub confirmed: Amount,
	}
}

/// Describes a completed transition of funds from offchain to onchain collaboratively with the
/// Ark server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offboard {
	/// The [RoundId] of the round in which the offboard occurred
	pub round: RoundId,
}

/// The output of the `bark refresh` command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refresh {
	/// A boolean indicated if the command participated
	/// in a round. If no [ark::Vtxo] was refreshed this variable
	/// will be set to [false] and otherwise [true]
	pub participate_round: bool,
	/// The [RoundId] of the round if the client participated in a round
	pub round: Option<RoundId>,
}

/// The result of participating in a round to send offchain funds to an onchain address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendOnchain {
	/// The [RoundId] of the round in which the onchain transaction occurred
	pub round: RoundId,
	// TODO: List the [OutPoint] and [Amount] here
}

pub type Vtxos = Vec<VtxoInfo>;

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn ark_info_fields() {
		//! the purpose of this test is to fail if we add a field to
		//! ark::ArkInfo but we forgot to add it to the ArkInfo here

		#[allow(unused)]
		fn convert(j: ArkInfo) -> ark::ArkInfo {
			ark::ArkInfo {
				network: j.network,
				server_pubkey: j.server_pubkey,
				round_interval: j.round_interval,
				nb_round_nonces: j.nb_round_nonces,
				vtxo_exit_delta: j.vtxo_exit_delta,
				vtxo_expiry_delta: j.vtxo_expiry_delta,
				htlc_expiry_delta: j.htlc_expiry_delta,
				max_vtxo_amount: j.max_vtxo_amount,
				max_arkoor_depth: j.max_arkoor_depth,
				required_board_confirmations: j.required_board_confirmations,
			}
		}
	}
}
