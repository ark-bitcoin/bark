
use std::borrow::Borrow;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, FeeRate, Txid};

use ark::rounds::RoundId;
use ark::VtxoId;
use bitcoin_ext::{BlockDelta, BlockHeight};
#[cfg(feature = "open-api")]
use utoipa::ToSchema;

use crate::exit::error::ExitError;
use crate::exit::package::ExitTransactionPackage;
use crate::exit::ExitState;
use crate::primitives::{VtxoInfo, RecipientInfo};
use crate::serde_utils;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ArkInfo {
	/// The bitcoin network the server operates on
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub network: bitcoin::Network,
	/// The Ark server pubkey
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub server_pubkey: PublicKey,
	/// The interval between each round
	#[serde(with = "serde_utils::duration")]
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub round_interval: Duration,
	/// Number of nonces per round
	pub nb_round_nonces: usize,
	/// Delta between exit confirmation and coins becoming spendable
	pub vtxo_exit_delta: BlockDelta,
	/// Expiration delta of the VTXO
	pub vtxo_expiry_delta: BlockDelta,
	/// The number of blocks after which an HTLC-send VTXO expires once granted.
	pub htlc_send_expiry_delta: BlockDelta,
	/// The number of blocks to keep between Lightning and Ark HTLCs expiries
	pub htlc_expiry_delta: BlockDelta,
	/// Maximum amount of a VTXO
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub max_vtxo_amount: Option<Amount>,
	/// Maximum number of OOR transition after VTXO tree leaf
	pub max_arkoor_depth: u16,
	/// The number of confirmations required to register a board vtxo
	pub required_board_confirmations: usize,
	/// Maximum CLTV delta server will allow clients to request an
	/// invoice generation with.
	pub max_user_invoice_cltv_delta: u16,
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
			htlc_send_expiry_delta: v.htlc_send_expiry_delta,
			htlc_expiry_delta: v.htlc_expiry_delta,
			max_vtxo_amount: v.max_vtxo_amount,
			max_arkoor_depth: v.max_arkoor_depth,
			required_board_confirmations: v.required_board_confirmations,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct LightningReceiveBalance {
	#[serde(rename = "total_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub total: Amount,
	#[serde(rename = "claimable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub claimable: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct Balance {
	#[serde(rename = "spendable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub spendable: Amount,
	#[serde(rename = "pending_lightning_send_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub pending_lightning_send: Amount,
	pub pending_lightning_receive: LightningReceiveBalance,
	#[serde(rename = "pending_in_round_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub pending_in_round: Amount,
	#[serde(rename = "pending_board_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub pending_board: Amount,
	#[serde(
		default,
		rename = "pending_exit_sat",
		with = "bitcoin::amount::serde::as_sat::opt",
		skip_serializing_if = "Option::is_none",
	)]
	#[cfg_attr(feature = "open-api", schema(value_type = u64, nullable=true))]
	pub pending_exit: Option<Amount>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
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
	#[cfg_attr(feature = "open-api", schema(value_type = u64, nullable = true))]
	pub fallback_fee_rate: Option<FeeRate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitProgressResponse {
	/// Status of each pending exit transaction
	pub exits: Vec<ExitProgressStatus>,
	/// Whether all transactions have been confirmed
	pub done: bool,
	/// Block height at which all exit outputs will be spendable
	pub claimable_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitProgressStatus {
	/// The ID of the VTXO that is being unilaterally exited
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// Any error that occurred during the exit process
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<ExitError>,
}

impl From<bark::exit::models::ExitProgressStatus> for ExitProgressStatus {
	fn from(v: bark::exit::models::ExitProgressStatus) -> Self {
		ExitProgressStatus {
			vtxo_id: v.vtxo_id,
			state: v.state.into(),
			error: v.error.map(ExitError::from),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct ExitTransactionStatus {
	/// The ID of the VTXO that is being unilaterally exited
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub vtxo_id: VtxoId,
	/// The current state of the exit transaction
	pub state: ExitState,
	/// The history of each state the exit transaction has gone through
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub history: Option<Vec<ExitState>>,
	/// Each exit transaction package required for the unilateral exit
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub transactions: Vec<ExitTransactionPackage>,
}

impl From<bark::exit::models::ExitTransactionStatus> for ExitTransactionStatus {
	fn from(v: bark::exit::models::ExitTransactionStatus) -> Self {
		ExitTransactionStatus {
			vtxo_id: v.vtxo_id,
			state: v.state.into(),
			history: v.history.map(|h| h.into_iter().map(ExitState::from).collect()),
			transactions: v.transactions.into_iter().map(ExitTransactionPackage::from).collect(),
		}
	}
}

/// Describes a completed transition of funds from onchain to offchain.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct Board {
	/// The [Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub funding_txid: Txid,
	/// The info for each [ark::Vtxo] that was created
	/// in this board.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vec<VtxoInfo>,
}

impl From<bark::Board> for Board {
	fn from(v: bark::Board) -> Self {
		Board {
			funding_txid: v.funding_txid,
			vtxos: v.vtxos.into_iter().map(VtxoInfo::from).collect(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct Movement {
	pub id: u32,
	/// Fees paid for the movement
	#[cfg_attr(feature = "open-api", schema(value_type = u64))]
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vec<VtxoInfo>,
	/// Received VTXOs from this movement
	pub receives: Vec<VtxoInfo>,
	/// External recipients of the movement
	pub recipients: Vec<RecipientInfo>,
	/// Movement date
	pub created_at: String,
}


pub mod onchain {
	use super::*;

	#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
	#[cfg_attr(feature = "open-api", derive(ToSchema))]
	pub struct Send {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		pub txid: Txid,
	}

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
	#[cfg_attr(feature = "open-api", derive(ToSchema))]
	pub struct Address {
		#[cfg_attr(feature = "open-api", schema(value_type = String))]
		pub address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	}

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
	pub struct Balance {
		/// All of them combined.
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub total: Amount,
		/// Get sum of trusted_pending and confirmed coins.
		///
		/// This is the balance you can spend right now that shouldn't get cancelled via another party
		/// double spending it.
		#[serde(rename="trusted_spendable_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub trusted_spendable: Amount,
		/// All coinbase outputs not yet matured
		#[serde(rename="immature_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub immature: Amount,
		/// Unconfirmed UTXOs generated by a wallet tx
		#[serde(rename="trusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub trusted_pending: Amount,
		/// Unconfirmed UTXOs received from an external wallet
		#[serde(rename="untrusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub untrusted_pending: Amount,
		/// Confirmed and immediately spendable balance
		#[serde(rename="confirmed_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "open-api", schema(value_type = u64))]
		pub confirmed: Amount,
	}
}

/// Describes a completed transition of funds from offchain to onchain collaboratively with the
/// Ark server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct Offboard {
	/// The [RoundId] of the round in which the offboard occurred
	#[cfg_attr(feature = "open-api", schema(value_type = String))]
	pub round: RoundId,
	// TODO: List the [OutPoint] and [Amount] here
}

impl From<bark::Offboard> for Offboard {
	fn from(v: bark::Offboard) -> Self {
		Offboard { round: v.round }
	}
}

/// The output of the `bark refresh` command
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "open-api", derive(ToSchema))]
pub struct Refresh {
	/// A boolean indicated if the command participated
	/// in a round. If no [ark::Vtxo] was refreshed this variable
	/// will be set to [false] and otherwise [true]
	pub participate_round: bool,
	/// The [RoundId] of the round if the client participated in a round
	#[cfg_attr(feature = "open-api", schema(value_type = String, nullable = true))]
	pub round: Option<RoundId>,
}

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
				htlc_send_expiry_delta: j.htlc_send_expiry_delta,
				htlc_expiry_delta: j.htlc_expiry_delta,
				max_vtxo_amount: j.max_vtxo_amount,
				max_arkoor_depth: j.max_arkoor_depth,
				required_board_confirmations: j.required_board_confirmations,
				max_user_invoice_cltv_delta: j.max_user_invoice_cltv_delta,
			}
		}
	}
}
