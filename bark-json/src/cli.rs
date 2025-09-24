
use std::borrow::Borrow;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Amount, FeeRate, Txid, Wtxid, address};

use ark::lightning::{PaymentHash, Preimage};
use ark::VtxoId;
use bitcoin_ext::{BlockDelta, BlockHeight};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::error::ExitError;
use crate::exit::package::ExitTransactionPackage;
use crate::exit::ExitState;
use crate::primitives::{VtxoInfo, RecipientInfo};
use crate::{WalletVtxoInfo, serde_utils};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ArkInfo {
	/// The bitcoin network the server operates on
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub network: bitcoin::Network,
	/// The Ark server pubkey
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub server_pubkey: PublicKey,
	/// The interval between each round
	#[serde(with = "serde_utils::duration")]
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
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
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub max_vtxo_amount: Option<Amount>,
	/// Maximum number of OOR transition after VTXO tree leaf
	pub max_arkoor_depth: u16,
	/// The number of confirmations required to register a board vtxo
	pub required_board_confirmations: usize,
	/// Maximum CLTV delta server will allow clients to request an
	/// invoice generation with.
	pub max_user_invoice_cltv_delta: u16,
	/// Minimum amount for a board the server will cosign
	pub min_board_amount: Amount,
	/// offboard feerate in sat per kvb
	pub offboard_feerate_sat_per_kvb: u64,
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
			min_board_amount: v.min_board_amount,
			offboard_feerate_sat_per_kvb: v.offboard_feerate.to_sat_per_kwu() * 4,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningReceiveBalance {
	#[serde(rename = "total_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub total: Amount,
	#[serde(rename = "claimable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub claimable: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Balance {
	#[serde(rename = "spendable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub spendable: Amount,
	#[serde(rename = "pending_lightning_send_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_lightning_send: Amount,
	pub pending_lightning_receive: LightningReceiveBalance,
	#[serde(rename = "pending_in_round_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_in_round: Amount,
	#[serde(rename = "pending_board_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_board: Amount,
	#[serde(
		default,
		rename = "pending_exit_sat",
		with = "bitcoin::amount::serde::as_sat::opt",
		skip_serializing_if = "Option::is_none",
	)]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, nullable=true))]
	pub pending_exit: Option<Amount>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
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
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, nullable = true))]
	pub fallback_fee_rate: Option<FeeRate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitProgressResponse {
	/// Status of each pending exit transaction
	pub exits: Vec<ExitProgressStatus>,
	/// Whether all transactions have been confirmed
	pub done: bool,
	/// Block height at which all exit outputs will be spendable
	pub claimable_height: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitProgressStatus {
	/// The ID of the VTXO that is being unilaterally exited
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitTransactionStatus {
	/// The ID of the VTXO that is being unilaterally exited
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Board {
	/// The [Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
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
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Movement {
	pub id: u32,
	/// Fees paid for the movement
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
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
	#[cfg_attr(feature = "utoipa", derive(ToSchema))]
	pub struct Send {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		pub txid: Txid,
	}

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
	#[cfg_attr(feature = "utoipa", derive(ToSchema))]
	pub struct Address {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		pub address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	}

	#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
	#[cfg_attr(feature = "utoipa", derive(ToSchema))]
	pub struct OnchainBalance {
		/// All of them combined.
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub total: Amount,
		/// Get sum of trusted_pending and confirmed coins.
		///
		/// This is the balance you can spend right now that shouldn't get cancelled via another party
		/// double spending it.
		#[serde(rename="trusted_spendable_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub trusted_spendable: Amount,
		/// All coinbase outputs not yet matured
		#[serde(rename="immature_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub immature: Amount,
		/// Unconfirmed UTXOs generated by a wallet tx
		#[serde(rename="trusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub trusted_pending: Amount,
		/// Unconfirmed UTXOs received from an external wallet
		#[serde(rename="untrusted_pending_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub untrusted_pending: Amount,
		/// Confirmed and immediately spendable balance
		#[serde(rename="confirmed_sat", with="bitcoin::amount::serde::as_sat")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		pub confirmed: Amount,
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum RoundStatus {
	/// The round was successful and is fully confirmed
	Confirmed {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		funding_txid: Txid,
	},
	/// Round successful but not fully confirmed
	Unconfirmed {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		funding_txid: Txid,
	},
	/// We have unsigned funding transactions that might confirm
	Pending {
		#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
		unsigned_funding_txids: Vec<Txid>,
	},
	/// The round failed
	Failed {
		error: String,
	},
}

impl RoundStatus {
	/// Whether this is the final state and it won't change anymore
	pub fn is_final(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => false,
			Self::Pending { .. } => false,
			Self::Failed { .. } => true,
		}
	}

	/// Whether it looks like the round succeeded
	pub fn is_success(&self) -> bool {
		match self {
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => true,
			Self::Pending { .. } => false,
			Self::Failed { .. } => false,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct InvoiceInfo {
	/// The invoice string
	pub invoice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningReceiveInfo {
	/// The payment hash linked to the lightning receive info
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// The payment preimage linked to the lightning receive info
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_preimage: Preimage,
	/// The timestamp at which the preimage was revealed
	pub preimage_revealed_at: Option<chrono::DateTime<chrono::Utc>>,
	/// The invoice string
	pub invoice: String,
	/// The HTLC VTXOs granted by the server for the lightning receive
	///
	/// Only present if the lightning HTLC has been received by the server.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<WalletVtxoInfo>, nullable = true))]
	pub htlc_vtxos: Option<Vec<WalletVtxoInfo>>,
}

impl From<bark::persist::models::LightningReceive> for LightningReceiveInfo {
	fn from(v: bark::persist::models::LightningReceive) -> Self {
		LightningReceiveInfo {
			payment_hash: v.payment_hash,
			payment_preimage: v.payment_preimage,
			preimage_revealed_at: v.preimage_revealed_at.map(|ts| {
				chrono::DateTime::from_timestamp_secs(ts as i64)
					.expect("timestamp is valid")
			}),
			invoice: v.invoice.to_string(),
			htlc_vtxos: v.htlc_vtxos.map(|vtxos| vtxos.into_iter()
				.map(crate::primitives::WalletVtxoInfo::from).collect()),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct InputScriptInfo {
	pub hex: Option<Vec<u8>>,
	pub asm: Option<String>,
}

impl From<hal::tx::InputScriptInfo> for InputScriptInfo {
	fn from(v: hal::tx::InputScriptInfo) -> Self {
		InputScriptInfo {
			hex: v.hex.map(|hex| hex.bytes().to_vec()),
			asm: v.asm,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct InputInfo {
	pub prevout: Option<String>,
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub txid: Option<Txid>,
	pub vout: Option<u32>,
	pub script_sig: Option<InputScriptInfo>,
	pub sequence: Option<u32>,
	pub witness: Option<Vec<Vec<u8>>>,
}

impl From<hal::tx::InputInfo> for InputInfo {
	fn from(v: hal::tx::InputInfo) -> Self {
		InputInfo {
			prevout: v.prevout,
			txid: v.txid,
			vout: v.vout,
			script_sig: v.script_sig.map(InputScriptInfo::from),
			sequence: v.sequence,
			witness: v.witness.map(|witness| witness.into_iter().map(|witness| witness.bytes().to_vec()).collect()),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OutputScriptInfo {
	pub hex: Option<Vec<u8>>,
	pub asm: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none", rename = "type")]
	pub type_: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub address: Option<Address<address::NetworkUnchecked>>,
}

impl From<hal::tx::OutputScriptInfo> for OutputScriptInfo {
	fn from(v: hal::tx::OutputScriptInfo) -> Self {
		OutputScriptInfo {
			hex: v.hex.map(|hex| hex.bytes().to_vec()),
			asm: v.asm,
			type_: v.type_,
			address: v.address,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OutputInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, nullable = true))]
	pub value: Option<Amount>,
	pub script_pub_key: Option<OutputScriptInfo>,
}

impl From<hal::tx::OutputInfo> for OutputInfo {
	fn from(v: hal::tx::OutputInfo) -> Self {
		OutputInfo {
			value: v.value,
			script_pub_key: v.script_pub_key.map(OutputScriptInfo::from),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TransactionInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub txid: Option<Txid>,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub wtxid: Option<Wtxid>,
	pub size: Option<usize>,
	pub weight: Option<usize>,
	pub vsize: Option<usize>,
	pub version: Option<i32>,
	pub locktime: Option<u32>,
	pub inputs: Option<Vec<InputInfo>>,
	pub outputs: Option<Vec<OutputInfo>>,
	pub total_output_value: Option<u64>,
}

impl From<hal::tx::TransactionInfo> for TransactionInfo {
	fn from(v: hal::tx::TransactionInfo) -> Self {
		TransactionInfo {
			txid: v.txid,
			wtxid: v.wtxid,
			size: v.size,
			weight: v.weight,
			vsize: v.vsize,
			version: v.version,
			locktime: v.locktime,
			inputs: v.inputs.map(|inputs| {
				inputs.into_iter().map(InputInfo::from).collect()
			}),
			outputs: v.outputs.map(|outputs| {
				outputs.into_iter().map(OutputInfo::from).collect()
			}),
			total_output_value: v.total_output_value,
		}
	}
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
				min_board_amount: j.min_board_amount,
				offboard_feerate: FeeRate::from_sat_per_kwu(j.offboard_feerate_sat_per_kvb / 4)
			}
		}
	}
}
