pub mod fees;
#[cfg(feature = "onchain-bdk")]
pub mod onchain;

use std::borrow::Borrow;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Txid};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use ark::VtxoId;
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::{AmountExt, BlockDelta};

use crate::cli::fees::FeeSchedule;
use crate::exit::error::ExitError;
use crate::exit::package::ExitTransactionPackage;
use crate::exit::ExitState;
use crate::primitives::{TransactionInfo, WalletVtxoInfo};
use crate::serde_utils;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ArkInfo {
	/// The bitcoin network the server operates on
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub network: bitcoin::Network,
	/// The Ark server pubkey
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub server_pubkey: PublicKey,
	/// The pubkey used for blinding unified mailbox IDs
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub mailbox_pubkey: PublicKey,
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
	/// The number of confirmations required to register a board vtxo
	pub required_board_confirmations: usize,
	/// Maximum CLTV delta server will allow clients to request an
	/// invoice generation with.
	pub max_user_invoice_cltv_delta: u16,
	/// Minimum amount for a board the server will cosign
	#[serde(rename = "min_board_amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub min_board_amount: Amount,
	/// offboard feerate in sat per kvb
	pub offboard_feerate_sat_per_kvb: u64,
	/// Indicates whether the Ark server requires clients to either
	/// provide a VTXO ownership proof, or a lightning receive token
	/// when preparing a lightning claim.
	pub ln_receive_anti_dos_required: bool,
	/// The fee schedule outlining any fees that must be paid to interact with the Ark server.
	pub fees: FeeSchedule,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct NextRoundStart {
	/// The next round start time in RFC 3339 format
	pub start_time: chrono::DateTime<chrono::Local>,
}

impl<T: Borrow<ark::ArkInfo>> From<T> for ArkInfo {
	fn from(v: T) -> Self {
		let v = v.borrow();
	    ArkInfo {
			network: v.network,
			server_pubkey: v.server_pubkey,
			mailbox_pubkey: v.mailbox_pubkey,
			round_interval: v.round_interval,
			nb_round_nonces: v.nb_round_nonces,
			vtxo_exit_delta: v.vtxo_exit_delta,
			vtxo_expiry_delta: v.vtxo_expiry_delta,
			htlc_send_expiry_delta: v.htlc_send_expiry_delta,
			htlc_expiry_delta: v.htlc_expiry_delta,
			max_vtxo_amount: v.max_vtxo_amount,
			required_board_confirmations: v.required_board_confirmations,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta,
			min_board_amount: v.min_board_amount,
			offboard_feerate_sat_per_kvb: v.offboard_feerate.to_sat_per_kwu() * 4,
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
			fees: v.fees.clone().into(),
		}
	}
}

/// The different balances of a Bark wallet, broken down by state.
///
/// All amounts are in sats.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Balance {
	/// Sats that are immediately spendable, either in-round or
	/// out-of-round.
	#[serde(rename = "spendable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub spendable: Amount,
	/// Sats locked in an outgoing Lightning payment that has not yet
	/// settled.
	#[serde(rename = "pending_lightning_send_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_lightning_send: Amount,
	/// Sats from an incoming Lightning payment that can be claimed but
	/// have not yet been swept into a spendable VTXO.
	#[serde(rename = "claimable_lightning_receive_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub claimable_lightning_receive: Amount,
	/// Sats locked in VTXOs forfeited for a round that has not yet
	/// completed.
	#[serde(rename = "pending_in_round_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_in_round: Amount,
	/// Sats in board transactions that are waiting for sufficient
	/// on-chain confirmations before becoming spendable.
	#[serde(rename = "pending_board_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_board: Amount,
	/// Sats in VTXOs undergoing an emergency exit back on-chain.
	/// `null` if the exit subsystem is unavailable.
	#[serde(
		default,
		rename = "pending_exit_sat",
		with = "bitcoin::amount::serde::as_sat::opt",
		skip_serializing_if = "Option::is_none",
	)]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, nullable=true))]
	pub pending_exit: Option<Amount>,
}

impl From<bark::Balance> for Balance {
	fn from(v: bark::Balance) -> Self {
		Balance {
			spendable: v.spendable,
			pending_in_round: v.pending_in_round,
			pending_lightning_send: v.pending_lightning_send,
			claimable_lightning_receive: v.claimable_lightning_receive,
			pending_exit: v.pending_exit,
			pending_board: v.pending_board,
		}
	}
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

impl From<bark::exit::ExitProgressStatus> for ExitProgressStatus {
	fn from(v: bark::exit::ExitProgressStatus) -> Self {
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

impl From<bark::exit::ExitTransactionStatus> for ExitTransactionStatus {
	fn from(v: bark::exit::ExitTransactionStatus) -> Self {
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
pub struct PendingBoardInfo {
	/// The funding transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	pub funding_tx: TransactionInfo,
	/// The IDs of the VTXOs that were created
	/// in this board.
	///
	/// Currently, this is always a vector of length 1
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub vtxos: Vec<VtxoId>,
	/// The amount of the board.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// The ID of the movement associated with this board.
	pub movement_id: u32,
}

impl From<bark::persist::models::PendingBoard> for PendingBoardInfo {
	fn from(v: bark::persist::models::PendingBoard) -> Self {
		PendingBoardInfo {
			funding_tx: v.funding_tx.into(),
			vtxos: v.vtxos,
			amount: v.amount,
			movement_id: v.movement_id.0,
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum RoundStatus {
	/// Failed to sync round
	SyncError {
		error: String,
	},
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
	Pending,
	/// The round failed
	Failed {
		error: String,
	},
	/// The round canceled
	Canceled,
}

impl RoundStatus {
	/// Whether this is the final state and it won't change anymore
	pub fn is_final(&self) -> bool {
		match self {
			Self::SyncError { .. } => false,
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => false,
			Self::Pending { .. } => false,
			Self::Failed { .. } => true,
			Self::Canceled => true,
		}
	}

	/// Whether it looks like the round succeeded
	pub fn is_success(&self) -> bool {
		match self {
			Self::SyncError { .. } => false,
			Self::Confirmed { .. } => true,
			Self::Unconfirmed { .. } => true,
			Self::Pending { .. } => false,
			Self::Failed { .. } => false,
			Self::Canceled => false,
		}
	}
}

impl From<bark::round::RoundStatus> for RoundStatus {
	fn from(s: bark::round::RoundStatus) -> Self {
		match s {
			bark::round::RoundStatus::Confirmed { funding_txid } => {
				Self::Confirmed { funding_txid }
			},
			bark::round::RoundStatus::Unconfirmed { funding_txid } => {
				Self::Unconfirmed { funding_txid }
			},
			bark::round::RoundStatus::Pending => Self::Pending,
			bark::round::RoundStatus::Failed { error } => Self::Failed { error },
			bark::round::RoundStatus::Canceled => Self::Canceled,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct RoundStateInfo {
	pub round_state_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct InvoiceInfo {
	/// The invoice string
	pub invoice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardResult {
	/// The transaction id of the offboard transaction
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub offboard_txid: Txid,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningReceiveInfo {
	/// The amount of the lightning receive
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// The payment hash linked to the lightning receive info
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// The payment preimage linked to the lightning receive info
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_preimage: Preimage,
	/// The timestamp at which the preimage was revealed
	pub preimage_revealed_at: Option<chrono::DateTime<chrono::Local>>,
	/// The timestamp at which the lightning receive was finished
	pub finished_at: Option<chrono::DateTime<chrono::Local>>,
	/// The invoice string
	pub invoice: String,
	/// The HTLC VTXOs granted by the server for the lightning receive
	///
	/// Empty if the lightning HTLC has not yet been received by the server.
	#[serde(default, deserialize_with = "serde_utils::null_as_default")]
	#[cfg_attr(feature = "utoipa", schema(required = true))]
	pub htlc_vtxos: Vec<WalletVtxoInfo>,
}

impl From<bark::persist::models::LightningReceive> for LightningReceiveInfo {
	fn from(v: bark::persist::models::LightningReceive) -> Self {
		LightningReceiveInfo {
			payment_hash: v.payment_hash,
			payment_preimage: v.payment_preimage,
			preimage_revealed_at: v.preimage_revealed_at,
			invoice: v.invoice.to_string(),
			htlc_vtxos: v.htlc_vtxos.into_iter()
				.map(crate::primitives::WalletVtxoInfo::from).collect(),
			amount: v.invoice.amount_milli_satoshis().map(Amount::from_msat_floor)
				.unwrap_or(Amount::ZERO),
			finished_at: v.finished_at,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningSendInfo {
	/// The amount being sent
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// The payment hash linked to the lightning send
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// The invoice string
	pub invoice: String,
	/// The payment preimage if the payment has completed successfully
	#[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
	pub preimage: Option<Preimage>,
	/// The HTLC VTXOs used for the lightning send
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<WalletVtxoInfo>))]
	pub htlc_vtxos: Vec<WalletVtxoInfo>,
	/// When the payment reached a terminal state (succeeded or failed)
	#[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
	pub finished_at: Option<chrono::DateTime<chrono::Local>>,
}

impl From<bark::persist::models::LightningSend> for LightningSendInfo {
	fn from(v: bark::persist::models::LightningSend) -> Self {
		LightningSendInfo {
			payment_hash: v.invoice.payment_hash(),
			invoice: v.invoice.to_string(),
			htlc_vtxos: v.htlc_vtxos.into_iter()
				.map(crate::primitives::WalletVtxoInfo::from).collect(),
			amount: v.amount,
			preimage: v.preimage,
			finished_at: v.finished_at,
		}
	}
}

/// Represents a lightning movement, either a send or receive
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum LightningMovement {
	/// A lightning receive (incoming payment)
	Receive(LightningReceiveInfo),
	/// A lightning send (outgoing payment)
	Send(LightningSendInfo),
}

#[cfg(test)]
mod test {
	use bitcoin::FeeRate;
	use super::*;

	fn lightning_receive_base_json() -> serde_json::Value {
		serde_json::json!({
			"amount_sat": 1000,
			"payment_hash": "0000000000000000000000000000000000000000000000000000000000000000",
			"payment_preimage": "0000000000000000000000000000000000000000000000000000000000000000",
			"preimage_revealed_at": null,
			"finished_at": null,
			"invoice": "lnbc1",
		})
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxos_missing() {
		let json = lightning_receive_base_json();
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxos_null() {
		let mut json = lightning_receive_base_json();
		json["htlc_vtxos"] = serde_json::json!(null);
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxos_empty() {
		let mut json = lightning_receive_base_json();
		json["htlc_vtxos"] = serde_json::json!([]);
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[test]
	fn ark_info_fields() {
		//! the purpose of this test is to fail if we add a field to
		//! ark::ArkInfo but we forgot to add it to the ArkInfo here

		#[allow(unused)]
		fn convert(j: ArkInfo) -> ark::ArkInfo {
			ark::ArkInfo {
				network: j.network,
				server_pubkey: j.server_pubkey,
				mailbox_pubkey: j.mailbox_pubkey,
				round_interval: j.round_interval,
				nb_round_nonces: j.nb_round_nonces,
				vtxo_exit_delta: j.vtxo_exit_delta,
				vtxo_expiry_delta: j.vtxo_expiry_delta,
				htlc_send_expiry_delta: j.htlc_send_expiry_delta,
				htlc_expiry_delta: j.htlc_expiry_delta,
				max_vtxo_amount: j.max_vtxo_amount,
				required_board_confirmations: j.required_board_confirmations,
				max_user_invoice_cltv_delta: j.max_user_invoice_cltv_delta,
				min_board_amount: j.min_board_amount,
				offboard_feerate: FeeRate::from_sat_per_kwu(j.offboard_feerate_sat_per_kvb / 4),
				ln_receive_anti_dos_required: j.ln_receive_anti_dos_required,
				fees: j.fees.into(),
			}
		}
	}
}

