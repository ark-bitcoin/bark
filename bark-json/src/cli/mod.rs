#[cfg(feature = "onchain_bdk")]
pub mod onchain;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, Txid, SignedAmount, ScriptBuf};
use chrono::DateTime;
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use ark::VtxoId;
use ark::lightning::{Invoice, Offer, PaymentHash, Preimage};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::movement::MovementId;
use bitcoin_ext::{AmountExt, BlockDelta};

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
	/// fixed number of vb charged additinally for an offboard
	/// this is charged after being multiplied with the offboard feerate
	pub offboard_fixed_fee_vb: u64,
	/// Indicates whether the Ark server requires clients to either
	/// provide a VTXO ownership proof, or a lightning receive token
	/// when preparing a lightning claim.
	pub ln_receive_anti_dos_required: bool,
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
			offboard_fixed_fee_vb: v.offboard_fixed_fee_vb,
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
		}
	}
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
	#[serde(rename = "claimable_lightning_receive_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub claimable_lightning_receive: Amount,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum MovementStatus {
	/// The default status of a new [Movement]. Should be treated as in-progress.
	Pending,
	/// The [Movement] has completed successfully.
	Successful,
	/// The [Movement] failed to complete due to an error. Note; this does not mean that VTXOs or
	/// user funds didn't change, old VTXOs may be consumed and new ones produced.
	Failed,
	/// A [Movement] was canceled, either by the protocol (e.g., lightning payments) or by the
	/// user.
	Canceled,
}

impl From<bark::movement::MovementStatus> for MovementStatus {
	fn from(v: bark::movement::MovementStatus) -> Self {
		match v {
			bark::movement::MovementStatus::Pending => Self::Pending,
			bark::movement::MovementStatus::Successful => Self::Successful,
			bark::movement::MovementStatus::Failed => Self::Failed,
			bark::movement::MovementStatus::Canceled => Self::Canceled,
		}
	}
}

/// Describes an attempted movement of offchain funds within the [bark::Wallet].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Movement {
	/// The internal ID of the movement.
	#[cfg_attr(feature = "utoipa", schema(value_type = u32))]
	pub id: MovementId,
	/// The status of the movement.
	pub status: MovementStatus,
	/// Contains information about the subsystem that created the movement as well as the purpose
	/// of the movement.
	pub subsystem: MovementSubsystem,
	/// Miscellaneous metadata for the movement. This is JSON containing arbitrary information as
	/// defined by the subsystem that created the movement.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub metadata: Option<HashMap<String, serde_json::Value>>,
	/// How much the movement was expected to increase or decrease the balance by. This is always an
	/// estimate and often discounts any applicable fees.
	#[serde(rename="intended_balance_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = i64))]
	pub intended_balance: SignedAmount,
	/// How much the wallet balance actually changed by. Positive numbers indicate an increase and
	/// negative numbers indicate a decrease. This is often inclusive of applicable fees, and it
	/// should be the most accurate number.
	#[serde(rename="effective_balance_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = i64))]
	pub effective_balance: SignedAmount,
	/// How much the movement cost the user in offchain fees. If there are applicable onchain fees
	/// they will not be included in this value but, depending on the subsystem, could be found in
	/// the metadata.
	#[serde(rename="offchain_fee_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub offchain_fee: Amount,
	/// A list of external recipients that received funds from this movement.
	pub sent_to: Vec<MovementDestination>,
	/// Describes the means by which the wallet received funds in this movement. This could include
	/// BOLT11 invoices or other useful data.
	pub received_on: Vec<MovementDestination>,
	/// A list of [Vtxo](ark::Vtxo) IDs that were consumed by this movement and
	/// are either locked or unavailable.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub input_vtxos: Vec<VtxoId>,
	/// A list of IDs for new VTXOs that were produced as a result of this movement. Often change
	/// VTXOs will be found here for outbound actions unless this was an inbound action.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub output_vtxos: Vec<VtxoId>,
	/// A list of IDs for VTXOs that were marked for unilateral exit as a result of this movement.
	/// This could happen for many reasons, e.g. an unsuccessful lightning payment which can't be
	/// revoked but is about to expire. VTXOs listed here will result in a reduction of spendable
	/// balance due to the VTXOs being managed by the [bark::exit::Exit] system.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub exited_vtxos: Vec<VtxoId>,
	/// Contains the times at which the movement was created, updated and completed.
	pub time: MovementTimestamp,
}

impl From<bark::movement::Movement> for Movement {
	fn from(m: bark::movement::Movement) -> Self {
		Movement {
			id: m.id,
			status: m.status.into(),
			subsystem: MovementSubsystem::from(m.subsystem),
			metadata: if m.metadata.is_empty() { None } else { Some(m.metadata) },
			intended_balance: m.intended_balance,
			effective_balance: m.effective_balance,
			offchain_fee: m.offchain_fee,
			sent_to: m.sent_to.into_iter().map(MovementDestination::from).collect(),
			received_on: m.received_on.into_iter().map(MovementDestination::from).collect(),
			input_vtxos: m.input_vtxos,
			output_vtxos: m.output_vtxos,
			exited_vtxos: m.exited_vtxos,
			time: MovementTimestamp::from(m.time),
		}
	}
}

/// Describes a recipient of a movement. This could either be an external recipient in send actions
/// or it could be the bark wallet itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct MovementDestination {
	/// An address, invoice or any other identifier to distinguish the recipient.
	pub destination: PaymentMethod,
	/// How many sats the recipient received.
	#[serde(rename="amount_sat", with="bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
}

impl From<bark::movement::MovementDestination> for MovementDestination {
	fn from(d: bark::movement::MovementDestination) -> Self {
		MovementDestination {
			destination: PaymentMethod::from(d.destination),
			amount: d.amount,
		}
	}
}

/// Provides a typed mechanism for describing the recipient in a [MovementDestination].
/// This is a bark-json wrapper that serializes all payment methods as strings for utoipa
/// compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum PaymentMethod {
	/// An [ark::Address] format for bark.
	Ark(String),
	/// An onchain [bitcoin::Address].
	Bitcoin(String),
	/// An onchain [bitcoin::ScriptBuf] output, typically used for non-address formats like
	/// OP_RETURN.
	OutputScript(String),
	/// Any supported form of lightning invoice, e.g., BOLT11 and BOLT12.
	Invoice(String),
	/// A reusable BOLT12 offer for making lightning payments.
	Offer(String),
	/// A variant using an email-like lightning address format.
	LightningAddress(String),
	/// An alternative payment method that isn't native to bark.
	Custom(String),
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PaymentMethod {
	fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
		use utoipa::openapi::schema;

		schema::ObjectBuilder::new()
			.title(Some("PaymentMethod"))
			.description(Some("A payment method with a type discriminator and string value"))
			.property(
				"type",
				schema::ObjectBuilder::new()
					.schema_type(schema::SchemaType::Type(schema::Type::String))
					.enum_values(Some([
						"ark",
						"bitcoin",
						"output-script",
						"invoice",
						"offer",
						"lightning-address",
						"custom",
					]))
					.description(Some("The type of payment method"))
			)
			.required("type")
			.property(
				"value",
				schema::ObjectBuilder::new()
					.schema_type(schema::SchemaType::Type(schema::Type::String))
					.description(Some("The payment method value (address, invoice, etc.)"))
			)
			.required("value")
			.into()
	}
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PaymentMethod {
	fn name() -> std::borrow::Cow<'static, str> {
		std::borrow::Cow::Borrowed("PaymentMethod")
	}
}

impl From<bark::movement::PaymentMethod> for PaymentMethod {
	fn from(p: bark::movement::PaymentMethod) -> Self {
		match p {
			bark::movement::PaymentMethod::Ark(a) => Self::Ark(a.to_string()),
			bark::movement::PaymentMethod::Bitcoin(b) => Self::Bitcoin(b.assume_checked().to_string()),
			bark::movement::PaymentMethod::OutputScript(s) => Self::OutputScript(s.to_hex_string()),
			bark::movement::PaymentMethod::Invoice(i) => Self::Invoice(i.to_string()),
			bark::movement::PaymentMethod::Offer(o) => Self::Offer(o.to_string()),
			bark::movement::PaymentMethod::LightningAddress(l) => Self::LightningAddress(l.to_string()),
			bark::movement::PaymentMethod::Custom(c) => Self::Custom(c),
		}
	}
}

impl TryFrom<PaymentMethod> for bark::movement::PaymentMethod {
	type Error = anyhow::Error;

	fn try_from(p: PaymentMethod) -> Result<Self, Self::Error> {
		match p {
			PaymentMethod::Ark(a) => Ok(bark::movement::PaymentMethod::Ark(
				ark::Address::from_str(&a)?,
			)),
			PaymentMethod::Bitcoin(b) => Ok(bark::movement::PaymentMethod::Bitcoin(
				bitcoin::Address::from_str(&b)?,
			)),
			PaymentMethod::OutputScript(s) => Ok(bark::movement::PaymentMethod::OutputScript(
				ScriptBuf::from_hex(&s)?,
			)),
			PaymentMethod::Invoice(i) => Ok(bark::movement::PaymentMethod::Invoice(
				Invoice::from_str(&i)?,
			)),
			PaymentMethod::Offer(o) => Ok(bark::movement::PaymentMethod::Offer(
				Offer::from_str(&o).map_err(|e| anyhow!("Failed to parse offer: {:?}", e))?,
			)),
			PaymentMethod::LightningAddress(l) => Ok(bark::movement::PaymentMethod::LightningAddress(
				LightningAddress::from_str(&l)?,
			)),
			PaymentMethod::Custom(c) => Ok(bark::movement::PaymentMethod::Custom(c)),
		}
	}
}

/// Contains information about the subsystem that created the movement as well as the purpose
/// of the movement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct MovementSubsystem {
	/// The name of the subsystem that created and manages the movement.
	pub name: String,
	/// The action responsible for registering the movement.
	pub kind: String,
}

impl From<bark::movement::MovementSubsystem> for MovementSubsystem {
	fn from(s: bark::movement::MovementSubsystem) -> Self {
		MovementSubsystem {
			name: s.name,
			kind: s.kind,
		}
	}
}

/// Contains the times at which the movement was created, updated and completed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct MovementTimestamp {
	/// When the movement was first created.
	pub created_at: DateTime<chrono::Local>,
	/// When the movement was last updated.
	pub updated_at: DateTime<chrono::Local>,
	/// The action responsible for registering the movement.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub completed_at: Option<DateTime<chrono::Local>>,
}

impl From<bark::movement::MovementTimestamp> for MovementTimestamp {
	fn from(t: bark::movement::MovementTimestamp) -> Self {
		MovementTimestamp {
			created_at: t.created_at,
			updated_at: t.updated_at,
			completed_at: t.completed_at,
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
pub struct InvoiceInfo {
	/// The invoice string
	pub invoice: String,
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
	/// Only present if the lightning HTLC has been received by the server.
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<WalletVtxoInfo>, nullable = true))]
	pub htlc_vtxos: Option<Vec<WalletVtxoInfo>>,
}

impl From<bark::persist::models::LightningReceive> for LightningReceiveInfo {
	fn from(v: bark::persist::models::LightningReceive) -> Self {
		LightningReceiveInfo {
			payment_hash: v.payment_hash,
			payment_preimage: v.payment_preimage,
			preimage_revealed_at: v.preimage_revealed_at,
			invoice: v.invoice.to_string(),
			htlc_vtxos: v.htlc_vtxos.map(|vtxos| vtxos.into_iter()
				.map(crate::primitives::WalletVtxoInfo::from).collect()),
			amount: v.invoice.amount_milli_satoshis().map(Amount::from_msat_floor)
				.unwrap_or(Amount::ZERO),
			finished_at: v.finished_at,
		}
	}
}

#[cfg(test)]
mod test {
	use bitcoin::FeeRate;
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
				offboard_fixed_fee_vb: j.offboard_fixed_fee_vb,
				ln_receive_anti_dos_required: j.ln_receive_anti_dos_required,
			}
		}
	}
}

