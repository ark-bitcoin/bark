pub mod fees;
#[cfg(feature = "onchain-bdk")]
pub mod onchain;

use std::borrow::Borrow;
use std::time::Duration;

use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{Amount, Txid};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use ark::VtxoId;
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::{AmountExt, BlockDelta};

use bark::actions::lightning::pay::{LightningSendState, Progress as SendProgress};
use bark::actions::lightning::receive::{
	LightningReceive, LightningReceiveState, Progress as ReceiveProgress,
};

use crate::cli::fees::FeeSchedule;
use crate::exit::error::ExitError;
use crate::exit::package::ExitTransactionPackage;
use crate::exit::{ExitState, ExitStateKind};
use crate::primitives::{TransactionInfo, VtxoStateInfo, WalletVtxoInfo};
use crate::serde_utils;

#[derive(Debug, Clone, Serialize)]
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
	#[cfg_attr(feature = "utoipa", schema(value_type = u16))]
	pub vtxo_exit_delta: BlockDelta,
	/// The number of blocks a VTXO lives before it expires
	#[serde(default)]
	#[cfg_attr(feature = "utoipa", schema(value_type = u16))]
	pub vtxo_lifetime: BlockDelta,
	/// The number of blocks after which an HTLC-send VTXO expires once granted.
	#[cfg_attr(feature = "utoipa", schema(value_type = u16))]
	pub htlc_send_expiry_delta: BlockDelta,
	/// The number of blocks to keep between Lightning and Ark HTLCs expiries
	#[cfg_attr(feature = "utoipa", schema(value_type = u16))]
	pub htlc_expiry_delta: BlockDelta,
	/// Maximum amount of a VTXO
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub max_vtxo_amount: Option<Amount>,
	/// The number of confirmations required to register a board vtxo
	pub required_board_confirmations: usize,
	/// Maximum CLTV delta server will allow clients to request an
	/// invoice generation with.
	#[cfg_attr(feature = "utoipa", schema(value_type = u16))]
	pub max_user_invoice_cltv_delta: BlockDelta,
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
	/// Maximum exit depth (genesis chain length) allowed for a VTXO.
	/// Once a VTXO's exit depth reaches this value the server will refuse to
	/// cosign further OOR transactions spending it. Clients should refresh
	/// their VTXOs into a round before this limit is reached.
	pub max_vtxo_exit_depth: u16,
	/// Link to the server's terms of service, if any.
	pub tos_link: Option<String>,
	/// The maximum number of inputs for an offboard
	pub max_offboard_inputs: usize,

	/// The number of blocks a VTXO lives before it expires.
	///
	/// **Deprecated**: renamed to `vtxo_lifetime`. This field is still
	/// populated with the same value for backwards compatibility and will
	/// be removed in a future release.
	#[deprecated(note = "renamed to `vtxo_lifetime`")]
	#[serde(default)]
	#[cfg_attr(feature = "utoipa", schema(required = true, value_type = u16))]
	pub vtxo_expiry_delta: BlockDelta,
}

impl<'de> serde::Deserialize<'de> for ArkInfo {
	#[allow(deprecated)]
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		#[derive(Deserialize)]
		struct ArkInfoStub {
			network: bitcoin::Network,
			server_pubkey: PublicKey,
			mailbox_pubkey: PublicKey,
			#[serde(with = "serde_utils::duration")]
			round_interval: Duration,
			nb_round_nonces: usize,
			vtxo_exit_delta: BlockDelta,
			#[serde(default)]
			vtxo_lifetime: BlockDelta,
			htlc_send_expiry_delta: BlockDelta,
			htlc_expiry_delta: BlockDelta,
			max_vtxo_amount: Option<Amount>,
			required_board_confirmations: usize,
			max_user_invoice_cltv_delta: BlockDelta,
			#[serde(rename = "min_board_amount_sat", with = "bitcoin::amount::serde::as_sat")]
			min_board_amount: Amount,
			offboard_feerate_sat_per_kvb: u64,
			ln_receive_anti_dos_required: bool,
			fees: FeeSchedule,
			max_vtxo_exit_depth: u16,
			tos_link: Option<String>,
			max_offboard_inputs: usize,
			#[serde(default)]
			vtxo_expiry_delta: BlockDelta,
		}

		let v = ArkInfoStub::deserialize(d)?;

		let vtxo_lifetime = match (v.vtxo_lifetime, v.vtxo_expiry_delta) {
			(BlockDelta::ZERO, expiry) => expiry,
			(lifetime, BlockDelta::ZERO) => lifetime,
			(lifetime, expiry) if lifetime == expiry => lifetime,
			(lifetime, expiry) => return Err(serde::de::Error::custom(format!(
				"vtxo_lifetime ({}) and vtxo_expiry_delta ({}) don't match", lifetime, expiry,
			))),
		};

		Ok(ArkInfo {
			network: v.network,
			server_pubkey: v.server_pubkey,
			mailbox_pubkey: v.mailbox_pubkey,
			round_interval: v.round_interval,
			nb_round_nonces: v.nb_round_nonces,
			vtxo_exit_delta: v.vtxo_exit_delta,
			vtxo_lifetime: vtxo_lifetime,
			vtxo_expiry_delta: vtxo_lifetime,
			htlc_send_expiry_delta: v.htlc_send_expiry_delta,
			htlc_expiry_delta: v.htlc_expiry_delta,
			max_vtxo_amount: v.max_vtxo_amount,
			required_board_confirmations: v.required_board_confirmations,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta,
			min_board_amount: v.min_board_amount,
			offboard_feerate_sat_per_kvb: v.offboard_feerate_sat_per_kvb,
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
			fees: v.fees,
			max_vtxo_exit_depth: v.max_vtxo_exit_depth,
			tos_link: v.tos_link,
			max_offboard_inputs: v.max_offboard_inputs,
		})
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct NextRoundStart {
	/// The next round start time in RFC 3339 format
	pub start_time: chrono::DateTime<chrono::Local>,
}

impl<T: Borrow<ark::ArkInfo>> From<T> for ArkInfo {
	#[allow(deprecated)] // vtxo_expiry_delta and offboard_feerate kept for old clients
	fn from(v: T) -> Self {
		let v = v.borrow();
	    ArkInfo {
			network: v.network,
			server_pubkey: v.server_pubkey,
			mailbox_pubkey: v.mailbox_pubkey,
			round_interval: v.round_interval,
			nb_round_nonces: v.nb_round_nonces,
			vtxo_exit_delta: v.vtxo_exit_delta,
			vtxo_lifetime: v.vtxo_lifetime,
			// we serve the deprecated field from the new one so that it
			// can never go stale for old clients
			vtxo_expiry_delta: v.vtxo_lifetime,
			htlc_send_expiry_delta: v.htlc_send_expiry_delta,
			htlc_expiry_delta: v.htlc_expiry_delta,
			max_vtxo_amount: v.max_vtxo_amount,
			required_board_confirmations: v.required_board_confirmations,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta,
			min_board_amount: v.min_board_amount,
			offboard_feerate_sat_per_kvb: v.offboard_feerate.to_sat_per_kwu() * 4,
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
			fees: v.fees.clone().into(),
			max_vtxo_exit_depth: v.max_vtxo_exit_depth,
			max_offboard_inputs: v.max_offboard_inputs,
			tos_link: v.tos_link.clone(),
		}
	}
}

/// A signature over a message
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SignedMessage {
	/// The BIP-340 Schnorr signature over the message digest
	/// `SHA256("bark/message" || message)`
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub signature: schnorr::Signature,
}

/// The result of verifying a signed message
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct MessageVerification {
	/// Whether the signature is valid for the given message and key
	pub valid: bool,
}

/// Wallet information that helps to debug issues.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct DebugInfo {
	/// The bitcoin network the wallet operates on
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub network: bitcoin::Network,
	/// The ID of the wallet's server mailbox
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub mailbox_id: PublicKey,
	/// The xpub from which all VTXO keypairs are derived
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub vtxo_xpub: bitcoin::bip32::Xpub,
}

/// The different balances of a Bark wallet.
///
/// `spendable_sat` counts the spendable VTXOs, `needs_refresh_sat` the ones
/// that have to be refreshed before they can be sent again, and every other
/// field what an operation in progress holds, so the fields never overlap.
///
/// See [BalanceSummary] for the totals to show a user.
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
	/// Sats in VTXOs that can no longer be sent in an arkoor payment because
	/// they have expired or their exit depth has reached the server's limit.
	/// They can still be offboarded, exited or refreshed, but are not part of
	/// `spendable_sat` until maintenance has refreshed them.
	#[serde(default, rename = "needs_refresh_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, required))]
	pub needs_refresh: Amount,
	/// Sats locked in an outgoing Lightning payment that has not yet
	/// settled.
	#[serde(rename = "pending_lightning_send_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending_lightning_send: Amount,
	/// Sats in HTLC VTXOs of an incoming Lightning payment whose preimage has
	/// been revealed but which have not been swapped for spendable VTXOs yet.
	/// A payment that can still be cancelled is not counted.
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
	/// Sats locked in an outgoing arkoor payment that has not completed yet:
	/// the whole input amount, until the send finalizes and the change comes
	/// back as spendable.
	#[serde(default, rename = "pending_arkoor_send_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, required))]
	pub pending_arkoor_send: Amount,
	/// Sats locked in an offboard whose transaction has not been broadcast
	/// yet, including any change that comes back. Once the transaction is on
	/// the network the sats belong to the on-chain wallet.
	#[serde(default, rename = "pending_offboard_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, required))]
	pub pending_offboard: Amount,
	/// Sats held in VTXOs whose unilateral exit has committed on-chain but which
	/// haven't yet been drained to the onchain wallet: their state is
	/// [`VtxoStateInfo::Exited`] and their exit has not reached
	/// [`ExitStateKind::Claimed`].
	#[serde(default, rename = "pending_exit_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64, required))]
	pub pending_exit: Amount,
}

impl From<bark::DebugInfo> for DebugInfo {
	fn from(v: bark::DebugInfo) -> Self {
		DebugInfo {
			network: v.network,
			mailbox_id: v.mailbox_id.as_pubkey(),
			vtxo_xpub: v.vtxo_xpub,
		}
	}
}

impl From<bark::Balance> for Balance {
	fn from(v: bark::Balance) -> Self {
		Balance {
			spendable: v.spendable,
			needs_refresh: v.needs_refresh,
			pending_in_round: v.pending_in_round,
			pending_lightning_send: v.pending_lightning_send,
			claimable_lightning_receive: v.claimable_lightning_receive,
			pending_exit: v.pending_exit,
			pending_board: v.pending_board,
			pending_arkoor_send: v.pending_arkoor_send,
			pending_offboard: v.pending_offboard,
		}
	}
}

/// The wallet balance without the breakdown of [Balance]: what a user can pay
/// with, what is held by operations in progress and what the user owns.
/// Build it from a [Balance].
///
/// All amounts are in sats.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BalanceSummary {
	/// Sats that can be spent right now. See `spendable_sat` of [Balance].
	#[serde(rename = "spendable_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub spendable: Amount,
	/// Sats that need a refresh before they can be sent again. See
	/// `needs_refresh_sat` of [Balance].
	#[serde(rename = "needs_refresh_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub needs_refresh: Amount,
	/// Sats held by operations in progress: the sum of the `pending_*_sat`
	/// fields of [Balance]. They either come back as spendable or leave the
	/// wallet, for example to the on-chain wallet.
	#[serde(rename = "pending_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub pending: Amount,
	/// All sats that belong to the wallet: `spendable_sat + needs_refresh_sat + pending_sat`.
	#[serde(rename = "total_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub total: Amount,
}

impl From<&Balance> for BalanceSummary {
	fn from(v: &Balance) -> Self {
		let pending = v.pending_in_round
			+ v.pending_board
			+ v.pending_arkoor_send
			+ v.pending_lightning_send
			+ v.claimable_lightning_receive
			+ v.pending_offboard
			+ v.pending_exit;
		BalanceSummary {
			spendable: v.spendable,
			needs_refresh: v.needs_refresh,
			pending,
			total: v.spendable + v.needs_refresh + pending,
		}
	}
}

impl From<Balance> for BalanceSummary {
	fn from(v: Balance) -> Self {
		BalanceSummary::from(&v)
	}
}

impl From<bark::BalanceSummary> for BalanceSummary {
	fn from(v: bark::BalanceSummary) -> Self {
		BalanceSummary {
			spendable: v.spendable,
			needs_refresh: v.needs_refresh,
			pending: v.pending,
			total: v.total,
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
	/// Top-level error that prevented progress from running cleanly this round. Per-exit
	/// problems live on each `ExitProgressStatus`; this slot is for failures that can't
	/// be attributed to a specific VTXO (e.g. the chain source becoming unavailable, or
	/// the exit manager failing to refresh its view of pending transactions).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<ExitError>,
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
	/// The payment hash linked to the lightning receive
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// Lifecycle phase of the receive: `awaiting-payment`, `htlcs-ready`,
	/// `preimage-revealed`, `delivering`, or `settled`.
	pub state: String,
	/// The invoice string, if known.
	pub invoice: String,
	/// The payment preimage, if known.
	#[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
	pub payment_preimage: Option<Preimage>,
	/// The amount of the lightning receive, if known.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	/// IDs of the HTLC-recv VTXOs granted by the server, if any.
	///
	/// Empty until the inbound HTLC has been received and prepared.
	#[serde(default, deserialize_with = "serde_utils::null_as_default")]
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>, required = true))]
	pub htlc_vtxo_ids: Vec<VtxoId>,
	/// The timestamp at which the receive settled, if it has.
	pub settled_at: Option<chrono::DateTime<chrono::Local>>,

	/// The timestamp at which the preimage was revealed.
	#[deprecated(note = "no longer tracked; use `state` and `settled_at`")]
	#[serde(default)]
	pub preimage_revealed_at: Option<chrono::DateTime<chrono::Local>>,
	/// The timestamp at which the lightning receive was finished.
	#[deprecated(note = "renamed to `settled_at`")]
	#[serde(default)]
	pub finished_at: Option<chrono::DateTime<chrono::Local>>,
	/// The HTLC VTXOs granted by the server for the lightning receive.
	#[deprecated(note = "replaced by `htlc_vtxo_ids`")]
	#[serde(default, deserialize_with = "serde_utils::null_as_default")]
	#[cfg_attr(feature = "utoipa", schema(required = true))]
	pub htlc_vtxos: Vec<WalletVtxoInfo>,
}

impl LightningReceiveInfo {
	/// Render a triaged receive state, mirroring the send-side status.
	#[allow(deprecated)] // populates deprecated compat fields kept for old clients
	pub fn from_state(state: &LightningReceiveState) -> Self {
		match state {
			LightningReceiveState::InProgress(recv) => LightningReceiveInfo::from(recv),
			LightningReceiveState::Settled(s) => LightningReceiveInfo {
				payment_hash: s.payment_hash,
				state: "settled".to_string(),
				invoice: s.invoice.to_string(),
				payment_preimage: Some(s.preimage),
				amount: s.amount,
				htlc_vtxo_ids: vec![],
				settled_at: Some(s.settled_at),
				preimage_revealed_at: None,
				finished_at: Some(s.settled_at),
				htlc_vtxos: vec![],
			},
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningSendInfo {
	/// The payment hash of the outgoing lightning payment
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// Lifecycle phase of the send: `unknown`, `start`, `htlc-received`,
	/// `payment-initiated`, `revocable-htlcs`, `revocation-stuck`, or `paid`.
	pub state: String,
	/// The invoice string, if known.
	pub invoice: Option<String>,
	/// The payment preimage, revealed once the payment succeeded.
	#[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
	pub preimage: Option<Preimage>,
}

impl LightningSendInfo {
	/// Render a triaged send state, mirroring the receive-side status.
	pub fn from_state(hash: PaymentHash, state: &LightningSendState) -> Self {
		match state {
			LightningSendState::Unknown => LightningSendInfo {
				payment_hash: hash,
				state: "unknown".to_string(),
				invoice: None,
				preimage: None,
			},
			LightningSendState::Paid(paid) => LightningSendInfo {
				payment_hash: paid.payment_hash,
				state: "paid".to_string(),
				invoice: None,
				preimage: Some(paid.preimage),
			},
			LightningSendState::InProgress(send) => {
				let phase = match send.progress {
					SendProgress::Start => "start",
					SendProgress::HtlcReceived(_) => "htlc-received",
					SendProgress::PaymentInitiated(_) => "payment-initiated",
					SendProgress::RevocableHtlcs { .. } => "revocable-htlcs",
					SendProgress::RevocationStuck { .. } => "revocation-stuck",
				};
				LightningSendInfo {
					payment_hash: send.invoice.payment_hash(),
					state: phase.to_string(),
					invoice: Some(send.invoice.to_string()),
					preimage: None,
				}
			},
		}
	}
}

impl From<&LightningReceive> for LightningReceiveInfo {
	#[allow(deprecated)] // populates deprecated compat fields kept for old clients
	fn from(recv: &LightningReceive) -> Self {
		let (state, htlc_vtxo_ids) = match &recv.progress {
			ReceiveProgress::AwaitingPayment => ("awaiting-payment", vec![]),
			ReceiveProgress::HtlcsReady(htlcs) => ("htlcs-ready", htlcs.vtxo_ids.clone()),
			ReceiveProgress::PreimageRevealed(htlcs) => ("preimage-revealed", htlcs.vtxo_ids.clone()),
			// The HTLCs are spent once the claim outputs await delivery.
			ReceiveProgress::Delivering(_) => ("delivering", vec![]),
		};
		LightningReceiveInfo {
			payment_hash: recv.payment_hash,
			state: state.to_string(),
			invoice: recv.invoice.to_string(),
			payment_preimage: Some(recv.payment_preimage),
			amount: recv.invoice.amount_milli_satoshis()
				.map(Amount::from_msat_floor)
				.expect("generated invoice with no amount"),
			htlc_vtxo_ids,
			settled_at: None,
			preimage_revealed_at: None,
			finished_at: None,
			htlc_vtxos: vec![],
		}
	}
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
			"state": "awaiting-payment",
			"settled_at": null,
			"invoice": "lnbc1",
		})
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxo_ids_missing() {
		let json = lightning_receive_base_json();
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxo_ids_null() {
		let mut json = lightning_receive_base_json();
		json["htlc_vtxo_ids"] = serde_json::json!(null);
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[test]
	fn deserialize_lightning_receive_htlc_vtxo_ids_empty() {
		let mut json = lightning_receive_base_json();
		json["htlc_vtxo_ids"] = serde_json::json!([]);
		serde_json::from_value::<LightningReceiveInfo>(json).unwrap();
	}

	#[allow(deprecated)]
	fn ark_info_base() -> ArkInfo {
		let pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
			.parse::<PublicKey>().unwrap();
		ArkInfo {
			network: bitcoin::Network::Regtest,
			server_pubkey: pubkey,
			mailbox_pubkey: pubkey,
			round_interval: Duration::from_secs(60),
			nb_round_nonces: 1,
			vtxo_exit_delta: BlockDelta::new(12),
			vtxo_lifetime: BlockDelta::new(100),
			vtxo_expiry_delta: BlockDelta::new(100),
			htlc_send_expiry_delta: BlockDelta::new(100),
			htlc_expiry_delta: BlockDelta::new(6),
			max_vtxo_amount: None,
			required_board_confirmations: 3,
			max_user_invoice_cltv_delta: BlockDelta::new(100),
			min_board_amount: Amount::from_sat(1000),
			offboard_feerate_sat_per_kvb: 1000,
			ln_receive_anti_dos_required: false,
			fees: ark::fees::FeeSchedule::default().into(),
			max_vtxo_exit_depth: 10,
			tos_link: None,
			max_offboard_inputs: 4,
		}
	}

	#[test]
	#[allow(deprecated)]
	fn ark_info_vtxo_lifetime_falls_back_to_deprecated_field() {
		// Servers from before the rename only set vtxo_expiry_delta.
		let mut json = serde_json::to_value(ark_info_base()).unwrap();
		json.as_object_mut().unwrap().remove("vtxo_lifetime");
		json["vtxo_expiry_delta"] = serde_json::json!(42);

		let info = serde_json::from_value::<ArkInfo>(json).unwrap();
		assert_eq!(info.vtxo_lifetime, BlockDelta::new(42));
		assert_eq!(info.vtxo_expiry_delta, BlockDelta::new(42));
	}

	#[test]
	#[allow(deprecated)]
	fn ark_info_vtxo_lifetime_kept_in_sync() {
		let mut json = serde_json::to_value(ark_info_base()).unwrap();
		json["vtxo_lifetime"] = serde_json::json!(42);
		json["vtxo_expiry_delta"] = serde_json::json!(42);

		let info = serde_json::from_value::<ArkInfo>(json).unwrap();
		assert_eq!(info.vtxo_lifetime, BlockDelta::new(42));
		assert_eq!(info.vtxo_expiry_delta, BlockDelta::new(42));

		// and both fields are populated again on the way out
		let json = serde_json::to_value(&info).unwrap();
		assert_eq!(json["vtxo_lifetime"], 42);
		assert_eq!(json["vtxo_expiry_delta"], 42);
	}

	#[test]
	fn ark_info_vtxo_lifetime_rejects_diverging_fields() {
		let mut json = serde_json::to_value(ark_info_base()).unwrap();
		json["vtxo_lifetime"] = serde_json::json!(42);
		json["vtxo_expiry_delta"] = serde_json::json!(100);

		assert!(serde_json::from_value::<ArkInfo>(json).is_err());
	}

	#[test]
	fn ark_info_fields() {
		//! the purpose of this test is to fail if we add a field to
		//! ark::ArkInfo but we forgot to add it to the ArkInfo here

		#[allow(unused, deprecated)]
		fn convert(j: ArkInfo) -> ark::ArkInfo {
			ark::ArkInfo {
				network: j.network,
				server_pubkey: j.server_pubkey,
				mailbox_pubkey: j.mailbox_pubkey,
				round_interval: j.round_interval,
				nb_round_nonces: j.nb_round_nonces,
				vtxo_exit_delta: j.vtxo_exit_delta,
				vtxo_lifetime: j.vtxo_lifetime,
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
				max_vtxo_exit_depth: j.max_vtxo_exit_depth,
				max_offboard_inputs: j.max_offboard_inputs,
				tos_link: j.tos_link,
			}
		}
	}
}

