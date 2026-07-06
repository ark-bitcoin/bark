//! State machine for outgoing offboards (offboard whole vtxos *and*
//! arkoor-prep-then-offboard for [`Wallet::send_onchain`]).
//!
//! Identity (`id`, `destination`, `fee_rate`, `kind`) and the parameters
//! fixed at the start (inputs, amounts) live on the action as top-level
//! fields; the mutable bit is [`Progress`], a small enum that names the
//! phases of the state machine and only carries the fields the phase
//! actually has.
//!
//! Both entry points share the same skeleton:
//! - [`start_offboard`] selects inputs and derives the offboard key (both
//!   for `SendOnchain` only), validates fee and dust constraints, and
//!   returns the action in [`Progress::Start`]; [`lock_vtxos`] then locks
//!   the inputs under the action id.
//! - For `SendOnchain` only, [`arkoor_split_offboard`] runs an arkoor to
//!   produce an exact-sized offboard vtxo plus change, which
//!   [`register_arkoor_split`] registers with the server.
//! - Both kinds converge in [`prepare_offboard`], which has the server
//!   build the offboard tx and validates it
//!   ([`Progress::OffboardTxPrepared`]), and [`finish_offboard`], which
//!   signs our forfeits and trades them for the signed offboard tx
//!   ([`Progress::ReadyForBroadcast`]).
//! - [`broadcast_offboard`] publishes the signed tx
//!   ([`Progress::AwaitingConfirmations`]).
//! - [`settle_offboard`] marks the vtxos spent and finalises the movement
//!   once the tx has enough confirmations.

use bitcoin::{Amount, FeeRate, Transaction, Txid};

use ark::{musig, VtxoId};

use crate::actions::WalletActionId;
use crate::movement::MovementId;

/// An outgoing offboard, persisted as a single checkpoint row and
/// driven across crashes by the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offboard {
	// Set at start, immutable thereafter:
	pub id: WalletActionId,
	pub destination: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain_output_amount: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub committed_fee: Amount,
	pub committed_fee_rate: FeeRate,
	pub kind: OffboardKind,

	// Mutable state:
	pub progress: Progress,
}

impl Offboard {
	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	pub fn check_destination(&self, network: bitcoin::Network) -> anyhow::Result<bitcoin::Address> {
		Ok(self.destination.clone().require_network(network)?)
	}
}

/// Which flavour of offboard this action drives.
///
/// `OffboardWhole` is reached from [`Wallet::offboard`] / [`Wallet::offboard_all`]
/// / [`Wallet::offboard_vtxos`]: the inputs are forfeited directly to
/// the offboard tx, fees come out of the gross amount.
///
/// `SendOnchain` is reached from [`Wallet::send_onchain`]: the user gives an
/// amount and the wallet must first arkoor-split its vtxos into an
/// exact-sized output (held by `offboard_pubkey`) plus change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffboardKind {
	/// Forfeit the listed vtxos as-is to the offboard tx.
	OffboardWhole {
		input_vtxo_ids: Vec<VtxoId>,
	},
	/// Run an arkoor first; offboard the resulting exact-sized vtxo.
	SendOnchain {
		input_vtxo_ids: Vec<VtxoId>,
		/// Holds the arkoor-output (offboard input) vtxo.
		arkoor_key_index: u32,
		/// Holds the arkoor change. Must differ from `arkoor_key_index`: the
		/// arkoor builder refuses a change output paying the destination.
		change_key_index: u32,
	},
}

impl OffboardKind {
	fn deduct_fees_from_gross_amount(&self) -> bool {
		match self {
			OffboardKind::OffboardWhole { .. } => true,
			OffboardKind::SendOnchain { .. } => false,
		}
	}

	fn vtxo_ids(&self) -> &Vec<VtxoId> {
		match self {
			OffboardKind::OffboardWhole { input_vtxo_ids } => input_vtxo_ids,
			OffboardKind::SendOnchain { input_vtxo_ids, .. } => input_vtxo_ids,
		}
	}
}

/// The phases of offboarding.
///
/// `SplitWithArkoor` and `ArkoorRegistrationRequired` are only reached from
/// the `SendOnchain` kind; the `OffboardWhole` kind transitions directly
/// from `Start` to `ReadyForOffboard`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Inputs need locking, but we have selected VTXOs to offboard.
	Start,
	/// `SendOnchain` intermediate: We need to perform an arkoor to split the VTXOs so we can
	/// offboard the exact amount requested.
	SplitWithArkoor,
	/// `SendOnchain` intermediate: arkoor done, yet to be registered with the server.
	ArkoorRegistrationRequired { offboard_vtxo_ids: Vec<VtxoId> },
	/// VTXOs are locked, (potential) split is done, now we can start the actual offboard.
	ReadyForOffboard {
		/// In the case of `SendOnchain` this is the arkoor VTXOs we just created, in the case
		/// of `OffboardWhole` this is the VTXOs we selected to offboard.
		offboard_vtxo_ids: Vec<VtxoId>,
	},
	/// Offboard tx built by the server and validated by us; our forfeits
	/// are not signed yet — that happens inside the finish step, with
	/// fresh nonces on every attempt, so that this checkpoint stays
	/// value-deterministic across re-drives.
	OffboardTxPrepared {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		/// The server's forfeit cosign nonces from the prepare response;
		/// stable across prepare replays.
		forfeit_cosign_nonces: Vec<musig::PublicNonce>,
		movement_id: MovementId,
	},
	ReadyForBroadcast {
		offboard_vtxo_ids: Vec<VtxoId>,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		signed_offboard_tx: Transaction,
		movement_id: MovementId,
	},
	/// Offboard tx broadcast; waiting for confirmation.
	AwaitingConfirmations {
		offboard_vtxo_ids: Vec<VtxoId>,
		offboard_txid: Txid,
		#[serde(with = "bitcoin_ext::serde::encodable")]
		offboard_tx: Transaction,
		movement_id: MovementId,
		created_at: chrono::DateTime<chrono::Utc>,
	},
}
