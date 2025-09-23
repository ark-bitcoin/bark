//! VTXO state tracking.
//!
//! This module defines the state machine used to track the lifecycle of each individual [Vtxo]
//! managed by the wallet. A [Vtxo] can be:
//! - created and ready to spend on Ark: [VtxoStateKind::Spendable]
//! - created but not yet acknowledged/registered by the server: [VtxoStateKind::UnregisteredBoard]
//! - consumed (no longer part of the wallet's balance): [VtxoStateKind::Spent]
//! - temporarily locked in an outgoing Lightning HTLC: [VtxoStateKind::PendingLightningSend]
//! - temporarily locked while waiting for an incoming Lightning HTLC to be claimed:
//!   [VtxoStateKind::PendingLightningRecv]
//!
//! Two layers of state are provided:
//! - [VtxoStateKind]: a compact, serialization-friendly discriminator intended for storage, logs,
//!   and wire formats. It maps to stable string identifiers via `as_str()`.
//! - [VtxoState]: a richer state that may include associated data needed at runtime (e.g.
//!   [Invoice], [Amount], or [PaymentHash]).
//!
//! [WalletVtxo] pairs a concrete [Vtxo] with its current [VtxoState], providing the primary
//! representation used by persistence and higher-level wallet logic.

use bitcoin::Amount;

use ark::Vtxo;
use ark::lightning::{Invoice, PaymentHash};

const SPENDABLE: &'static str = "Spendable";
const UNREGISTERED_BOARD : &'static str = "UnregisteredBoard";
const SPENT: &'static str = "Spent";
const PENDING_LIGHTNING_SEND: &'static str = "PendingLightningSend";
const PENDING_LIGHTNING_RECV: &'static str = "PendingLightningRecv";

/// A compact, serialization-friendly representation of a VTXO's state.
///
/// Use [VtxoState::as_kind] to derive it from a richer [VtxoState].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoStateKind {
	/// The [Vtxo] is available and can be selected as an input for a new offboard/round.
	Spendable,
	/// The [Vtxo] was produced by a board but is not yet registered/acknowledged by the server.
	UnregisteredBoard,
	/// The [Vtxo] has been consumed and is no longer part of the wallet's balance.
	Spent,
	/// The [Vtxo] is currently locked in an outgoing Lightning HTLC.
	PendingLightningSend,
	/// The [Vtxo] is currently locked for an incoming Lightning HTLC (awaiting claim).
	PendingLightningRecv,
}

impl VtxoStateKind {
	/// Returns a stable string identifier for this state, suitable for DB rows, logs, and APIs.
	pub fn as_str(&self) -> &str {
		match self {
			VtxoStateKind::UnregisteredBoard => UNREGISTERED_BOARD,
			VtxoStateKind::Spendable => SPENDABLE,
			VtxoStateKind::Spent => SPENT,
			VtxoStateKind::PendingLightningSend => PENDING_LIGHTNING_SEND,
			VtxoStateKind::PendingLightningRecv => PENDING_LIGHTNING_RECV,
		}
	}
}

/// Rich [Vtxo] state carrying additional context needed at runtime.
///
/// Use this when application logic needs to act on a [Vtxo]: e.g. to surface the
/// [Invoice] being paid, the amount committed to a Lightning payment, or the
/// payment hash for an expected incoming HTLC.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoState {
	/// The [Vtxo] is available and can be spent in a future round.
	Spendable,
	/// The [Vtxo] has been consumed.
	Spent,
	/// The [Vtxo] exists locally but is not yet registered/acknowledged by the server.
	UnregisteredBoard,
	/// The current [Vtxo] is locked in an outgoing Lightning HTLC pending settlement.
	///
	/// The associated data identifies the Lightning [Invoice] being paid and the
	/// amount reserved from this [Vtxo] for that payment. While in this state,
	/// the wallet should not use the [Vtxo] for other operations unless the HTLC
	/// is revoked or otherwise resolved.
	PendingLightningSend {
		invoice: Invoice,
		amount: Amount,
	},
	/// The current [Vtxo] is reserved for an incoming Lightning HTLC awaiting claim by the
	/// recipient.
	///
	/// The associated payment hash can be used to check the payment status and
	/// to finalize or revoke the HTLC as needed.
	PendingLightningRecv {
		payment_hash: PaymentHash,
	},
}

impl VtxoState {
	/// Returns the compact [VtxoStateKind] discriminator for this rich state.
	pub fn as_kind(&self) -> VtxoStateKind {
		match self {
			VtxoState::UnregisteredBoard => VtxoStateKind::UnregisteredBoard,
			VtxoState::Spendable => VtxoStateKind::Spendable,
			VtxoState::Spent => VtxoStateKind::Spent,
			VtxoState::PendingLightningSend { .. } => VtxoStateKind::PendingLightningSend,
			VtxoState::PendingLightningRecv { .. } => VtxoStateKind::PendingLightningRecv,
		}
	}

	/// If the [Vtxo] is [VtxoStateKind::PendingLightningSend], returns the `(invoice, amount)`
	/// currently reserved.
	/// Otherwise returns `None`.
	pub fn as_pending_lightning_send(&self) -> Option<(&Invoice, Amount)> {
		match self {
			VtxoState::PendingLightningSend { invoice, amount } => Some((invoice, *amount)),
			_ => None,
		}
	}
}

/// A wallet-owned [Vtxo] paired with its current tracked state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletVtxo {
	/// The underlying [Vtxo].
	pub vtxo: Vtxo,
	/// The current tracked state for [WalletVtxo::vtxo].
	pub state: VtxoState,
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn convert_serialize() {
		let states = [
			VtxoStateKind::Spendable,
			VtxoStateKind::Spent,
			VtxoStateKind::UnregisteredBoard,
			VtxoStateKind::PendingLightningSend,
			VtxoStateKind::PendingLightningRecv,
		];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, UNREGISTERED_BOARD, PENDING_LIGHTNING_SEND, PENDING_LIGHTNING_RECV]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::UnregisteredBoard => (),
			VtxoState::PendingLightningSend { .. } => (),
			VtxoState::PendingLightningRecv { .. } => (),
		}
	}
}
