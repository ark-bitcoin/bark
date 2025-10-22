//! VTXO state tracking.
//!
//! This module defines the state machine used to track the lifecycle of each individual [Vtxo]
//! managed by the wallet. A [Vtxo] can be:
//! - created and ready to spend on Ark: [VtxoStateKind::Spendable]
//! - owned but not usable because it is locked by subsystem: [VtxoStateKind::Locked]
//! - consumed (no longer part of the wallet's balance): [VtxoStateKind::Spent]
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

use std::fmt;
use std::ops::Deref;

use ark::vtxo::VtxoRef;

use ark::Vtxo;
use ark::lightning::PaymentHash;

const SPENDABLE: &'static str = "Spendable";
const LOCKED: &'static str = "Locked";
const SPENT: &'static str = "Spent";
const PENDING_LIGHTNING_RECV: &'static str = "PendingLightningRecv";

/// A compact, serialization-friendly representation of a VTXO's state.
///
/// Use [VtxoState::as_kind] to derive it from a richer [VtxoState].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoStateKind {
	/// The [Vtxo] is available and can be selected as an input for a new offboard/round.
	Spendable,
	/// The [Vtxo] is currently locked in an action.
	Locked,
	/// The [Vtxo] has been consumed and is no longer part of the wallet's balance.
	Spent,
	/// The [Vtxo] is currently locked for an incoming Lightning HTLC (awaiting claim).
	PendingLightningRecv,
}

impl VtxoStateKind {
	/// Returns a stable string identifier for this state, suitable for DB rows, logs, and APIs.
	pub fn as_str(&self) -> &str {
		match self {
			VtxoStateKind::Spendable => SPENDABLE,
			VtxoStateKind::Locked => LOCKED,
			VtxoStateKind::Spent => SPENT,
			VtxoStateKind::PendingLightningRecv => PENDING_LIGHTNING_RECV,
		}
	}
}

impl fmt::Display for VtxoStateKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    f.write_str(self.as_str())
	}
}

impl fmt::Debug for VtxoStateKind {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    f.write_str(self.as_str())
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
	/// The [Vtxo] is currently locked in an action.
	Locked,
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
	pub fn kind(&self) -> VtxoStateKind {
		match self {
			VtxoState::Locked => VtxoStateKind::Locked,
			VtxoState::Spendable => VtxoStateKind::Spendable,
			VtxoState::Spent => VtxoStateKind::Spent,
			VtxoState::PendingLightningRecv { .. } => VtxoStateKind::PendingLightningRecv,
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

impl VtxoRef for WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn vtxo(&self) -> Option<&Vtxo> { Some(&self.vtxo) }
}

impl<'a> VtxoRef for &'a WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn vtxo(&self) -> Option<&Vtxo> { Some(&self.vtxo) }
}

impl Deref for WalletVtxo {
	type Target = Vtxo;

	fn deref(&self) -> &Vtxo {
		&self.vtxo
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn convert_serialize() {
		let states = [
			VtxoStateKind::Spendable,
			VtxoStateKind::Spent,
			VtxoStateKind::Locked,
			VtxoStateKind::PendingLightningRecv,
		];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, LOCKED, PENDING_LIGHTNING_RECV]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::Locked => {},
			VtxoState::PendingLightningRecv { .. } => (),
		}
	}
}
