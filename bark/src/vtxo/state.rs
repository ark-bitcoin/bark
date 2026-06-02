//! VTXO state tracking.
//!
//! This module defines the state machine used to track the lifecycle of each individual [Vtxo]
//! managed by the wallet. A [Vtxo] can be:
//! - created and ready to spend on Ark: [VtxoStateKind::Spendable]
//! - owned but not usable because it is locked by subsystem: [VtxoStateKind::Locked]
//! - consumed (no longer part of the wallet's balance): [VtxoStateKind::Spent]
//! - taken on-chain via a unilateral exit: [VtxoStateKind::Exited]. Distinct from
//!   [VtxoStateKind::Spent] so callers can tell whether a VTXO disappeared from the
//!   wallet because the user forfeited it (round, send) or because the user moved
//!   it onchain. The server refuses VTXOs once every exit transaction for a VTXO has
//!   been broadcast, even before the corresponding on-chain UTXO has been claimed, so
//!   the VTXO will enter [VtxoStateKind::Exited] as soon as we expect a VTXO to become
//!   unusable offchain.
//!
//! Two layers of state are provided:
//! - [VtxoStateKind]: a compact, serialization-friendly discriminator intended for storage, logs,
//!   and wire formats. It maps to stable string identifiers via `as_str()`.
//! - [VtxoState]: A richer state that might include metadata
//!
//! [WalletVtxo] pairs a concrete [Vtxo] with its current [VtxoState], providing the primary
//! representation used by persistence and higher-level wallet logic.

use std::fmt;
use std::ops::Deref;

use bitcoin::Weight;

use ark::Vtxo;
use ark::vtxo::{Bare, Full, VtxoRef};

use crate::actions::WalletActionId;
use crate::movement::MovementId;

/// What kind of entity holds a [VtxoState::Locked] reservation.
///
/// The wallet's invariant is "every vtxo lock is owned by exactly one
/// operation." For subsystems modelled as a [WalletAction] (today: the
/// lightning send), that's an `Action(id)`. For subsystems that still
/// run pre-action machinery (round, offboard, board, lightning receive)
/// the holder is the operation's movement, captured as
/// `Movement(MovementId)`. As those subsystems get converted to actions,
/// new variants land here and the migration from `Movement` happens
/// per-subsystem.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VtxoLockHolder {
	/// A [WalletAction] checkpointed in `bark_wallet_action_checkpoint`.
	Action { id: WalletActionId },
	/// A pre-action subsystem (round, offboard, board, lightning
	/// receive). The movement is used as a stable handle.
	Movement { id: MovementId },
}

impl From<MovementId> for VtxoLockHolder {
	fn from(id: MovementId) -> Self {
		VtxoLockHolder::Movement { id }
	}
}

const SPENDABLE: &'static str = "Spendable";
const LOCKED: &'static str = "Locked";
const SPENT: &'static str = "Spent";
const EXITED: &'static str = "Exited";

/// A compact, serialization-friendly representation of a VTXO's state.
///
/// Use [VtxoState::kind] to derive it from a richer [VtxoState].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VtxoStateKind {
	/// The [Vtxo] is available and can be selected as an input for a new offboard/round.
	Spendable,
	/// The [Vtxo] is currently locked in an action.
	Locked,
	/// The [Vtxo] has been consumed and is no longer part of the wallet's balance.
	Spent,
	/// The [Vtxo] has been moved on-chain via a unilateral exit. Like
	/// [VtxoStateKind::Spent], an `Exited` vtxo is no longer part of the wallet's balance
	/// and the server will refuse to interact with it; unlike `Spent`, the disappearance
	/// is the result of the user taking the funds onchain rather than forfeiting them in
	/// the protocol.
	Exited,
}

impl VtxoStateKind {
	/// Returns a stable string identifier for this state, suitable for DB rows, logs, and APIs.
	pub fn as_str(&self) -> &str {
		match self {
			VtxoStateKind::Spendable => SPENDABLE,
			VtxoStateKind::Locked => LOCKED,
			VtxoStateKind::Spent => SPENT,
			VtxoStateKind::Exited => EXITED,
		}
	}

	pub fn as_byte(&self) -> u8 {
		match self {
			VtxoStateKind::Spendable => 0,
			VtxoStateKind::Locked { .. } => 1,
			VtxoStateKind::Spent => 2,
			VtxoStateKind::Exited => 3,
		}
	}

	/// List of all existing states
	pub const ALL: &[VtxoStateKind] = &[
		VtxoStateKind::Spendable,
		VtxoStateKind::Locked,
		VtxoStateKind::Spent,
		VtxoStateKind::Exited,
	];

	/// List of the different states considered unspent
	pub const UNSPENT_STATES: &[VtxoStateKind] = &[
		VtxoStateKind::Spendable,
		VtxoStateKind::Locked,
	];
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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum VtxoState {
	/// The [Vtxo] is available and can be spent in a future round.
	Spendable,
	/// The [Vtxo] is currently locked by an operation.
	///
	/// `holder` is `None` for the narrow window between creating a
	/// fresh locked vtxo and pinning it to a specific operation (e.g.
	/// during the offboard's preparatory arkoor). Production code
	/// should set the holder explicitly whenever it knows the owner.
	Locked {
		holder: Option<VtxoLockHolder>,
	},
	/// The [Vtxo] has been consumed.
	Spent,
	/// The [Vtxo] is in (or has completed) a unilateral exit. See
	/// [VtxoStateKind::Exited] for the distinction from [VtxoState::Spent].
	Exited,
}

impl VtxoState {
	/// Returns the compact [VtxoStateKind] discriminator for this rich state.
	pub fn kind(&self) -> VtxoStateKind {
		match self {
			VtxoState::Spendable => VtxoStateKind::Spendable,
			VtxoState::Locked { .. } => VtxoStateKind::Locked,
			VtxoState::Spent => VtxoStateKind::Spent,
			VtxoState::Exited => VtxoStateKind::Exited,
		}
	}
}

/// A wallet-owned [Vtxo] paired with its current tracked state and a small set of
/// genesis-derived summaries that the wallet would otherwise have to load the full
/// exit chain for.
///
/// The wallet stores [Vtxo<Full>] on disk but listings, balance computations, coin
/// selection, and refresh-strategy checks all run against this bare representation
/// to avoid the per-VTXO memory cost (tens of KB at high exit depths). When an
/// operation actually needs the exit chain — unilateral exit, server registration,
/// arkoor send, offboard, counterparty-risk checks — call
/// [crate::Wallet::get_full_vtxo] or
/// [crate::persist::BarkPersister::get_full_vtxos] to fetch it from disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletVtxo {
	/// The underlying [Vtxo] without its genesis chain.
	#[serde(with = "ark::encode::serde")]
	pub vtxo: Vtxo<Bare>,

	/// The current tracked state for [`WalletVtxo`].
	pub state: VtxoState,

	/// Cached `vtxo.exit_depth()` from when the VTXO was inserted into the
	/// wallet. Genesis is immutable post-creation, so this never drifts.
	pub exit_depth: u16,

	/// Cached sum of weight units for the unilateral exit transaction chain.
	///
	/// Lets the refresh strategy answer "uneconomical to exit" without loading the genesis.
	pub exit_tx_weight: Weight,
}

impl VtxoRef for WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn as_bare_vtxo(&self) -> Option<std::borrow::Cow<'_, Vtxo<Bare>>> {
		Some(std::borrow::Cow::Borrowed(&self.vtxo))
	}
	fn as_full_vtxo(&self) -> Option<&Vtxo<Full>> { None }
	fn into_full_vtxo(self) -> Option<Vtxo<Full>> { None }
}

impl<'a> VtxoRef for &'a WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn as_bare_vtxo(&self) -> Option<std::borrow::Cow<'_, Vtxo<Bare>>> {
		Some(std::borrow::Cow::Borrowed(&self.vtxo))
	}
	fn as_full_vtxo(&self) -> Option<&Vtxo<Full>> { None }
	fn into_full_vtxo(self) -> Option<Vtxo<Full>> { None }
}

impl AsRef<Vtxo<Bare>> for WalletVtxo {
	fn as_ref(&self) -> &Vtxo<Bare> {
		&self.vtxo
	}
}

impl Deref for WalletVtxo {
	type Target = Vtxo<Bare>;

	fn deref(&self) -> &Vtxo<Bare> {
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
			VtxoStateKind::Exited,
		];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, LOCKED, EXITED]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::Locked { .. } => {},
			VtxoState::Exited => {},
		}
	}
}
