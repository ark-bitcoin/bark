//! VTXO state tracking.
//!
//! This module defines the state machine used to track the lifecycle of each individual [Vtxo]
//! managed by the wallet. A [Vtxo] can be:
//! - created and ready to spend on Ark: [VtxoStateKind::Spendable]
//! - owned but not usable because it is locked by subsystem: [VtxoStateKind::Locked]
//! - consumed (no longer part of the wallet's balance): [VtxoStateKind::Spent]
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

use ark::Vtxo;
use ark::vtxo::{Bare, Full, VtxoRef};
use crate::movement::MovementId;

const SPENDABLE: &'static str = "Spendable";
const LOCKED: &'static str = "Locked";
const SPENT: &'static str = "Spent";

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
}

impl VtxoStateKind {
	/// Returns a stable string identifier for this state, suitable for DB rows, logs, and APIs.
	pub fn as_str(&self) -> &str {
		match self {
			VtxoStateKind::Spendable => SPENDABLE,
			VtxoStateKind::Locked => LOCKED,
			VtxoStateKind::Spent => SPENT,
		}
	}

	pub fn as_byte(&self) -> u8 {
		match self {
			VtxoStateKind::Spendable => 0,
			VtxoStateKind::Locked { .. } => 1,
			VtxoStateKind::Spent => 2,
		}
	}

	/// List of all existing states
	pub const ALL: &[VtxoStateKind] = &[
		VtxoStateKind::Spendable,
		VtxoStateKind::Locked,
		VtxoStateKind::Spent,
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
	/// The [Vtxo] is currently locked in an action.
	Locked {
		/// The ID of the associated [Movement](crate::movement::Movement) that locked this VTXO.
		movement_id: Option<MovementId>,
	},
	/// The [Vtxo] has been consumed.
	Spent,
}

impl VtxoState {
	/// Returns the compact [VtxoStateKind] discriminator for this rich state.
	pub fn kind(&self) -> VtxoStateKind {
		match self {
			VtxoState::Spendable => VtxoStateKind::Spendable,
			VtxoState::Locked { .. } => VtxoStateKind::Locked,
			VtxoState::Spent => VtxoStateKind::Spent,
		}
	}
}

/// A wallet-owned [Vtxo] paired with its current tracked state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletVtxo {
	/// The underlying [Vtxo].
	#[serde(with = "ark::encode::serde")]
	pub vtxo: Vtxo<Full>,
	/// The current tracked state for [WalletVtxo::into_vtxo].
	pub state: VtxoState,
}

impl VtxoRef for WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn as_bare_vtxo(&self) -> Option<std::borrow::Cow<'_, Vtxo<Bare>>> {
		Some(std::borrow::Cow::Owned(self.vtxo.to_bare()))
	}
	fn as_full_vtxo(&self) -> Option<&Vtxo<Full>> { Some(&self.vtxo) }
	fn into_full_vtxo(self) -> Option<Vtxo<Full>> { Some(self.vtxo) }
}

impl<'a> VtxoRef for &'a WalletVtxo {
	fn vtxo_id(&self) -> ark::VtxoId { self.vtxo.id() }
	fn as_bare_vtxo(&self) -> Option<std::borrow::Cow<'_, Vtxo<Bare>>> {
		Some(std::borrow::Cow::Owned(self.vtxo.to_bare()))
	}
	fn as_full_vtxo(&self) -> Option<&Vtxo<Full>> { Some(&self.vtxo) }
	fn into_full_vtxo(self) -> Option<Vtxo<Full>> { Some(self.vtxo.clone()) }
}

impl AsRef<Vtxo<Full>> for WalletVtxo {
	fn as_ref(&self) -> &Vtxo<Full> {
		&self.vtxo
	}
}

impl Deref for WalletVtxo {
	type Target = Vtxo<Full>;

	fn deref(&self) -> &Vtxo<Full> {
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
		];

		assert_eq!(
			serde_json::to_string(&states).unwrap(),
			serde_json::to_string(&[SPENDABLE, SPENT, LOCKED]).unwrap(),
		);

		// If a compiler error occurs,
		// This is a reminder that you should update the test above
		match VtxoState::Spent {
			VtxoState::Spendable => {},
			VtxoState::Spent => {},
			VtxoState::Locked { .. } => {},
		}
	}
}
