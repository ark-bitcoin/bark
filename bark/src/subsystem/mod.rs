//! Contains subsystem-related constants and types for Bark.
//!
//! In its current form this has little functionality; however, in the future
//! it will contain interfaces allowing for developers to add their own
//! subsystems which Bark can use.

use std::collections::HashMap;
use std::fmt;

use bitcoin::{Amount, OutPoint};

use ark::lightning::PaymentHash;
use ark::vtxo::VtxoRef;

/// A unique identifier for a subsystem.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SubsystemId(&'static str);

impl SubsystemId {
	pub const fn new(id: &'static str) -> Self {
		SubsystemId(id)
	}

	pub fn as_name(&self) -> &'static str {
		self.0
	}

	/// The built-in arkoor subsystem
	pub const ARKOOR: SubsystemId = SubsystemId::new("bark.arkoor");

	/// The built-in board subsystem
	pub const BOARD: SubsystemId = SubsystemId::new("bark.board");

	/// The built-in exit subsystem
	pub const EXIT: SubsystemId = SubsystemId::new("bark.exit");

	/// The built-in Lightning receive subsystem
	pub const LIGHTNING_RECEIVE: SubsystemId = SubsystemId::new("bark.lightning_receive");

	/// The built-in Lightning send subsystem
	pub const LIGHTNING_SEND: SubsystemId = SubsystemId::new("bark.lightning_send");

	/// The built-in round subsystem
	pub const ROUND: SubsystemId = SubsystemId::new("bark.round");
}

impl fmt::Display for SubsystemId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.0)
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum RoundMovement {
	Offboard,
	Refresh,
	SendOnchain,
}

impl fmt::Display for RoundMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			RoundMovement::Offboard => f.write_str("offboard"),
			RoundMovement::Refresh => f.write_str("refresh"),
			RoundMovement::SendOnchain => f.write_str("send_onchain"),
		}
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum ArkoorMovement {
	Receive,
	Send,
}

impl fmt::Display for ArkoorMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ArkoorMovement::Receive => f.write_str("receive"),
			ArkoorMovement::Send => f.write_str("send"),
		}
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum BoardMovement {
	Board,
}

impl BoardMovement {
	pub fn metadata(
		outpoint: OutPoint,
		onchain_fee: Amount,
	) -> anyhow::Result<HashMap<String, serde_json::Value>> {
		Ok(HashMap::from([
			("chain_anchor".into(), serde_json::to_value(outpoint)?),
			("onchain_fee_sat".into(), serde_json::to_value(onchain_fee.to_sat())?),
		]))
	}
}

impl fmt::Display for BoardMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			BoardMovement::Board => f.write_str("board"),
		}
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum ExitMovement {
	Exit,
}

impl fmt::Display for ExitMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ExitMovement::Exit => f.write_str("start"),
		}
	}
}

/// Provides helper methods for lightning-related movements.
pub(crate) struct LightningMovement {}

impl LightningMovement {
	pub fn metadata(
		payment_hash: PaymentHash,
		htlcs: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<impl IntoIterator<Item = (String, serde_json::Value)>> {
		let htlcs = htlcs.into_iter().map(|v| v.vtxo_id()).collect::<Vec<_>>();
		Ok([
			("payment_hash".into(), serde_json::to_value(payment_hash)?),
			("htlc_vtxos".into(), serde_json::to_value(&htlcs)?)
		])
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum LightningReceiveMovement {
	Receive,
}

impl fmt::Display for LightningReceiveMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			LightningReceiveMovement::Receive => f.write_str("receive"),
		}
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum LightningSendMovement {
	Send,
}

impl fmt::Display for LightningSendMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			LightningSendMovement::Send => f.write_str("send"),
		}
	}
}
