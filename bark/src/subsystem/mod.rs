//! Contains subsystem-related constants and types for Bark.
//!
//! In its current form this has little functionality; however, in the future
//! it will contain interfaces allowing for developers to add their own
//! subsystems which Bark can use.

use std::collections::HashMap;
use std::fmt;

use bitcoin::{Amount, OutPoint};

use ark::vtxo::VtxoRef;

/// A unique identifier for a subsystem.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct SubsystemId(u32);

impl SubsystemId {
	pub fn new(id: u32) -> Self {
		SubsystemId(id)
	}
}

impl fmt::Display for SubsystemId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.0)
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
		write!(f, "{}", match self {
			RoundMovement::Offboard => "offboard",
			RoundMovement::Refresh => "refresh",
			RoundMovement::SendOnchain => "send_onchain",
		})
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum BarkSubsystem {
	Arkoor,
	Board,
	Exit,
	LightningReceive,
	LightningSend,
	Round,
}

impl BarkSubsystem {
	pub fn as_str(&self) -> &'static str {
		match self {
			BarkSubsystem::Arkoor => "bark.arkoor",
			BarkSubsystem::Board => "bark.board",
			BarkSubsystem::Exit => "bark.exit",
			BarkSubsystem::LightningReceive => "bark.lightning_receive",
			BarkSubsystem::LightningSend => "bark.lightning_send",
			BarkSubsystem::Round => "bark.round",
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
		write!(f, "{}", match self {
			ArkoorMovement::Receive => "receive",
			ArkoorMovement::Send => "send",
		})
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
		write!(f, "{}", match self {
			BoardMovement::Board => "board",
		})
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum ExitMovement {
	Exit,
}

impl fmt::Display for ExitMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", match self {
			ExitMovement::Exit => "start",
		})
	}
}

/// Provides helper methods for lightning-related movements.
pub(crate) struct LightningMovement {}

impl LightningMovement {
	pub fn htlc_metadata(
		htlcs: impl IntoIterator<Item = impl VtxoRef>,
	) -> anyhow::Result<impl IntoIterator<Item = (String, serde_json::Value)>> {
		let htlcs = htlcs.into_iter().map(|v| v.vtxo_id()).collect::<Vec<_>>();
		Ok([("htlc_vtxos".into(), serde_json::to_value(&htlcs)?)])
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum LightningReceiveMovement {
	Receive,
}

impl fmt::Display for LightningReceiveMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", match self {
			LightningReceiveMovement::Receive => "receive",
		})
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum LightningSendMovement {
	Send,
}

impl fmt::Display for LightningSendMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", match self {
			LightningSendMovement::Send => "send",
		})
	}
}
