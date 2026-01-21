//! Contains subsystem-related constants and types for Bark.
//!
//! In its current form this has little functionality; however, in the future
//! it will contain interfaces allowing for developers to add their own
//! subsystems which Bark can use.

use std::fmt;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, OutPoint, Transaction};

use ark::lightning::PaymentHash;
use ark::vtxo::VtxoRef;

/// A unique identifier for a subsystem.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Subsystem(&'static str);

impl Subsystem {
	pub const fn new(id: &'static str) -> Self {
		Subsystem(id)
	}

	pub fn as_name(&self) -> &'static str {
		self.0
	}

	/// The built-in arkoor subsystem
	pub const ARKOOR: Subsystem = Subsystem::new("bark.arkoor");

	/// The built-in board subsystem
	pub const BOARD: Subsystem = Subsystem::new("bark.board");

	/// The built-in offboard subsystem
	pub const OFFBOARD: Subsystem = Subsystem::new("bark.offboard");

	/// The built-in exit subsystem
	pub const EXIT: Subsystem = Subsystem::new("bark.exit");

	/// The built-in Lightning receive subsystem
	pub const LIGHTNING_RECEIVE: Subsystem = Subsystem::new("bark.lightning_receive");

	/// The built-in Lightning send subsystem
	pub const LIGHTNING_SEND: Subsystem = Subsystem::new("bark.lightning_send");

	/// The built-in round subsystem
	pub const ROUND: Subsystem = Subsystem::new("bark.round");
}

impl fmt::Display for Subsystem {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str(self.0)
	}
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum RoundMovement {
	Refresh,
}

impl fmt::Display for RoundMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			RoundMovement::Refresh => f.write_str("refresh"),
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
	) -> impl IntoIterator<Item = (String, serde_json::Value)> {
		[
			(
				"chain_anchor".into(),
				serde_json::to_value(outpoint).expect("outpoint can serde"),
			),
			(
				"onchain_fee_sat".into(),
				serde_json::to_value(onchain_fee.to_sat()).expect("int can serde"),
			),
		]
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
pub(crate) enum OffboardMovement {
	Offboard,
	SendOnchain,
}

impl OffboardMovement {
	pub fn metadata(
		offboard_tx: &Transaction,
	) -> impl IntoIterator<Item = (String, serde_json::Value)> {
		[
			(
				"offboard_txid".into(),
				serde_json::to_value(offboard_tx.compute_txid()).expect("txid can serde"),
			),
			(
				"offboard_tx".into(),
				serde_json::to_value(serialize_hex(&offboard_tx)).expect("string can serde"),
			),
		]
	}
}

impl fmt::Display for OffboardMovement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			OffboardMovement::Offboard => f.write_str("offboard"),
			OffboardMovement::SendOnchain => f.write_str("send_onchain"),
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
	) -> impl IntoIterator<Item = (String, serde_json::Value)> {
		let htlcs = htlcs.into_iter().map(|v| v.vtxo_id()).collect::<Vec<_>>();
		[
			(
				"payment_hash".into(),
				serde_json::to_value(payment_hash).expect("payment hash can serde"),
			),
			(
				"htlc_vtxos".into(),
				serde_json::to_value(&htlcs).expect("vtxo ids can serde"),
			),
		]
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
