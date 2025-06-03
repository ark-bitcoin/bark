
use ark::Vtxo;
use bitcoin::Amount;

use crate::vtxo_state::VtxoState;

#[derive(Debug, Deserialize, Serialize)]
pub enum MovementKind {
	Board,
	Round,
	Offboard,
	Exit,
	ArkoorSend,
	ArkoorReceive,
	LightningSend,
	LightningSendRevocation,
	LightningReceive,
}

impl MovementKind {
	pub fn from_str(s: &str) -> anyhow::Result<Self> {
		match s {
			"onboard" => Ok(MovementKind::Board),
			"round" => Ok(MovementKind::Round),
			"offboard" => Ok(MovementKind::Offboard),
			"arkoor-send" => Ok(MovementKind::ArkoorSend),
			"arkoor-receive" => Ok(MovementKind::ArkoorReceive),
			"lightning-send" => Ok(MovementKind::LightningSend),
			"lightning-send-revocation" => Ok(MovementKind::LightningSendRevocation),
			"lightning-receive" => Ok(MovementKind::LightningReceive),
			"exit" => Ok(MovementKind::Exit),
			_ => bail!("Invalid movement kind: {}", s),
		}
	}

	pub fn as_str(&self) -> &str {
		match self {
			MovementKind::Board => "onboard",
			MovementKind::Round => "round",
			MovementKind::Offboard => "offboard",
			MovementKind::ArkoorSend => "arkoor-send",
			MovementKind::ArkoorReceive => "arkoor-receive",
			MovementKind::LightningSend => "lightning-send",
			MovementKind::LightningSendRevocation => "lightning-send-revocation",
			MovementKind::LightningReceive => "lightning-receive",
			MovementKind::Exit => "exit",
		}
	}
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MovementRecipient {
	/// Can either be a publickey, spk or a bolt11 invoice
	pub recipient: String,
	/// Amount sent to the recipient
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}

/// A [`Movement`] represents any offchain balance change,
/// either by receiving, sending or refreshing VTXO
#[derive(Debug)]
pub struct Movement {
	pub id: u32,
	/// Movement kind
	pub kind: MovementKind,
	/// Fees paid for the movement
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vec<Vtxo>,
	/// Received VTXOs from this movement
	pub receives: Vec<Vtxo>,
	/// External recipients of the movement
	pub recipients: Vec<MovementRecipient>,
	/// Movement date
	pub created_at: String,
}

/// Arguments used to create a movement
pub struct MovementArgs<'a> {
	/// Movement kind
	pub kind: MovementKind,
	/// VTXOs that are spent in the movement.
	///
	/// They will be marked as spent and linked to the created movement
	pub spends: &'a [&'a Vtxo],
	/// New VTXOs to store and link to the created movement
	pub receives: &'a [(&'a Vtxo, VtxoState)],
	/// External destinations of the movement
	pub recipients: &'a [(&'a str, Amount)],
	/// Optional offchain fees paid for the movement
	pub fees: Option<Amount>
}
