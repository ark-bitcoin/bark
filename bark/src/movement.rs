use ark::{Vtxo, VtxoId};
use bitcoin::Amount;

use crate::vtxo_state::VtxoState;

#[derive(Debug, Deserialize, Serialize)]
pub struct VtxoSubset {
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MovementRecipient {
	/// Can either be a publickey, spk or a bolt11 invoice
	pub recipient: String,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}

/// A [`Movement`] represents any offchain balance change,
/// either by receiving, sending or refreshing VTXO
#[derive(Debug, Deserialize, Serialize)]
pub struct Movement {
	pub id: u32,
	/// Fees paid for the movement
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vec<VtxoSubset>,
	/// Received VTXOs from this movement
	pub receives: Vec<VtxoSubset>,
	/// External recipients of the movement
	pub recipients: Vec<MovementRecipient>,
	/// Movement date
	pub created_at: String,
}

/// Arguments used to create a movement
pub struct MovementArgs<'a> {
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
