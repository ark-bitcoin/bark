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
#[derive(Debug, Deserialize, Serialize)]
pub struct MovementArgs<'a, S, R, Re>
	where
		S: IntoIterator<Item = &'a Vtxo>,
		R: IntoIterator<Item = (&'a Vtxo, VtxoState)>,
		Re: IntoIterator<Item = (String, Amount)>,
{
	/// VTXOs that are spent in the movement.
	///
	/// They will be marked as spent and linked to the created movement
	pub spends: S,
	/// New VTXOs to store and link to the created movement
	pub receives: R,
	/// External destinations of the movement
	pub recipients: Re,
	/// Optional offchain fees paid for the movement
	pub fees: Option<Amount>
}
