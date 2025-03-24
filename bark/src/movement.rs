use ark::{Vtxo, VtxoId};
use bitcoin::Amount;

#[derive(Debug, Deserialize, Serialize)]
pub struct VtxoSubset {
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}

/// A [`Movement`] represents any offchain balance change,
/// either by receiving, sending or refreshing VTXO
#[derive(Debug, Deserialize, Serialize)]
pub struct Movement {
	pub id: u32,
	/// Can either be a publickey or a bolt11 invoice
	///
	/// Paid amount can be computed as: `paid = sum(spends) - sum(receives) - fees`
	pub destination: Option<String>,
	/// Fees paid for the movement
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vec<VtxoSubset>,
	/// Received VTXOs from this movement
	pub receives: Vec<VtxoSubset>,
	/// Movement date
	pub created_at: String,
}

/// Arguments used to create a movement
#[derive(Debug, Deserialize, Serialize)]
pub struct MovementArgs<'a, S, R>
	where
		S: IntoIterator<Item = &'a Vtxo>,
		R: IntoIterator<Item = &'a Vtxo>
{
	/// VTXOs that are spent in the movement.
	///
	/// They will be marked as spent and linked to the created movement
	pub spends: S,
	/// New VTXOs to store and link to the created movement
	pub receives: R,
	/// Optional external destination of the movement, in case of a sending.
	pub destination: Option<String>,
	/// Optional offchain fees paid for the movement
	pub fees: Option<Amount>
}