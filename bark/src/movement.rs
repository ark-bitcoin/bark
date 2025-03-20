use ark::VtxoId;
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