
use bitcoin::{Amount, Txid};

use ark::{VtxoId, VtxoRequest};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentPoolVtxo {
	pub vtxo: VtxoId,
	/// The amount of the spent VTXO
	pub amount: Amount,
	pub request: VtxoRequest,
}
impl_slog!(SpentPoolVtxo, Debug, "a VTXO pool vtxo was spent");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoolVtxo {
	pub vtxo: VtxoId,
	pub amount: Amount,
}
impl_slog!(ChangePoolVtxo, Debug, "we created a change VTXO from the VTXO pool");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparingPoolIssuance {
	pub amount: Amount,
	pub count: usize,
}
impl_slog!(PreparingPoolIssuance, Info, "preparing to issue VTXOs for VTXO pool");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparingPoolIssuanceTx {
	pub txid: Txid,
	pub total_amount: Amount,
	pub total_count: usize,
}
impl_slog!(PreparingPoolIssuanceTx, Info, "preparing funding tx for signed VTXO tree");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishedPoolIssuance {
	pub txid: Txid,
	pub total_amount: Amount,
	pub total_count: usize,
}
impl_slog!(FinishedPoolIssuance, Info, "finished issuing new pool VTXOs");

