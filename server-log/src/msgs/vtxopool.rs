
use bitcoin::{Amount, Txid};

use ark::VtxoId;
use ark::arkoor::ArkoorDestination;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentPoolVtxo {
	pub vtxo: VtxoId,
	/// The amount of the spent VTXO
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub destination: ArkoorDestination,
}
impl_slog!(SpentPoolVtxo, DEBUG, "a VTXO pool vtxo was spent");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoolVtxo {
	pub vtxo: VtxoId,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}
impl_slog!(ChangePoolVtxo, DEBUG, "we created a change VTXO from the VTXO pool");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparingPoolIssuance {
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub count: usize,
}
impl_slog!(PreparingPoolIssuance, INFO, "preparing to issue VTXOs for VTXO pool");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparingPoolIssuanceTx {
	pub txid: Txid,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub total_amount: Amount,
	pub total_count: usize,
}
impl_slog!(PreparingPoolIssuanceTx, INFO, "preparing funding tx for signed VTXO tree");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishedPoolIssuance {
	pub txid: Txid,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub total_amount: Amount,
	pub total_count: usize,
}
impl_slog!(FinishedPoolIssuance, INFO, "finished issuing new pool VTXOs");

