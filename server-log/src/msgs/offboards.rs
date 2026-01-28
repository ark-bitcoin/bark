
use bitcoin::{Amount, FeeRate, OutPoint, Txid};

use ark::VtxoId;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedOffboard {
	pub offboard_txid: Txid,
	pub input_vtxos: Vec<VtxoId>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub gross_amount: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub net_amount: Amount,
	pub fee_rate: FeeRate,
	pub wallet_utxos: Vec<OutPoint>,
}
impl_slog!(PreparedOffboard, TRACE, "prepared offboard tx");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOffboard {
	pub offboard_txid: Txid,
	pub input_vtxos: Vec<VtxoId>,
	pub wallet_utxos: Vec<OutPoint>,
}
impl_slog!(SignedOffboard, TRACE, "signed offboard tx");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardTxRejected {
	pub offboard_txid: Txid,
	pub reject_reason: String,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_offboardtx: Vec<u8>,
	pub input_vtxos: Vec<VtxoId>,
	pub wallet_utxos: Vec<OutPoint>,
}
impl_slog!(OffboardTxRejected, ERROR, "offboard tx rejected by mempool");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitOffboardFailed {
	pub offboard_txid: Txid,
	pub error: String,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_offboardtx: Vec<u8>,
	pub input_vtxos: Vec<VtxoId>,
	pub wallet_utxos: Vec<OutPoint>,
}
impl_slog!(CommitOffboardFailed, ERROR, "failed to commit offboard");
