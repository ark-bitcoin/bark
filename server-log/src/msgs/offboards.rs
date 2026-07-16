
use bitcoin::{Amount, FeeRate, OutPoint, SignedAmount, Txid};

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
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain_fee: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub user_fee: Amount,
	/// the fee charged by the server, can be negative
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub fee: SignedAmount,
}
impl_slog!(PreparedOffboard, TRACE, "prepared offboard tx");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayedOffboardSession {
	pub offboard_txid: Txid,
	pub input_vtxos: Vec<VtxoId>,
}
impl_slog!(ReplayedOffboardSession, DEBUG, "replayed pending offboard session for identical request");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOffboard {
	pub offboard_txid: Txid,
	pub input_vtxos: Vec<VtxoId>,
	pub wallet_utxos: Vec<OutPoint>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain_fee: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub user_fee: Amount,
	/// the fee charged by the server, can be negative
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub fee: SignedAmount,
}
impl_slog!(SignedOffboard, DEBUG, "signed offboard tx");

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
