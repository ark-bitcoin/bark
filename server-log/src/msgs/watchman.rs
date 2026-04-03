
use ark::vtxo::VtxoPolicyKind;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Amount, FeeRate, Txid};
use bitcoin::hashes::sha256;

use ark::VtxoId;
use bitcoin_ext::BlockHeight;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateSecretHash {
	pub hash: sha256::Hash,
}
impl_slog!(DuplicateSecretHash, ERROR, "preimage-hash pair duplicate");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressMissingSignature {
	pub vtxo_id: VtxoId,
	pub txid: Txid,
}
impl_slog!(ProgressMissingSignature, WARN, "progress transaction exists but signature is missing");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDeadlineExceeded {
	pub vtxo_id: VtxoId,
	pub deadline: BlockHeight,
	pub current_height: BlockHeight,
}
impl_slog!(ClaimDeadlineExceeded, WARN, "claim deadline exceeded");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressDeadlineExceeded {
	pub vtxo_id: VtxoId,
	pub deadline: BlockHeight,
	pub current_height: BlockHeight,
}
impl_slog!(ProgressDeadlineExceeded, WARN, "progress deadline exceeded");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchmanAddedVtxo {
	pub id: VtxoId,
}
impl_slog!(WatchmanAddedVtxo, TRACE, "added VTXO to frontier");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchmanAddedFundingTx {
	pub txid: Txid,
	pub nb_vtxos: usize,
}
impl_slog!(WatchmanAddedFundingTx, INFO, "Added funding tx to frontier");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimChunkBroadcastFailure {
	pub error: String,
	pub vtxos: Vec<VtxoId>,
}
impl_slog!(ClaimChunkBroadcastFailure, WARN, "Failed to broadcast claim chunk");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimBroadcastFailure {
	pub error: String,
	pub vtxo_id: VtxoId,
}
impl_slog!(ClaimBroadcastFailure, WARN, "Failed to broadcast claim");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparingVtxoClaim {
	pub vtxo_id: VtxoId,
	pub policy: VtxoPolicyKind,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub value: Amount,
}
impl_slog!(PreparingVtxoClaim, DEBUG, "Broadcast claim transaction");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimBroadcast {
	pub txid: Txid,
	pub vtxo_ids: Vec<VtxoId>,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub fee_rate: FeeRate,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub total_input_value: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub total_output_value: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub fee: Amount,
}
impl_slog!(ClaimBroadcast, INFO, "Broadcast claim transaction");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoMoreConfirmedFunds {
	pub wallet: String,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub balance: Amount,
	pub address: bitcoin::Address<NetworkUnchecked>,
}
impl_slog!(NoMoreConfirmedFunds, WARN, "No more confirmed funds in wallet");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressCpfpFailure {
	pub vtxo_id: VtxoId,
	pub txid: Txid,
	pub error: String,
}
impl_slog!(ProgressCpfpFailure, WARN, "Failed to create CPFP for a progress tx");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastingDependentTx {
	pub child_txid: Txid,
	pub parent_txid: Txid,
}
impl_slog!(BroadcastingDependentTx, DEBUG, "Broadcasting a dependent tx for a progress tx");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressBroadcast {
	pub txid: Txid,
	pub cpfp_txid: Txid,
	pub vtxo_id: VtxoId,
}
impl_slog!(ProgressBroadcast, INFO, "Broadcast progress transaction with CPFP");
