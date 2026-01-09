

use std::borrow::Cow;

use ark::rounds::RoundId;
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin_ext::BlockHeight;
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UneconomicalSweepInput {
	pub outpoint: OutPoint,
	pub value: Amount,
}
impl_slog!(UneconomicalSweepInput, DEBUG, "A sweepable output is uneconomical to sweep");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotSweeping {
	pub available_surplus: Amount,
	pub nb_inputs: usize,
}
impl_slog!(NotSweeping, INFO, "Not sweeping rounds");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepingVtxos {
	pub total_surplus: Amount,
	pub inputs: Vec<OutPoint>,
}
impl_slog!(SweepingVtxos, INFO, "Sweeping vtxos");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepingOutput {
	pub outpoint: OutPoint,
	pub amount: Amount,
	pub surplus: Amount,
	pub sweep_type: Cow<'static, str>,
	pub expiry_height: BlockHeight,
}
impl_slog!(SweepingOutput, DEBUG, "Sweeping output");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepBroadcast {
	pub txid: Txid,
	pub surplus: Amount,
}
impl_slog!(SweepBroadcast, INFO, "Completed a sweep tx");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardFullySwept {
	pub board_utxo: OutPoint,
	pub sweep_tx: Txid,
}
impl_slog!(BoardFullySwept, INFO, "Succesfully swept and fully confirmed an board vtxo");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundFullySwept {
	pub round_id: RoundId,
}
impl_slog!(RoundFullySwept, INFO, "An expired round was successfully swept");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedSweepTrigger {}
impl_slog!(ReceivedSweepTrigger, INFO, "Received a trigger to sweep over RPC");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepTxFullyConfirmed {
	pub txid: Txid,
}
impl_slog!(SweepTxFullyConfirmed, INFO, "a sweep tx is deeply confirmed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepTxAbandoned {
	pub txid: Txid,
	pub tx: String,
}
impl_slog!(SweepTxAbandoned, WARN, "a sweep tx is no longer needed, but unconfirmed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweeperStats {
	pub nb_pending_txs: usize,
	pub nb_pending_utxos: usize,
}
impl_slog!(SweeperStats, INFO, "sweep process statistics");
