

use bitcoin::{Amount, OutPoint, Txid};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UneconomicalSweepInput {
	pub outpoint: OutPoint,
	pub value: Amount,
}
impl_slog!(UneconomicalSweepInput, Debug, "A sweepable output is uneconomical to sweep");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotSweeping {
	pub available_surplus: Amount,
	pub nb_inputs: usize,
}
impl_slog!(NotSweeping, Info, "Not sweeping rounds");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepingVtxos {
	pub total_surplus: Amount,
	pub inputs: Vec<OutPoint>,
}
impl_slog!(SweepingVtxos, Info, "Sweeping vtxos");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepingOutput {
	pub outpoint: OutPoint,
	pub amount: Amount,
	pub surplus: Amount,
}
impl_slog!(SweepingOutput, Debug, "Sweeping output");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepBroadcast {
	pub txid: Txid,
	pub surplus: Amount,
}
impl_slog!(SweepBroadcast, Info, "Completed a sweep tx");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardFullySwept {
	pub onboard_utxo: OutPoint,
}
impl_slog!(OnboardFullySwept, Info, "Succesfully swept and fully confirmed an onboard vtxo");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundFullySwept {
	pub round_id: Txid,
}
impl_slog!(RoundFullySwept, Info, "An expired round was successfully swept");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedSweepTrigger {}
impl_slog!(ReceivedSweepTrigger, Info, "Received a trigger to sweep over RPC");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepTxFullyConfirmed {
	pub txid: Txid,
}
impl_slog!(SweepTxFullyConfirmed, Info, "a sweep tx is deeply confirmed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepTxAbandoned {
	pub txid: Txid,
	pub tx: String,
}
impl_slog!(SweepTxAbandoned, Warn, "a sweep tx is no longer needed, but unconfirmed");


