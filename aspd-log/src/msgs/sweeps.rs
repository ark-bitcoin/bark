

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
pub struct SweepingRounds {
	pub total_surplus: Amount,
	pub inputs: Vec<OutPoint>,
}
impl_slog!(SweepingRounds, Info, "Sweeping rounds");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepingOutput {
	pub outpoint: OutPoint,
	pub amount: Amount,
	pub surplus: Amount,
}
impl_slog!(SweepingOutput, Debug, "Sweeping output");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepComplete {
	pub txid: Txid,
	pub surplus: Amount,
}
impl_slog!(SweepComplete, Info, "Completed a sweep tx");
