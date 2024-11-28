
//! In this module, we define all our log messages.
//!
//! TODO(stevenroose) ideally we'd do this a bit more efficiently
//! I'd like to improve to
//! - have the struct definitions be independent, so we can easily add docs
//! - let the macro just do the impls
//! - somehow build a wrapper that uses serde to be a `Source` and use serde also
//!   to deserialize from the log message

use bitcoin::{Amount, OutPoint, Txid};
use serde::{Deserialize, Serialize};

use ark::VtxoId;


// round flow

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_id: u64,
}
impl_slog!(RoundStarted, Info, "Round started");

// wallet mgmt

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingForfeits {
	pub round_id: u64,
	pub input: VtxoId,
}
impl_slog!(MissingForfeits, Trace, "Missing forfeit sigs for input vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartMissingForfeits {
	pub round_id: u64,
}
impl_slog!(RestartMissingForfeits, Debug, "Restarting round because of missing forfeits");
