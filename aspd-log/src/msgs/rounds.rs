use std::time::Duration;

use bitcoin::{OutPoint, Txid};
use bitcoin::secp256k1::PublicKey;
use ark::VtxoId;

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_id: u64,
}
impl_slog!(RoundStarted, Info, "Round started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptingRound {
	pub round_id: u64,
	pub attempt_number: usize,
}
impl_slog!(AttemptingRound, Debug, "Attempting to complete a round");

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistrationFailed {
	pub round_id: u64,
	pub attempt_number: usize,
	pub error: String,
}
impl_slog!(RoundPaymentRegistrationFailed, Trace, "Participant failed to register a payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistered {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_inputs: usize,
	pub nb_outputs: usize,
	pub nb_offboards: usize,
}
impl_slog!(RoundPaymentRegistered, Trace, "Registered payment from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullRound {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_outputs: usize,
	pub max_output_vtxos: usize,
}
impl_slog!(FullRound, Warn, "Round is full, no longer adding payments");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoRoundPayments {
	pub round_id: u64,
	pub attempt_number: usize,
	pub duration: Duration,
	pub max_round_submit_time: Duration,
}
impl_slog!(NoRoundPayments, Info, "Nothing to do this round, sitting it out...");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundPayments {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_inputs: usize,
	pub nb_outputs: usize,
	pub duration: Duration,
	pub max_round_submit_time: Duration,
}
impl_slog!(ReceivedRoundPayments, Info, "Finished collecting round payments");

// ****************************************************************************
// * VTXO signatures
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructingRoundVtxoTree {
	pub round_id: u64,
	pub attempt_number: usize,
	pub tip_block_height: u32,
	pub vtxo_expiry_block_height: u32,
}
impl_slog!(ConstructingRoundVtxoTree, Debug, "Beginning VTXO tree construction and signing");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingRoundSignatures {
	pub round_id: u64,
	pub attempt_number: usize,
	pub duration_since_sending: Duration,
	pub max_round_sign_time: Duration,
}
impl_slog!(AwaitingRoundSignatures, Debug, "Waiting for VTXO tree signatures to be received");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppingLateVtxoSignatureVtxos {
	pub round_id: u64,
	pub attempt_number: usize,
	pub disallowed_vtxos: Vec<VtxoId>,
}
impl_slog!(DroppingLateVtxoSignatureVtxos, Trace, "Dropping VTXOs from the round because we didn't receive the participants VTXO tree signature in time");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoSignatureRegistrationFailed {
	pub round_id: u64,
	pub attempt_number: usize,
	pub error: String,
}
impl_slog!(VtxoSignatureRegistrationFailed, Warn, "Participant failed to provide a valid VTXO tree signature");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVtxoSignaturesRegistered {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_vtxo_signatures: usize,
	pub cosigner: PublicKey,
}
impl_slog!(RoundVtxoSignaturesRegistered, Trace, "Registered VTXO tree signatures from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundVtxoSignatures {
	pub round_id: u64,
	pub attempt_number: usize,
	pub duration: Duration,
	pub max_round_sign_time: Duration,
}
impl_slog!(ReceivedRoundVtxoSignatures, Debug, "Finished receiving VTXO tree signatures");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedSignedVtxoTree {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_vtxo_signatures: usize,
	pub duration: Duration,
}
impl_slog!(CreatedSignedVtxoTree, Debug, "Created the final signed VTXO tree, ready to broadcast to participants");

// ****************************************************************************
// * Forfeit signatures
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingRoundForfeits {
	pub round_id: u64,
	pub attempt_number: usize,
	pub duration_since_sending: Duration,
	pub max_round_sign_time: Duration,
}
impl_slog!(AwaitingRoundForfeits, Debug, "Sent the round proposal to participants and awaiting any round forfeits");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedForfeitSignatures {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_forfeits: usize,
	pub vtxo_ids: Vec<VtxoId>,
}
impl_slog!(ReceivedForfeitSignatures, Trace, "Received signatures for given VTXOs");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownForfeitSignature {
	pub round_id: u64,
	pub attempt_number: usize,
	pub vtxo_id: VtxoId,
}
impl_slog!(UnknownForfeitSignature, Trace, "Participant provided a forfeit signature for an unknown input");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppingLateForfeitSignatureVtxo {
	pub round_id: u64,
	pub attempt_number: usize,
	pub disallowed_vtxo: VtxoId,
}
impl_slog!(DroppingLateForfeitSignatureVtxo, Trace, "Dropping VTXO from the round because we didn't receive the participants signature in time");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitRegistrationFailed {
	pub round_id: u64,
	pub attempt_number: usize,
	pub error: String,
}
impl_slog!(ForfeitRegistrationFailed, Warn, "Failed to register forfeits for the VTXO tree");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundForfeits {
	pub round_id: u64,
	pub attempt_number: usize,
	pub nb_forfeits: usize,
	pub duration: Duration,
	pub max_round_sign_time: Duration,
}
impl_slog!(ReceivedRoundForfeits, Debug, "Finished receiving round forfeits");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingForfeits {
	pub round_id: u64,
	pub attempt_number: usize,
	pub input: VtxoId,
}
impl_slog!(MissingForfeits, Trace, "Missing forfeit sigs for input vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartMissingForfeits {
	pub round_id: u64,
	pub attempt_number: usize,
}
impl_slog!(RestartMissingForfeits, Debug, "Restarting round because of missing forfeits");

// ****************************************************************************
// * Round end
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastingFinalizedRoundTransaction {
	pub round_id: u64,
	pub attempt_number: usize,
	pub tx_hex: String,
	pub signing_time: Duration,
}
impl_slog!(BroadcastingFinalizedRoundTransaction, Info, "Broadcasting round transaction to the network and all participants");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoringForfeitVtxo {
	pub round_id: u64,
	pub attempt_number: usize,
	pub out_point: OutPoint,
}
impl_slog!(StoringForfeitVtxo, Trace, "Storing forfeit vtxo for outpoint");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundFinished {
	pub round_id: u64,
	pub attempt_number: usize,
	pub txid: Txid,
	pub vtxo_expiry_block_height: u32,
	pub duration: Duration,
}
impl_slog!(RoundFinished, Info, "Round finished");
