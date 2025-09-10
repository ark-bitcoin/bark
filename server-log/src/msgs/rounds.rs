use std::time::Duration;

use ark::rounds::RoundSeq;
use ark::vtxo::VtxoPolicyType;
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_ext::BlockHeight;
use ark::VtxoId;

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_seq: RoundSeq,
}
impl_slog!(RoundStarted, Info, "Round started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptingRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::hex")]
	pub challenge: Vec<u8>,
}
impl_slog!(AttemptingRound, Debug, "Attempting to complete a round");

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistrationFailed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
	pub duration_since_attempt: Duration,
}
impl_slog!(RoundPaymentRegistrationFailed, Trace, "Participant failed to register a payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoDuplicateInput {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
}
impl_slog!(RoundUserVtxoDuplicateInput, Trace, "user attempted to spend same input vtxo twice");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoAlreadyRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
}
impl_slog!(RoundUserVtxoAlreadyRegistered, Trace, "user attempted to spend vtxo already registered in round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoNotAllowed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
}
impl_slog!(RoundUserVtxoNotAllowed, Trace, "user attempted to spend vtxo not allowed in this round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoInFlux {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
	pub duration_since_attempt: Duration,
}
impl_slog!(RoundUserVtxoInFlux, Trace, "user attempted to submit vtxo already in flux to round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoUnknown {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: Option<VtxoId>,
	pub duration_since_attempt: Duration,
}
impl_slog!(RoundUserVtxoUnknown, Trace, "user attempted to spend unknown vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserDuplicateCosignPubkey {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub cosign_pubkey: PublicKey,
}
impl_slog!(RoundUserDuplicateCosignPubkey, Trace,
	"user attempted to register two payments with the same cosign pubkey",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserBadNbNonces {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_cosign_nonces: usize,
}
impl_slog!(RoundUserBadNbNonces, Trace,
	"user attempted to register output vtxo with incorrect number of cosign nonces",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserBadOutputAmount {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub amount: Amount,
}
impl_slog!(RoundUserBadOutputAmount, Trace,
	"user requested an output with an amount exceeding maximum vtxo amount",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_inputs: usize,
	pub nb_outputs: usize,
	pub nb_offboards: usize,
	pub duration_since_attempt: Duration,
}
impl_slog!(RoundPaymentRegistered, Trace, "Registered payment from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_outputs: usize,
	pub max_output_vtxos: usize,
	pub duration_since_attempt: Duration,
}
impl_slog!(FullRound, Warn, "Round is full, no longer adding payments");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoRoundPayments {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_submit_time: Duration,
}
impl_slog!(NoRoundPayments, Info, "Nothing to do this round, sitting it out...");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundPayments {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub input_volume: Amount,
	pub input_count: usize,
	pub output_count: usize,
	pub offboard_count: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration: Duration,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_submit_time: Duration,
}
impl_slog!(ReceivedRoundPayments, Info, "Finished collecting round payments");

// ****************************************************************************
// * VTXO signatures
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructingRoundVtxoTree {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub tip_block_height: BlockHeight,
	pub vtxo_expiry_block_height: BlockHeight,
}
impl_slog!(ConstructingRoundVtxoTree, Debug, "Beginning VTXO tree construction and signing");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingRoundSignatures {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration_since_sending: Duration,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_sign_time: Duration,
}
impl_slog!(AwaitingRoundSignatures, Debug, "Waiting for VTXO tree signatures to be received");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppingLateVtxoSignatureVtxos {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub disallowed_vtxos: Vec<VtxoId>,
}
impl_slog!(DroppingLateVtxoSignatureVtxos, Trace, "Dropping VTXOs from the round because we didn't receive the participants VTXO tree signature in time");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoSignatureRegistrationFailed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
}
impl_slog!(VtxoSignatureRegistrationFailed, Warn, "Participant failed to provide a valid VTXO tree signature");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVtxoSignaturesRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_vtxo_signatures: usize,
	pub cosigner: PublicKey,
}
impl_slog!(RoundVtxoSignaturesRegistered, Trace, "Registered VTXO tree signatures from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundVtxoSignatures {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration: Duration,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_sign_time: Duration,
}
impl_slog!(ReceivedRoundVtxoSignatures, Debug, "Finished receiving VTXO tree signatures");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedSignedVtxoTree {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_vtxo_signatures: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration: Duration,
}
impl_slog!(CreatedSignedVtxoTree, Debug, "Created the final signed VTXO tree, ready to broadcast to participants");

// ****************************************************************************
// * Forfeit signatures
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingRoundForfeits {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration_since_sending: Duration,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_sign_time: Duration,
}
impl_slog!(AwaitingRoundForfeits, Debug, "Sent the round proposal to participants and awaiting any round forfeits");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedForfeitSignatures {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_forfeits: usize,
	pub vtxo_ids: Vec<VtxoId>,
}
impl_slog!(ReceivedForfeitSignatures, Trace, "Received signatures for given VTXOs");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownForfeitSignature {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo_id: VtxoId,
}
impl_slog!(UnknownForfeitSignature, Trace, "Participant provided a forfeit signature for an unknown input");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitRegistrationFailed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
}
impl_slog!(ForfeitRegistrationFailed, Warn, "Failed to register forfeits for the VTXO tree");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundForfeits {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_forfeits: usize,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration: Duration,
	#[serde(with = "crate::serde_utils::duration")]
	pub max_round_sign_time: Duration,
}
impl_slog!(ReceivedRoundForfeits, Debug, "Finished receiving round forfeits");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingForfeits {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub input: VtxoId,
}
impl_slog!(MissingForfeits, Trace, "Missing forfeit sigs for input vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartMissingForfeits {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
}
impl_slog!(RestartMissingForfeits, Debug, "Restarting round because of missing forfeits");

// ****************************************************************************
// * Round end
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastedFinalizedRoundTransaction {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub txid: Txid,
	#[serde(with = "crate::serde_utils::duration")]
	pub signing_time: Duration,
}
impl_slog!(BroadcastedFinalizedRoundTransaction, Info,
	"Broadcasted round transaction to the network and all participants"
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoringForfeitVtxo {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub out_point: OutPoint,
}
impl_slog!(StoringForfeitVtxo, Trace, "Storing forfeit vtxo for outpoint");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVtxoCreated {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo_id: VtxoId,
	pub vtxo_type: VtxoPolicyType,
}
impl_slog!(RoundVtxoCreated, Debug, "New VTXO created in round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundFinished {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub txid: Txid,
	pub vtxo_expiry_block_height: BlockHeight,
	#[serde(with = "crate::serde_utils::duration")]
	pub duration: Duration,
	pub nb_input_vtxos: usize,
}
impl_slog!(RoundFinished, Info, "Round finished");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundError {
	pub round_seq: RoundSeq,
	pub error: String,
}
impl_slog!(RoundError, Error, "error during round, restarting");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSyncError {
	pub error: String,
}
impl_slog!(RoundSyncError, Warn, "onchain wallet sync failed during round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatalStoringRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
	#[serde(with = "crate::serde_utils::hex")]
	pub signed_tx: Vec<u8>,
	#[serde(with = "crate::serde_utils::hex")]
	pub vtxo_tree: Vec<u8>,
	pub connector_key: SecretKey,
	pub forfeit_vtxos: Vec<VtxoId>,
}
impl_slog!(FatalStoringRound, Error, "failed to store finished and signed round");
