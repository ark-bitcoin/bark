use std::time::Duration;

use ark::tree::signed::UnlockHash;
use bitcoin::{Amount, Txid};
use bitcoin::secp256k1::PublicKey;

use ark::VtxoId;
use ark::rounds::RoundSeq;
use ark::vtxo::VtxoPolicyKind;
use bitcoin_ext::BlockHeight;

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_seq: RoundSeq,
}
impl_slog!(RoundStarted, INFO, "Round started");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptingRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::hex")]
	pub challenge: Vec<u8>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(AttemptingRound, DEBUG, "Initiating a round attempt");

// ****************************************************************************
// * Round start
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistrationFailed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundPaymentRegistrationFailed, TRACE, "Participant failed to register a payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoDuplicateInput {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserVtxoDuplicateInput, TRACE, "user attempted to spend same input vtxo twice");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoAlreadyRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserVtxoAlreadyRegistered, TRACE, "user attempted to spend vtxo already registered in round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoNotAllowed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserVtxoNotAllowed, TRACE, "user attempted to spend vtxo not allowed in this round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoInFlux {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: VtxoId,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserVtxoInFlux, TRACE, "user attempted to submit vtxo already in flux to round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserVtxoUnknown {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo: Option<VtxoId>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserVtxoUnknown, TRACE, "user attempted to spend unknown vtxo");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserDuplicateCosignPubkey {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub cosign_pubkey: PublicKey,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserDuplicateCosignPubkey, TRACE,
	"user attempted to register two payments with the same cosign pubkey",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserBadNbNonces {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_cosign_nonces: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserBadNbNonces, TRACE,
	"user attempted to register output vtxo with incorrect number of cosign nonces",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundUserBadOutputAmount {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub amount: Amount,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundUserBadOutputAmount, TRACE,
	"user requested an output with an amount exceeding maximum vtxo amount",
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPaymentRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_inputs: usize,
	pub nb_outputs: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
	pub unlock_hash: UnlockHash,
}
impl_slog!(RoundPaymentRegistered, TRACE, "Registered payment from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_outputs: usize,
	pub max_output_vtxos: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(FullRound, WARN, "Round is full, no longer adding payments");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoRoundPayments {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub max_round_submit_time: Duration,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(NoRoundPayments, INFO, "Nothing to do this round, sitting it out...");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundPayments {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub input_volume: Amount,
	pub input_count: usize,
	pub output_count: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub max_round_submit_time: Duration,
}
impl_slog!(ReceivedRoundPayments, INFO, "Finished collecting round payments");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeedNewRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub max_round_sign_time: Duration,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(NeedNewRound, INFO, "New round is required...");

// ****************************************************************************
// * VTXO signatures
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructingRoundVtxoTree {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub tip_block_height: BlockHeight,
	pub vtxo_expiry_block_height: BlockHeight,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(ConstructingRoundVtxoTree, DEBUG, "Beginning VTXO tree construction and signing");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendVtxoProposal {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(SendVtxoProposal, DEBUG, "Sending VTXO tree propsals to participants");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppingLateVtxoSignatureVtxos {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub disallowed_vtxos: Vec<VtxoId>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(DroppingLateVtxoSignatureVtxos, TRACE, "Dropping VTXOs from the round because we didn't receive the participants VTXO tree signature in time");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoSignatureRegistrationFailed {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(VtxoSignatureRegistrationFailed, WARN, "Participant failed to provide a valid VTXO tree signature");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVtxoSignaturesRegistered {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_vtxo_signatures: usize,
	pub cosigner: PublicKey,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub client_duration: Duration,
}
impl_slog!(RoundVtxoSignaturesRegistered, TRACE, "Registered VTXO tree signatures from a participant");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRoundVtxoSignatures {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub max_round_sign_time: Duration,
}
impl_slog!(ReceivedRoundVtxoSignatures, DEBUG, "Finished receiving VTXO tree signatures");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedSignedVtxoTree {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub nb_vtxo_signatures: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(CreatedSignedVtxoTree, DEBUG, "Created the final signed VTXO tree, ready to broadcast to participants");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartMissingVtxoSigs {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(RestartMissingVtxoSigs, DEBUG, "Restarting round because of missing VTXO tree signatures");

// ****************************************************************************
// * Round end
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastedFinalizedRoundTransaction {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub txid: Txid,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(BroadcastedFinalizedRoundTransaction, INFO,
	"Broadcasted round transaction to the network and all participants"
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundVtxoCreated {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub vtxo_id: VtxoId,
	pub vtxo_type: VtxoPolicyKind,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(RoundVtxoCreated, DEBUG, "New VTXO created in round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundFinished {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub txid: Txid,
	pub vtxo_expiry_block_height: BlockHeight,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
	pub nb_input_vtxos: usize,
}
impl_slog!(RoundFinished, INFO, "Round finished");

// ****************************************************************************
// * hArk leaf and forfeit signing
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarkLeafSigned {
	pub vtxo_id: VtxoId,
	pub funding_txid: Txid,
}
impl_slog!(HarkLeafSigned, TRACE, "signed hArk leaf output");

// ****************
// * general hArk *
// ****************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundParticipationRejected {
	pub unlock_hash: UnlockHash,
	pub reason: String,
}
impl_slog!(RoundParticipationRejected, DEBUG, "rejected hArk participation for round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundForfeitNonceCleanup {
	pub removed_finished: usize,
	pub removed_unfinished: usize,
	pub remaining: usize,
}
impl_slog!(RoundForfeitNonceCleanup, INFO, "cleaned up hArk round forfeit nonce sessions");

// ****************************************************************************
// * general round
// ****************************************************************************

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundError {
	pub round_seq: RoundSeq,
	pub error: String,
}
impl_slog!(RoundError, ERROR, "error during round, restarting");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundSyncError {
	pub error: String,
}
impl_slog!(RoundSyncError, WARN, "onchain wallet sync failed during round");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FatalStoringRound {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub error: String,
	#[serde(with = "crate::serde_utils::hex")]
	pub signed_tx: Vec<u8>,
	#[serde(with = "crate::serde_utils::hex")]
	pub vtxo_tree: Vec<u8>,
	pub input_vtxos: Vec<VtxoId>,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub server_duration: Duration,
}
impl_slog!(FatalStoringRound, ERROR, "failed to store finished and signed round");
