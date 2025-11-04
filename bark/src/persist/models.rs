//! Persistence-focused data models.
//!
//! This module defines serializable types that mirror core in-memory structures but are tailored
//! for durable storage and retrieval via a BarkPersister implementation.
//!
//! Intent
//! - Keep storage concerns decoupled from runtime types used by protocol logic.
//! - Provide stable, serde-friendly representations for database backends.
//! - Enable forward/backward compatibility when schema migrations occur.

use std::borrow::Cow;
use std::time::SystemTime;

use bitcoin::{Amount, ScriptBuf, Transaction, Txid};
use bitcoin::secp256k1::Keypair;
use lightning_invoice::Bolt11Invoice;

use ark::{OffboardRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::musig::DangerousSecretNonce;
use ark::tree::signed::VtxoTreeSpec;
use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::rounds::RoundSeq;
use bitcoin_ext::BlockDelta;

use crate::WalletVtxo;
use crate::exit::ExitVtxo;
use crate::exit::models::ExitState;
use crate::round::{AttemptState, RoundFlowState, RoundParticipation, RoundState, UnconfirmedRound};

/// Persisted representation of a pending lightning send.
///
/// Stores the invoice and the amount being sent.
///
/// Note: the record should be removed when the payments is completed or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingLightningSend {
	pub invoice: Invoice,
	pub amount: Amount,
	pub htlc_vtxos: Vec<WalletVtxo>,
}

/// Persisted representation of an incoming Lightning payment.
///
/// Stores the invoice and related cryptographic material (e.g., payment hash and preimage)
/// and tracks whether the preimage has been revealed.
///
/// Note: the record should be removed when the receive is completed or failed.
#[derive(Debug, Clone)]
pub struct LightningReceive {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub invoice: Bolt11Invoice,
	pub preimage_revealed_at: Option<u64>,
	pub htlc_vtxos: Option<Vec<WalletVtxo>>,
	pub htlc_recv_cltv_delta: BlockDelta,
}

/// Persistable view of an [ExitVtxo].
///
/// `StoredExit` is a lightweight data transfer object tailored for storage backends. It captures
/// the VTXO ID, the current state, and the full history of the unilateral exit.
pub struct StoredExit {
	/// Identifier of the VTXO being exited.
	pub vtxo_id: VtxoId,
	/// Current exit state.
	pub state: ExitState,
	/// Historical states for auditability.
	pub history: Vec<ExitState>,
}

impl StoredExit {
	/// Builds a persistable snapshot from an [ExitVtxo].
	pub fn new(exit: &ExitVtxo) -> Self {
		Self {
			vtxo_id: exit.id(),
			state: exit.state().clone(),
			history: exit.history().clone(),
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SerdeVtxoRequest<'a> {
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	amount: Amount,
	#[serde(with = "ark::encode::serde")]
	policy: Cow<'a, VtxoPolicy>,
}

impl<'a> From<&'a VtxoRequest> for SerdeVtxoRequest<'a> {
	fn from(v: &'a VtxoRequest) -> Self {
		Self {
			amount: v.amount,
			policy: Cow::Borrowed(&v.policy),
		}
	}
}

impl<'a> From<SerdeVtxoRequest<'a>> for VtxoRequest {
	fn from(v: SerdeVtxoRequest<'a>) -> Self {
		VtxoRequest {
			amount: v.amount,
			policy: v.policy.into_owned(),
		}
	}
}

/// Model for [OffboardRequest]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct SerdeOffboardRequest<'a> {
	#[serde(with = "bitcoin_ext::serde::encodable::cow")]
	script_pubkey: Cow<'a, ScriptBuf>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	amount: Amount,
}

impl<'a> From<&'a OffboardRequest> for SerdeOffboardRequest<'a> {
	fn from(v: &'a OffboardRequest) -> Self {
		SerdeOffboardRequest {
			script_pubkey: Cow::Borrowed(&v.script_pubkey),
			amount: v.amount,
		}
	}
}

impl<'a> From<SerdeOffboardRequest<'a>> for OffboardRequest {
	fn from(v: SerdeOffboardRequest) -> Self {
	    OffboardRequest {
			script_pubkey: v.script_pubkey.into_owned(),
			amount: v.amount,
		}
	}
}

/// Model for [UnconfirmedRound]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeUnconfirmedRound<'a> {
	#[serde(with = "bitcoin_ext::serde::encodable::cow")]
	funding_tx: Cow<'a, Transaction>,
	#[serde(with = "ark::encode::serde::cow::vec")]
	new_vtxos: Cow<'a, [Vtxo]>,
	double_spenders: Cow<'a, [Option<Txid>]>,
	first_double_spent_at: Option<SystemTime>,
}

impl<'a> From<&'a UnconfirmedRound> for SerdeUnconfirmedRound<'a> {
	fn from(v: &'a UnconfirmedRound) -> Self {
		Self {
			funding_tx: Cow::Borrowed(&v.funding_tx),
			new_vtxos: Cow::Borrowed(&v.new_vtxos),
			double_spenders: Cow::Borrowed(&v.double_spenders),
			first_double_spent_at: v.first_double_spent_at,
		}
	}
}

impl<'a> From<SerdeUnconfirmedRound<'a>> for UnconfirmedRound {
	fn from(v: SerdeUnconfirmedRound<'a>) -> Self {
		Self {
			funding_tx: v.funding_tx.into_owned(),
			new_vtxos: v.new_vtxos.into_owned(),
			double_spenders: v.double_spenders.into_owned(),
			first_double_spent_at: v.first_double_spent_at,
		}
	}
}

/// Model for [RoundParticipation]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerdeRoundParticipation<'a> {
	#[serde(with = "ark::encode::serde::cow::vec")]
	inputs: Cow<'a, [Vtxo]>,
	outputs: Vec<SerdeVtxoRequest<'a>>,
	offboards: Vec<SerdeOffboardRequest<'a>>,
}

impl<'a> From<&'a RoundParticipation> for SerdeRoundParticipation<'a> {
	fn from(v: &'a RoundParticipation) -> Self {
	    Self {
			inputs: Cow::Borrowed(&v.inputs),
			outputs: v.outputs.iter().map(|v| v.into()).collect(),
			offboards: v.offboards.iter().map(|v| v.into()).collect(),
		}
	}
}

impl<'a> From<SerdeRoundParticipation<'a>> for RoundParticipation {
	fn from(v: SerdeRoundParticipation<'a>) -> Self {
		Self {
			inputs: v.inputs.into_owned(),
			outputs: v.outputs.into_iter().map(|v| v.into()).collect(),
			offboards: v.offboards.into_iter().map(|v| v.into()).collect(),
		}
	}
}

/// Model for [AttemptState]
#[derive(Debug, Serialize, Deserialize)]
enum SerdeAttemptState<'a> {
	AwaitingAttempt,
	AwaitingUnsignedVtxoTree {
		cosign_keys: Cow<'a, [Keypair]>,
		secret_nonces: Cow<'a, [Vec<DangerousSecretNonce>]>,
	},
	AwaitingRoundProposal {
		#[serde(with = "bitcoin_ext::serde::encodable::cow")]
		unsigned_round_tx: Cow<'a, Transaction>,
		#[serde(with = "ark::encode::serde")]
		vtxos_spec: VtxoTreeSpec,
	},
	AwaitingFinishedRound {
		#[serde(with = "bitcoin_ext::serde::encodable::cow")]
		unsigned_round_tx: Cow<'a, Transaction>,
		#[serde(with = "ark::encode::serde::cow::vec")]
		new_vtxos: Cow<'a, [Vtxo]>,
	},
}

impl<'a> From<&'a AttemptState> for SerdeAttemptState<'a> {
	fn from(state: &'a AttemptState) -> Self {
		match state {
			AttemptState::AwaitingAttempt => SerdeAttemptState::AwaitingAttempt,
			AttemptState::AwaitingUnsignedVtxoTree { cosign_keys, secret_nonces } => {
				SerdeAttemptState::AwaitingUnsignedVtxoTree {
					cosign_keys: Cow::Borrowed(cosign_keys),
					secret_nonces: Cow::Borrowed(secret_nonces),
				}
			}
			AttemptState::AwaitingRoundProposal { unsigned_round_tx, vtxos_spec } => {
				SerdeAttemptState::AwaitingRoundProposal {
					unsigned_round_tx: Cow::Borrowed(unsigned_round_tx),
					vtxos_spec: vtxos_spec.clone(),
				}
			}
			AttemptState::AwaitingFinishedRound { unsigned_round_tx, new_vtxos } => {
				SerdeAttemptState::AwaitingFinishedRound {
					unsigned_round_tx: Cow::Borrowed(unsigned_round_tx),
					new_vtxos: Cow::Borrowed(new_vtxos),
				}
			}
		}
	}
}

impl<'a> From<SerdeAttemptState<'a>> for AttemptState {
	fn from(state: SerdeAttemptState<'a>) -> Self {
		match state {
			SerdeAttemptState::AwaitingAttempt => AttemptState::AwaitingAttempt,
			SerdeAttemptState::AwaitingUnsignedVtxoTree { cosign_keys, secret_nonces } => {
				AttemptState::AwaitingUnsignedVtxoTree {
					cosign_keys: cosign_keys.into_owned(),
					secret_nonces: secret_nonces.into_owned(),
				}
			}
			SerdeAttemptState::AwaitingRoundProposal { unsigned_round_tx, vtxos_spec } => {
				AttemptState::AwaitingRoundProposal {
					unsigned_round_tx: unsigned_round_tx.into_owned(),
					vtxos_spec,
				}
			}
			SerdeAttemptState::AwaitingFinishedRound { unsigned_round_tx, new_vtxos } => {
				AttemptState::AwaitingFinishedRound {
					unsigned_round_tx: unsigned_round_tx.into_owned(),
					new_vtxos: new_vtxos.into_owned(),
				}
			}
		}
	}
}

/// Model for [RoundFlowState]
#[derive(Debug, Serialize, Deserialize)]
enum SerdeRoundFlowState<'a> {
	WaitingToStart,
	Ongoing {
		round_seq: RoundSeq,
		attempt_seq: usize,
		state: SerdeAttemptState<'a>,
	},
	Finished,
	Failed {
		error: Cow<'a, str>,
	},
}

impl<'a> From<&'a RoundFlowState> for SerdeRoundFlowState<'a> {
	fn from(state: &'a RoundFlowState) -> Self {
		match state {
			RoundFlowState::WaitingToStart => SerdeRoundFlowState::WaitingToStart,
			RoundFlowState::Ongoing { round_seq, attempt_seq, state } => {
				SerdeRoundFlowState::Ongoing {
					round_seq: *round_seq,
					attempt_seq: *attempt_seq,
					state: state.into(),
				}
			}
			RoundFlowState::Success => SerdeRoundFlowState::Finished,
			RoundFlowState::Failed { error } => {
				SerdeRoundFlowState::Failed {
					error: Cow::Borrowed(error),
				}
			}
		}
	}
}

impl<'a> From<SerdeRoundFlowState<'a>> for RoundFlowState {
	fn from(state: SerdeRoundFlowState<'a>) -> Self {
		match state {
			SerdeRoundFlowState::WaitingToStart => RoundFlowState::WaitingToStart,
			SerdeRoundFlowState::Ongoing { round_seq, attempt_seq, state } => {
				RoundFlowState::Ongoing {
					round_seq,
					attempt_seq,
					state: state.into(),
				}
			}
			SerdeRoundFlowState::Finished => RoundFlowState::Success,
			SerdeRoundFlowState::Failed { error } => {
				RoundFlowState::Failed {
					error: error.into_owned(),
				}
			}
		}
	}
}

/// Model for [RoundState]
#[derive(Debug, Serialize, Deserialize)]
pub struct SerdeRoundState<'a> {
	participation: SerdeRoundParticipation<'a>,
	flow: SerdeRoundFlowState<'a>,
	unconfirmed_rounds: Vec<SerdeUnconfirmedRound<'a>>,
}

impl<'a> From<&'a RoundState> for SerdeRoundState<'a> {
	fn from(state: &'a RoundState) -> Self {
		Self {
			participation: (&state.participation).into(),
			flow: (&state.flow).into(),
			unconfirmed_rounds: state.unconfirmed_rounds.iter().map(|r| r.into()).collect(),
		}
	}
}

impl<'a> From<SerdeRoundState<'a>> for RoundState {
	fn from(state: SerdeRoundState<'a>) -> Self {
		Self {
			participation: state.participation.into(),
			flow: state.flow.into(),
			unconfirmed_rounds: state.unconfirmed_rounds.into_iter().map(|r| r.into()).collect(),
		}
	}
}

#[cfg(test)]
mod test {
	use crate::exit::models::{ExitState, ExitTxOrigin};
	use crate::movement::MovementRecipient;
	use crate::vtxo_state::VtxoState;

	#[test]
	/// Each struct stored as JSON in the database should have test to check for backwards compatibility
	/// Parsing can occur either in convert.rs or this file (query.rs)
	fn test_serialised_structs() {
		// Exit state
		let serialised = r#"{"type":"start","tip_height":119}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-input-confirmation","txids":["ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de"]}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"awaiting-delta","tip_height":122,"confirmed_block":"122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f","claimable_height":134}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimable","tip_height":134,"claimable_since": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9","last_scanned_block":null}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claim-in-progress","tip_height":134, "claimable_since": "134:6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a","claim_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimed","tip_height":134,"txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c","block": "122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Exit child tx origins
		let serialized = r#"{"type":"wallet","confirmed_in":null}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"wallet","confirmed_in": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"mempool","fee_rate_kwu":25000,"total_fee":27625}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"block","confirmed_in": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();

		// Movement recipient
		let serialised = r#"{"recipient":"03a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount_sat":150000}"#;
		serde_json::from_str::<MovementRecipient>(serialised).unwrap();

		// Vtxo state
		let serialised = r#""Spendable""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Spent""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Locked""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
	}
}
