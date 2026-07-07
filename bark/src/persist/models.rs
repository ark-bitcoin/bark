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
use std::fmt;

use bitcoin::{Amount, Transaction};
use bitcoin::secp256k1::{Keypair, PublicKey};
use lightning_invoice::Bolt11Invoice;

use ark::{Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::vtxo::Full;
use ark::mailbox::MailboxIdentifier;
use ark::tree::signed::{UnlockHash, VtxoTreeSpec};
use ark::lightning::{PaymentHash, Preimage};
use ark::rounds::RoundSeq;

use crate::WalletVtxo;
use crate::exit::{ExitState, ExitTxOrigin, ExitVtxo};
use crate::movement::MovementId;
use crate::lock_manager::LockGuard;
use crate::round::{AttemptState, RoundFlowState, RoundParticipation, RoundState};
use crate::vtxo::VtxoState;

/// VTXO with state history for persistence.
///
/// TODO(pc): once the storage adaptor grows a migration framework, switch
/// this to hold a `Vtxo<Bare>` plus the cached summaries (mirroring the
/// SQLite `raw_bare`/`raw_genesis` split) and store the genesis bytes in a
/// sibling record. For now we keep the full VTXO embedded so adaptor
/// listings still pay the full deserialization cost — this is the
/// follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeVtxo {
	#[serde(with = "ark::encode::serde")]
	pub vtxo: Vtxo<Full>,
	/// VTXO states, sorted from oldest to newest.
	pub states: Vec<VtxoState>,
}

#[derive(Debug, thiserror::Error)]
#[error("vtxo has no state")]
pub struct MissingStateError;

impl SerdeVtxo {
	pub fn current_state(&self) -> Option<&VtxoState> {
		self.states.last()
	}

	pub fn to_wallet_vtxo(&self) -> Result<WalletVtxo, MissingStateError> {
		let state = self.current_state().cloned().ok_or(MissingStateError)?;
		Ok(wallet_vtxo_from_full(&self.vtxo, state))
	}
}

/// Project a stored full VTXO into the bare-shaped [WalletVtxo] the wallet
/// hot paths consume, computing the cached `exit_depth` and
/// `exit_tx_weight` summaries on the fly.
///
/// SQLite stores those summaries as columns and reads them without touching
/// the genesis chain; the adaptor backend currently does not split storage,
/// so it has to deserialize the full vtxo first and compute the summaries
/// here. Once the adaptor gains a migration framework this helper goes away
/// in favor of a true split.
pub(crate) fn wallet_vtxo_from_full(
	vtxo: &Vtxo<Full>,
	state: VtxoState,
) -> WalletVtxo {
	WalletVtxo {
		vtxo: vtxo.to_bare(),
		state,
		exit_depth: vtxo.exit_depth(),
		exit_tx_weight: vtxo.transactions().map(|t| t.tx.weight()).sum(),
	}
}

/// VTXO key mapping for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeVtxoKey {
	pub index: u32,
	pub public_key: PublicKey,
}

/// Identifier for a stored [RoundState].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoundStateId(pub u32);

impl RoundStateId {
	pub fn to_bytes(&self) -> [u8; 4] {
		self.0.to_be_bytes()
	}
}

impl fmt::Display for RoundStateId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    fmt::Display::fmt(&self.0, f)
	}
}

#[allow(unused)]
pub struct Locked(Box<dyn LockGuard>);

pub struct Unlocked;

pub struct StoredRoundState<G = Locked> {
	id: RoundStateId,
	state: RoundState,
	_guard: G
}

impl<G> StoredRoundState<G> {
	pub fn id(&self) -> RoundStateId {
		self.id
	}

	pub fn state(&self) -> &RoundState {
		&self.state
	}
}

impl StoredRoundState<Unlocked> {
	pub fn new(id: RoundStateId, state: RoundState) -> Self {
		Self { id, state, _guard: Unlocked }
	}

	pub fn lock(self, guard: Box<dyn LockGuard>) -> StoredRoundState {
		StoredRoundState { id: self.id, state: self.state, _guard: Locked(guard) }
	}
}

impl StoredRoundState<Locked> {
	pub fn state_mut(&mut self) -> &mut RoundState {
		&mut self.state
	}

	pub fn unlock(self) -> StoredRoundState<Unlocked> {
		StoredRoundState { id: self.id, state: self.state, _guard: Unlocked }
	}
}

/// Persisted representation of a pending board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingBoard {
	/// This is the [bitcoin::Transaction] that has to
	/// be confirmed onchain for the board to succeed.
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub funding_tx: Transaction,
	/// The id of VTXOs being boarded.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vec<VtxoId>,
	/// The amount of the board.
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// The [MovementId] associated with this board.
	pub movement_id: MovementId,
}

/// Persisted representation of a pending offboard.
///
/// Created when an offboard swap is performed, tracked until the
/// offboard transaction confirms on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOffboard {
	/// The [MovementId] associated with this offboard.
	pub movement_id: MovementId,
	/// The txid of the offboard transaction.
	pub offboard_txid: bitcoin::Txid,
	/// The full signed offboard transaction.
	pub offboard_tx: Transaction,
	/// The VTXOs consumed by this offboard.
	pub vtxo_ids: Vec<VtxoId>,
	/// The destination address of the offboard.
	pub destination: String,
	/// When this pending offboard was created.
	pub created_at: chrono::DateTime<chrono::Local>,
}

/// Replay-protection record for a fully-settled outgoing lightning send.
///
/// Written when a payment is acknowledged with a valid preimage; never
/// deleted. Used by [`crate::actions::lightning::pay`] to refuse paying
/// the same invoice twice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaidInvoice {
	pub payment_hash: PaymentHash,
	pub preimage: Preimage,
	pub paid_at: chrono::DateTime<chrono::Local>,
}

/// Permanent record of a fully-settled incoming lightning receive.
///
/// Written when an inbound payment is claimed (the wallet has obtained
/// spendable VTXOs in exchange for the preimage); never deleted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettledLightningReceive {
	pub payment_hash: PaymentHash,
	pub preimage: Preimage,
	pub invoice: Bolt11Invoice,
	pub amount: Amount,
	pub settled_at: chrono::DateTime<chrono::Local>,
}

/// Persistable view of an [ExitVtxo].
///
/// `StoredExit` is a lightweight data transfer object tailored for storage backends. It captures
/// the VTXO ID, the current state, the full history of the unilateral exit, and a pointer
/// back to the pending movement that records this exit.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredExit {
	/// Identifier of the VTXO being exited.
	pub vtxo_id: VtxoId,
	/// Current exit state.
	pub state: ExitState,
	/// Historical states for auditability.
	pub history: Vec<ExitState>,
	/// The movement that records this exit. `None` for exits created before
	/// movement tracking was wired up.
	pub movement_id: Option<MovementId>,
}

impl StoredExit {
	/// Builds a persistable snapshot from an [ExitVtxo].
	pub fn new(exit: &ExitVtxo) -> Self {
		Self {
			vtxo_id: exit.id(),
			state: exit.state().clone(),
			history: exit.history().clone(),
			movement_id: exit.movement_id(),
		}
	}
}

/// Exit child transaction for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeExitChildTx {
	#[serde(with = "bitcoin_ext::serde::encodable")]
	pub child_tx: Transaction,
	pub origin: ExitTxOrigin,
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

/// Model for [RoundParticipation]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerdeRoundParticipation<'a> {
	#[serde(with = "ark::encode::serde::cow::vec")]
	inputs: Cow<'a, [Vtxo<Full>]>,
	outputs: Vec<SerdeVtxoRequest<'a>>,
	#[serde(default, skip_serializing_if = "Option::is_none", with = "ark::encode::serde::opt")]
	unblinded_mailbox_id: Option<MailboxIdentifier>,
}

impl<'a> From<&'a RoundParticipation> for SerdeRoundParticipation<'a> {
	fn from(v: &'a RoundParticipation) -> Self {
	    Self {
			inputs: Cow::Borrowed(&v.inputs),
			outputs: v.outputs.iter().map(|v| v.into()).collect(),
			unblinded_mailbox_id: v.unblinded_mailbox_id,
		}
	}
}

impl<'a> From<SerdeRoundParticipation<'a>> for RoundParticipation {
	fn from(v: SerdeRoundParticipation<'a>) -> Self {
		Self {
			inputs: v.inputs.into_owned(),
			outputs: v.outputs.into_iter().map(|v| v.into()).collect(),
			unblinded_mailbox_id: v.unblinded_mailbox_id,
		}
	}
}

/// Placeholder for the now-removed `secret_nonces` field. Discards
/// any payload on read so legacy records still parse.
#[derive(Debug, Default)]
struct PersistedNoncesPlaceholder;

impl ::serde::Serialize for PersistedNoncesPlaceholder {
	fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.collect_seq(std::iter::empty::<()>())
	}
}

impl<'de> ::serde::Deserialize<'de> for PersistedNoncesPlaceholder {
	fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		::serde::de::IgnoredAny::deserialize(d)?;
		Ok(PersistedNoncesPlaceholder)
	}
}

/// Model for [AttemptState]
#[derive(Debug, Serialize, Deserialize)]
enum SerdeAttemptState<'a> {
	AwaitingAttempt,
	AwaitingUnsignedVtxoTree {
		cosign_keys: Cow<'a, [Keypair]>,
		/// Kept for backward compatibility. See
		/// [PersistedNoncesPlaceholder].
		#[serde(rename = "secret_nonces", default)]
		_legacy_secret_nonces: PersistedNoncesPlaceholder,
		unlock_hash: UnlockHash,
	},
	AwaitingFinishedRound {
		#[serde(with = "bitcoin_ext::serde::encodable::cow")]
		unsigned_round_tx: Cow<'a, Transaction>,
		#[serde(with = "ark::encode::serde")]
		vtxos_spec: Cow<'a, VtxoTreeSpec>,
		unlock_hash: UnlockHash,
	},
}

impl<'a> From<&'a AttemptState> for SerdeAttemptState<'a> {
	fn from(state: &'a AttemptState) -> Self {
		match state {
			AttemptState::AwaitingAttempt => SerdeAttemptState::AwaitingAttempt,
			AttemptState::AwaitingUnsignedVtxoTree { cosign_keys, unlock_hash } => {
				SerdeAttemptState::AwaitingUnsignedVtxoTree {
					cosign_keys: Cow::Borrowed(cosign_keys),
					_legacy_secret_nonces: PersistedNoncesPlaceholder,
					unlock_hash: *unlock_hash,
				}
			},
			AttemptState::AwaitingFinishedRound { unsigned_round_tx, vtxos_spec, unlock_hash } => {
				SerdeAttemptState::AwaitingFinishedRound {
					unsigned_round_tx: Cow::Borrowed(unsigned_round_tx),
					vtxos_spec: Cow::Borrowed(vtxos_spec),
					unlock_hash: *unlock_hash,
				}
			},
		}
	}
}

impl<'a> From<SerdeAttemptState<'a>> for AttemptState {
	fn from(state: SerdeAttemptState<'a>) -> Self {
		match state {
			SerdeAttemptState::AwaitingAttempt => AttemptState::AwaitingAttempt,
			SerdeAttemptState::AwaitingUnsignedVtxoTree { cosign_keys, _legacy_secret_nonces: _, unlock_hash } => {
				AttemptState::AwaitingUnsignedVtxoTree {
					cosign_keys: cosign_keys.into_owned(),
					unlock_hash: unlock_hash,
				}
			},
			SerdeAttemptState::AwaitingFinishedRound { unsigned_round_tx, vtxos_spec, unlock_hash } => {
				AttemptState::AwaitingFinishedRound {
					unsigned_round_tx: unsigned_round_tx.into_owned(),
					vtxos_spec: vtxos_spec.into_owned(),
					unlock_hash: unlock_hash,
				}
			},
		}
	}
}

/// Model for [RoundFlowState]
#[derive(Debug, Serialize, Deserialize)]
enum SerdeRoundFlowState<'a> {
	/// We don't do flow and we just wait for the round to finish
	NonInteractivePending {
		unlock_hash: UnlockHash,
	},

	/// Waiting for round to happen
	InteractivePending,
	/// Interactive part ongoing
	InteractiveOngoing {
		round_seq: RoundSeq,
		attempt_seq: usize,
		state: SerdeAttemptState<'a>,
	},

	/// Interactive part finished, waiting for confirmation
	Finished {
		funding_tx: Cow<'a, Transaction>,
		unlock_hash: UnlockHash,
	},

	/// Failed during round
	Failed {
		error: Cow<'a, str>,
	},

	/// User canceled round
	Canceled,
}

impl<'a> From<&'a RoundFlowState> for SerdeRoundFlowState<'a> {
	fn from(state: &'a RoundFlowState) -> Self {
		match state {
			RoundFlowState::NonInteractivePending { unlock_hash } => {
				SerdeRoundFlowState::NonInteractivePending {
					unlock_hash: *unlock_hash,
				}
			},
			RoundFlowState::InteractivePending => SerdeRoundFlowState::InteractivePending,
			RoundFlowState::InteractiveOngoing { round_seq, attempt_seq, state } => {
				SerdeRoundFlowState::InteractiveOngoing {
					round_seq: *round_seq,
					attempt_seq: *attempt_seq,
					state: state.into(),
				}
			},
			RoundFlowState::Finished { funding_tx, unlock_hash } => {
				SerdeRoundFlowState::Finished {
					funding_tx: Cow::Borrowed(funding_tx),
					unlock_hash: *unlock_hash,
				}
			},
			RoundFlowState::Failed { error } => {
				SerdeRoundFlowState::Failed {
					error: Cow::Borrowed(error),
				}
			},
			RoundFlowState::Canceled => SerdeRoundFlowState::Canceled,
		}
	}
}

impl<'a> From<SerdeRoundFlowState<'a>> for RoundFlowState {
	fn from(state: SerdeRoundFlowState<'a>) -> Self {
		match state {
			SerdeRoundFlowState::NonInteractivePending { unlock_hash } => {
				RoundFlowState::NonInteractivePending { unlock_hash }
			},
			SerdeRoundFlowState::InteractivePending => RoundFlowState::InteractivePending,
			SerdeRoundFlowState::InteractiveOngoing { round_seq, attempt_seq, state } => {
				RoundFlowState::InteractiveOngoing {
					round_seq: round_seq,
					attempt_seq: attempt_seq,
					state: state.into(),
				}
			},
			SerdeRoundFlowState::Finished { funding_tx, unlock_hash } => {
				RoundFlowState::Finished {
					funding_tx: funding_tx.into_owned(),
					unlock_hash,
				}
			},
			SerdeRoundFlowState::Failed { error } => {
				RoundFlowState::Failed {
					error: error.into_owned(),
				}
			},
			SerdeRoundFlowState::Canceled => RoundFlowState::Canceled,
		}
	}
}

/// Model for [RoundState]
#[derive(Debug, Serialize, Deserialize)]
pub struct SerdeRoundState<'a> {
	done: bool,
	participation: SerdeRoundParticipation<'a>,
	movement_id: Option<MovementId>,
	flow: SerdeRoundFlowState<'a>,
	#[serde(with = "ark::encode::serde::cow::vec")]
	new_vtxos: Cow<'a, [Vtxo<Full>]>,
	sent_forfeit_sigs: bool,
}

impl<'a> From<&'a RoundState> for SerdeRoundState<'a> {
	fn from(state: &'a RoundState) -> Self {
		Self {
			done: state.done,
			participation: (&state.participation).into(),
			movement_id: state.movement_id,
			flow: (&state.flow).into(),
			new_vtxos: Cow::Borrowed(&state.new_vtxos),
			sent_forfeit_sigs: state.sent_forfeit_sigs,
		}
	}
}

impl<'a> From<SerdeRoundState<'a>> for RoundState {
	fn from(state: SerdeRoundState<'a>) -> Self {
		Self {
			done: state.done,
			participation: state.participation.into(),
			movement_id: state.movement_id,
			flow: state.flow.into(),
			new_vtxos: state.new_vtxos.into_owned(),
			sent_forfeit_sigs: state.sent_forfeit_sigs,
		}
	}
}

#[cfg(test)]
mod test {
	use crate::exit::{ExitState, ExitTxOrigin};
	use crate::vtxo::VtxoState;
	use super::SerdeAttemptState;

	#[test]
	/// Each struct stored as JSON in the database should have test to check for backwards compatibility
	/// Parsing can occur either in convert.rs or this file (query.rs)
	fn test_serialized_structs() {
		// Exit state — top-level variants
		let serialised = r#"{"type":"start","tip_height":119}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"awaiting-delta","tip_height":122,"confirmed_block":"122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f","claimable_height":134}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimable","tip_height":134,"claimable_since": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9","last_scanned_block":null}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimable","tip_height":140,"claimable_since": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9","last_scanned_block": "139:c6e9eb8c8b4d9620bbe87b94d7fb0fbb8eef1c4a8c1e60f7b3a5d80fe26b0d3e"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claim-in-progress","tip_height":134, "claimable_since": "134:6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a","claim_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"claimed","tip_height":134,"txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c","block": "122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"vtxo-already-spent","tip_height":135}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"canceled","tip_height":135}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Exit state — `processing` carrying each ExitTxStatus variant. These fixtures
		// guard against the same class of bug the m0029 migration was written to fix:
		// renaming, dropping, or reshaping a nested status variant must trip this test.
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"verify-inputs"}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-input-confirmation","txids":["ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de"]}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-cpfp-broadcast"}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-confirmation","child_txid":"ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de","origin":{"type":"wallet","confirmed_in":null}}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-confirmation","child_txid":"ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de","origin":{"type":"mempool","fee_rate_kwu":25000,"total_fee":27625}}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":134,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"confirmed","child_txid":"ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de","block":"122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f","origin":{"type":"block","confirmed_in":"122:3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Exit child tx origins
		let serialized = r#"{"type":"wallet","confirmed_in":null}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"wallet","confirmed_in": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		// New shape: mempool is a unit variant; fee data lives on ChildTransactionInfo.fee_info.
		let serialized = r#"{"type":"mempool"}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		// Legacy shape: extra fee_rate_kwu/total_fee fields must still deserialize cleanly.
		let serialized = r#"{"type":"mempool","fee_rate_kwu":25000,"total_fee":27625}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"block","confirmed_in": "134:71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();

		// Vtxo state
		let serialised = r#"{"type": "spendable"}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"type": "spent"}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"type": "exited"}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		// Legacy locked shape: pre-holder records carry `movement_id` instead.
		let serialised = r#"{"type": "locked", "movement_id": null}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"type": "locked", "movement_id": 42}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		// Current locked shapes: `holder` is absent, null, or one of the VtxoLockHolder variants.
		let serialised = r#"{"type": "locked", "holder": null}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"type": "locked", "holder": {"type": "movement", "id": 42}}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"type": "locked", "holder": {"type": "action", "id": "test-action-id"}}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();

		// Round-attempt state — `AwaitingUnsignedVtxoTree`. Legacy
		// records carry `secret_nonces` as an array of 132-byte buffers.
		let serialised = r#"{"AwaitingUnsignedVtxoTree":{"cosign_keys":[],"secret_nonces":[[[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]]],"unlock_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
		serde_json::from_str::<SerdeAttemptState>(serialised).unwrap();
		let serialised = r#"{"AwaitingUnsignedVtxoTree":{"cosign_keys":[],"unlock_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
		serde_json::from_str::<SerdeAttemptState>(serialised).unwrap();
	}

	/// `SerdeRoundState` is written to sqlite via `rmp_serde` (positional
	/// MessagePack), so its wire format needs covering separately from
	/// the JSON fixtures.
	#[test]
	fn test_serialized_round_state_msgpack() {
		use bitcoin::hex::FromHex;

		// Legacy record carrying `secret_nonces`.
		let serialised = "81b84177616974696e67556e7369676e65645674786f5472656593909191dc0084000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4200000000000000000000000000000000000000000000000000000000000000000";
		rmp_serde::from_slice::<SerdeAttemptState>(
			&Vec::<u8>::from_hex(serialised).unwrap(),
		).unwrap();
		// Current record: `secret_nonces` is an empty placeholder seq.
		let serialised = "81b84177616974696e67556e7369676e65645674786f54726565939090c4200000000000000000000000000000000000000000000000000000000000000000";
		rmp_serde::from_slice::<SerdeAttemptState>(
			&Vec::<u8>::from_hex(serialised).unwrap(),
		).unwrap();
	}
}
