use std::fmt::{self, Debug};
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::key::Keypair;
use bitcoin::{Transaction, Txid};

use ark::rounds::{RoundId, RoundInfo, RoundSeq, VtxoOwnershipChallenge};
use ark::tree::signed::VtxoTreeSpec;
use ark::{Vtxo, VtxoId};

use crate::RoundParticipation;
use crate::persist::BarkPersister;

pub(crate) enum ProgressResult<S: Into<RoundState>> {
	Progress { state: S },
	WaitNewRound,
	NewRoundStarted(RoundInfo),
	NewAttemptStarted((AttemptStartedState, VtxoOwnershipChallenge)),
	Wait(S),
}

impl<S: Into<RoundState>> ProgressResult<S> {
	pub fn into_round_state_progress(self) -> ProgressResult<RoundState> {
		match self {
			ProgressResult::Progress { state } => ProgressResult::Progress { state: state.into() },
			ProgressResult::WaitNewRound => ProgressResult::WaitNewRound,
			ProgressResult::NewRoundStarted(r) => ProgressResult::NewRoundStarted(r),
			ProgressResult::NewAttemptStarted(a) => ProgressResult::NewAttemptStarted(a.into()),
			ProgressResult::Wait(state) => ProgressResult::Wait(state.into()),
		}
	}
}

const ATTEMPT_STARTED: &'static str = "AttemptStarted";
const PAYMENT_SUBMITTED: &'static str = "PaymentSubmitted";
const VTXO_TREE_SIGNED: &'static str = "VtxoTreeSigned";
const FORFEIT_SIGNED: &'static str = "ForfeitSigned";
const PENDING_CONFIRMATION: &'static str = "PendingConfirmation";
const ROUND_CONFIRMED: &'static str = "RoundConfirmed";
const ROUND_ABANDONNED: &'static str = "RoundAbandonned";
const ROUND_CANCELLED: &'static str = "RoundCancelled";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum RoundStateKind {
	/// see [`AttemptStartedState`]
	AttemptStarted,
	/// see [`PaymentSubmittedState`]
	PaymentSubmitted,
	/// see [`VtxoTreeSignedState`]
	VtxoTreeSigned,
	/// see [`ForfeitSignedState`]
	ForfeitSigned,
	/// see [`PendingConfirmationState`]
	PendingConfirmation,
	/// see [`RoundConfirmedState`]
	RoundConfirmed,
	/// see [`RoundAbandonedState`]
	RoundAbandonned,
	/// see [`RoundCancelledState`]
	RoundCancelled,
}

impl RoundStateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::AttemptStarted => ATTEMPT_STARTED,
			Self::PaymentSubmitted => PAYMENT_SUBMITTED,
			Self::VtxoTreeSigned => VTXO_TREE_SIGNED,
			Self::ForfeitSigned => FORFEIT_SIGNED,
			Self::PendingConfirmation => PENDING_CONFIRMATION,
			Self::RoundConfirmed => ROUND_CONFIRMED,
			Self::RoundAbandonned => ROUND_ABANDONNED,
			Self::RoundCancelled => ROUND_CANCELLED,
		}
	}
}

impl fmt::Display for RoundStateKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.as_str())
	}
}

impl FromStr for RoundStateKind {
	type Err = anyhow::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			ATTEMPT_STARTED => Ok(RoundStateKind::AttemptStarted),
			PAYMENT_SUBMITTED => Ok(RoundStateKind::PaymentSubmitted),
			VTXO_TREE_SIGNED => Ok(RoundStateKind::VtxoTreeSigned),
			FORFEIT_SIGNED => Ok(RoundStateKind::ForfeitSigned),
			PENDING_CONFIRMATION => Ok(RoundStateKind::PendingConfirmation),
			ROUND_CONFIRMED => Ok(RoundStateKind::RoundConfirmed),
			ROUND_CANCELLED => Ok(RoundStateKind::RoundCancelled),
			ROUND_ABANDONNED => Ok(RoundStateKind::RoundAbandonned),
			_ => bail!("Invalid RoundStateKind: {}", s),
		}
	}
}

pub enum RoundState {
	/// see [`AttemptStartedState`]
	AttemptStarted(AttemptStartedState),
	/// see [`PaymentSubmittedState`]
	PaymentSubmitted(PaymentSubmittedState),
	/// see [`VtxoTreeSignedState`]
	VtxoTreeSigned(VtxoTreeSignedState),
	/// see [`ForfeitSignedState`]
	ForfeitSigned(ForfeitSignedState),
	/// see [`PendingConfirmationState`]
	PendingConfirmation(PendingConfirmationState),
	/// see [`RoundConfirmedState`]
	RoundConfirmed(RoundConfirmedState),
	/// see [`RoundAbandonedState`]
	RoundAbandoned(RoundAbandonedState),
	/// see [`RoundCancelledState`]
	RoundCancelled(RoundCancelledState),
}

impl RoundState {
	pub fn kind(&self) -> RoundStateKind {
		match &self {
			Self::AttemptStarted(_) => RoundStateKind::AttemptStarted,
			Self::PaymentSubmitted(_) => RoundStateKind::PaymentSubmitted,
			Self::VtxoTreeSigned(_) => RoundStateKind::VtxoTreeSigned,
			Self::ForfeitSigned(_) => RoundStateKind::ForfeitSigned,
			Self::PendingConfirmation(_) => RoundStateKind::PendingConfirmation,
			Self::RoundConfirmed(_) => RoundStateKind::RoundConfirmed,
			Self::RoundAbandoned(_) => RoundStateKind::RoundAbandonned,
			Self::RoundCancelled(_) => RoundStateKind::RoundCancelled,
		}
	}

	pub fn round_attempt_id(&self) -> i64 {
		match self {
			RoundState::AttemptStarted(state) => state.round_attempt_id,
			RoundState::PaymentSubmitted(state) => state.round_attempt_id,
			RoundState::VtxoTreeSigned(state) => state.round_attempt_id,
			RoundState::ForfeitSigned(state) => state.round_attempt_id,
			RoundState::PendingConfirmation(state) => state.round_attempt_id,
			RoundState::RoundConfirmed(state) => state.round_attempt_id,
			RoundState::RoundAbandoned(state) => state.round_attempt_id,
			RoundState::RoundCancelled(state) => state.round_attempt_id,
		}
	}

	pub fn participation(&self) -> Option<&RoundParticipation> {
		match &self {
			RoundState::AttemptStarted(state) => Some(&state.participation),
			RoundState::PaymentSubmitted(state) => Some(&state.participation),
			RoundState::VtxoTreeSigned(state) => Some(&state.participation),
			RoundState::ForfeitSigned(state) => Some(&state.participation),
			RoundState::PendingConfirmation(state) => Some(&state.participation),
			RoundState::RoundConfirmed(_) => None,
			RoundState::RoundAbandoned(_) => None,
			RoundState::RoundCancelled(_) => None,
		}
	}

	pub async fn can_progress(&self) -> bool {
		match self {
			RoundState::AttemptStarted(_) => true,
			RoundState::PaymentSubmitted(_) => true,
			RoundState::VtxoTreeSigned(_) => true,
			RoundState::ForfeitSigned(_) => true,
			RoundState::PendingConfirmation(_) => false,
			RoundState::RoundConfirmed(_) => false,
			RoundState::RoundAbandoned(_) => false,
			RoundState::RoundCancelled(_) => false,
		}
	}

	pub fn into_attempt_started(self) -> Option<AttemptStartedState> {
		match self {
			RoundState::AttemptStarted(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_payment_submitted(self) -> Option<PaymentSubmittedState> {
		match self {
			RoundState::PaymentSubmitted(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_vtxo_tree_signed(self) -> Option<VtxoTreeSignedState> {
		match self {
			RoundState::VtxoTreeSigned(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_forfeit_signed(self) -> Option<ForfeitSignedState> {
		match self {
			RoundState::ForfeitSigned(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_pending_confirmation(self) -> Option<PendingConfirmationState> {
		match self {
			RoundState::PendingConfirmation(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_round_confirmed(self) -> Option<RoundConfirmedState> {
		match self {
			RoundState::RoundConfirmed(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_round_abandoned(self) -> Option<RoundAbandonedState> {
		match self {
			RoundState::RoundAbandoned(state) => Some(state),
			_ => None,
		}
	}

	pub fn into_round_cancelled(self) -> Option<RoundCancelledState> {
		match self {
			RoundState::RoundCancelled(state) => Some(state),
			_ => None,
		}
	}
}

impl From<AttemptStartedState> for RoundState {
	fn from(state: AttemptStartedState) -> Self { RoundState::AttemptStarted(state) }
}

impl From<PaymentSubmittedState> for RoundState {
	fn from(state: PaymentSubmittedState) -> Self { RoundState::PaymentSubmitted(state) }
}

impl From<VtxoTreeSignedState> for RoundState {
	fn from(state: VtxoTreeSignedState) -> Self { RoundState::VtxoTreeSigned(state) }
}

impl From<ForfeitSignedState> for RoundState {
	fn from(state: ForfeitSignedState) -> Self { RoundState::ForfeitSigned(state) }
}

impl From<PendingConfirmationState> for RoundState {
	fn from(state: PendingConfirmationState) -> Self { RoundState::PendingConfirmation(state) }
}

impl From<RoundConfirmedState> for RoundState {
	fn from(state: RoundConfirmedState) -> Self { RoundState::RoundConfirmed(state) }
}

impl From<RoundAbandonedState> for RoundState {
	fn from(state: RoundAbandonedState) -> Self { RoundState::RoundAbandoned(state) }
}

impl From<RoundCancelledState> for RoundState {
	fn from(state: RoundCancelledState) -> Self { RoundState::RoundCancelled(state) }
}

pub struct RoundContext {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
}

pub trait GetRoundContext {
	fn round_context(&self) -> RoundContext;
}

pub trait GetRoundTx {
	fn round_tx(&self) -> &Transaction;
	fn round_txid(&self) -> &RoundId;
}

pub trait GetForfeitedVtxos {
	fn forfeited_vtxos(&self) -> &Vec<VtxoForfeitedInRound>;
}

pub trait ToCancelled: Sized + GetRoundContext + GetRoundTx + GetForfeitedVtxos + Into<RoundState> {
	fn to_cancelled_state(
		self,
		db: &Arc<dyn BarkPersister>,
		double_spend_txid: Txid,
	) -> anyhow::Result<RoundCancelledState> {
		let round_context = self.round_context();

		let state = RoundCancelledState {
			round_attempt_id: round_context.round_attempt_id,
			round_seq: round_context.round_seq,
			attempt_seq: round_context.attempt_seq,
			round_txid: *self.round_txid(),
			forfeited_vtxos: self.forfeited_vtxos().iter().map(|f| VtxoForfeitedInRound {
				vtxo_id: f.vtxo_id,
				round_attempt_id: round_context.round_attempt_id,
				double_spend_txid: Some(double_spend_txid),
			}).collect(),
		};

		Ok(state)
	}
}

/// Trait to restrict transition to `RoundAbandonedState` state for a given round state
pub trait ToAbandoned: Sized + GetRoundContext + Into<RoundState> {
	fn to_abandoned_state(self, db: &Arc<dyn BarkPersister>) -> anyhow::Result<RoundAbandonedState> {
		let round_context = self.round_context();
		let state = RoundAbandonedState { round_attempt_id: round_context.round_attempt_id };

		Ok(state)
	}
}

/// When the Server has started a new attempt
///
/// Can transition to states:
/// - `PaymentSubmittedState`: when payment submission step is over
/// - `AbandonedState`: when client decides to leave the current round
#[derive(Debug)]
pub struct AttemptStartedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
}

impl ToAbandoned for AttemptStartedState {}

impl GetRoundContext for AttemptStartedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
		}
	}
}

/// Each time the client has submitted a new payment request (either
/// after new round start or because of round attempt failure and retry)
///
/// At this point, we have secret nonces stored in the database.
///
/// Can transition to states:
/// - `AttemptStartedState`: when a new round attempt is started
/// - `VtxoTreeSignedState`: when payment submission step is over
/// - `AbandonedState`: when client decides to leave the current round
#[derive(Debug)]
pub struct PaymentSubmittedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
	pub cosign_keys: Vec<Keypair>,
}

impl ToAbandoned for PaymentSubmittedState {}

impl GetRoundContext for PaymentSubmittedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
		}
	}
}

/// When client has submitted VTXO tree signatures to the Ark Server
///
/// Can transition to states:
/// - `AttemptStartedState`: when new round attempt is started (most probably
/// VTXO signatures submission step is over and some participant failed to
///provide them in time
/// - `ForfeitSignedState`: when VTXO signatures submission step is
/// over and all participants submitted
/// - `AbandonedState`: when client decides to leave the current round
#[derive(Debug)]
pub struct VtxoTreeSignedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
	pub unsigned_round_tx: Transaction,
	pub round_txid: RoundId,
	pub vtxo_tree: VtxoTreeSpec,
}

impl ToAbandoned for VtxoTreeSignedState {}

impl GetRoundContext for VtxoTreeSignedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
		}
	}
}

#[derive(Debug, Clone, Deserialize)]
pub struct VtxoForfeitedInRound {
	pub round_attempt_id: i64,
	pub vtxo_id: VtxoId,
	pub double_spend_txid: Option<Txid>,
}

/// When client has submitted forfeit signatures to the Ark Server
///
/// Can transition to states:
/// - `AttemptStartedState`: when new round attempt is started (most probably
/// forfeit signatures submission step is over and some participant failed to
/// provide them in time
/// - `RoundPendingConfirmationState`: when VTXO signatures submission step is
/// over and all participants submitted
/// - `RoundCancelledState`: when the Ark Server decided to invalidate a round,
/// makes input VTXOs valid again
///
/// Note: after forfeit signature, round cannot be left by client anymore
/// Note 2: client should not trust Server invalidation, it needs to remember
/// about it in case the server ever broadcast forfeit of one of the input VTXOs.
/// In that case, round tx would need to be broadcast so payment request should
/// be fulfilled and new VTXO created
#[derive(Debug)]
pub struct ForfeitSignedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
	pub unsigned_round_tx: Transaction,
	pub round_txid: RoundId,
	pub vtxos: Vec<Vtxo>,
	pub forfeited_vtxos: Vec<VtxoForfeitedInRound>,
}

impl GetRoundContext for ForfeitSignedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
		}
	}
}

impl GetRoundTx for ForfeitSignedState {
	fn round_tx(&self) -> &Transaction { &self.unsigned_round_tx }
	fn round_txid(&self) -> &RoundId { &self.round_txid }
}

impl GetForfeitedVtxos for ForfeitSignedState {
	fn forfeited_vtxos(&self) -> &Vec<VtxoForfeitedInRound> { &self.forfeited_vtxos }
}

impl ToCancelled for ForfeitSignedState {}

/// When Ark Server successfully finished the round and provided the
/// funding tx to client but it is not confirmed yet
///
/// Can transition to states:
/// - `RoundConfirmedState`: when funding tx has been confirmed deeply enough.
/// Input VTXO can then be marked as spent and new VTXOs created
/// - `RoundCancelledState`: when the Ark Server decided to invalidate a round,
/// makes input VTXOs valid again
///
/// Note: after forfeit signature, round cannot be left by client anymore
/// Note 2: client should not trust Server invalidation, it needs to remember
/// about it in case the server ever broadcast forfeit of one of the input VTXOs.
/// In that case, round tx would need to be broadcast so payment request should
/// be fulfilled and new VTXO created
#[derive(Debug)]
pub struct PendingConfirmationState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
	pub round_tx: Transaction,
	pub round_txid: RoundId,
	/// Our VTXOs that will be created in the round
	pub vtxos: Vec<Vtxo>,
	/// Forfeits involved in the round
	pub forfeited_vtxos: Vec<VtxoForfeitedInRound>,
}

impl GetRoundContext for PendingConfirmationState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
		}
	}
}

impl GetRoundTx for PendingConfirmationState {
	fn round_tx(&self) -> &Transaction { &self.round_tx }
	fn round_txid(&self) -> &RoundId { &self.round_txid }
}

impl GetForfeitedVtxos for PendingConfirmationState {
	fn forfeited_vtxos(&self) -> &Vec<VtxoForfeitedInRound> { &self.forfeited_vtxos }
}

impl ToCancelled for PendingConfirmationState {}

/// When round's funding tx has been confirmed deeply enough.
///
/// This is a final state.
#[derive(Debug)]
pub struct RoundConfirmedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub round_tx: Transaction,
	pub round_txid: RoundId,
}

/// When round has been left by the client or server, before the forfeit signature
/// step.
///
/// This is a final state.
#[derive(Debug)]
pub struct RoundAbandonedState {
	pub round_attempt_id: i64,
}

/// When round has been cancelled by the Ark Server (after the forfeit signature
/// step).
///
/// This is a final state.
#[derive(Debug)]
pub struct RoundCancelledState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub round_txid: RoundId,
	pub forfeited_vtxos: Vec<VtxoForfeitedInRound>,
}
