//! Round State Machine
//!
//! This module defines the lifecycle of an Ark round as a strongly typed state machine. Each phase
//! of the round is represented by a distinct struct with appropriate data, wrapped in the
//! [RoundState] enum. This design makes transitions explicit and helps ensure only valid
//! operations are performed at each step.
//!
//! ## States
//!
//! The [RoundState] enum enumerates all phases a round can take:
//!
//! - [RoundState::AttemptStarted] → initial attempt context
//! - [RoundState::PaymentSubmitted] → a payment has been submitted
//! - [RoundState::VtxoTreeSigned] → VTXO tree signatures collected
//! - [RoundState::ForfeitSigned] → forfeits recorded
//! - [RoundState::PendingConfirmation] → transaction waiting for onchain confirmation
//! - [RoundState::RoundConfirmed] → round successfully confirmed onchain
//! - [RoundState::RoundAbandoned] → round was intentionally abandoned
//! - [RoundState::RoundCancelled] → round canceled after failures
//!
//! A lightweight [RoundStateKind] enum is also provided for quick discriminant checks or
//! serialization.
//!
//! ## Traits
//!
//! The module defines traits representing *capabilities* available in certain
//! states:
//!
//! - [GetRoundContext] — access round identifiers and participation
//! - [GetRoundTx] — access to the round transaction / txid
//! - [GetForfeitedVtxos] — access to forfeited VTXOs where applicable
//! - [StartNewAttempt] — derive a new [RoundState::AttemptStarted] state
//! - [ToCancelled] — transition to a canceled state
//! - [ToAbandoned] — transition to an abandoned state
//!

use std::iter;
use std::time::Duration;
use std::{collections::HashMap, fmt::{self, Debug}, str::FromStr, sync::Arc};

use anyhow::Context;
use bip39::rand;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use bitcoin::key::Keypair;
use bitcoin::params::Params;
use bitcoin::{Address, Amount, FeeRate, OutPoint, ScriptBuf, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin_ext::{TxStatus, P2TR_DUST};
use futures::Stream;
use log::{debug, error, info, trace, warn};
use tokio_stream::StreamExt;
use tonic::Code;

use ark::{OffboardRequest, ProtocolEncoding, SignedVtxoRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::connectors::ConnectorChain;
use ark::musig::{self, PublicNonce, SecretNonce};
use ark::rounds::{
	RoundEvent, RoundId, RoundInfo, RoundSeq, VtxoOwnershipChallenge, MIN_ROUND_TX_OUTPUTS,
	ROUND_TX_CONNECTOR_VOUT, ROUND_TX_VTXO_TREE_VOUT,
};
use ark::tree::signed::VtxoTreeSpec;
use server_rpc::{protos, ServerConnection};

use crate::persist::models::StoredVtxoRequest;
use crate::{ROUND_DEEPLY_CONFIRMED, SECP, Wallet};
use crate::movement::{MovementArgs, MovementKind};
use crate::onchain::ChainSource;
use crate::persist::BarkPersister;
use crate::vtxo_selection::{FilterVtxos, VtxoFilter};
use crate::vtxo_state::{VtxoState, WalletVtxo};

/// Struct to communicate your desired round participation for an Ark round
#[derive(Debug, Clone)]
pub enum DesiredRoundParticipation {
	/// Inputs are provided, ready to go
	Funded(RoundParticipation),
	/// Making an offboard of specific vtxos
	Offboard {
		vtxos: Vec<Vtxo>,
		destination: ScriptBuf,
	},
	/// Attempting to deliver an onchain payment
	OnchainPayment {
		destination: ScriptBuf,
		amount: Amount,
	},
}

/// Struct to communicate your specific participation for an Ark round.
#[derive(Debug, Clone)]
pub struct RoundParticipation {
	pub inputs: Vec<Vtxo>,
	pub outputs: Vec<StoredVtxoRequest>,
	pub offboards: Vec<OffboardRequest>,
}

/// Unrecoverable errors that can occur during a round attempt. For
/// recoverable/retryable errors, use [AttemptResult::WaitNewRound] instead.
///
/// Errors are categorized based on when they occur in relation to forfeit
/// signature creation.
#[derive(Debug)]
pub enum AttemptError {
	/// Occurs before forfeit signatures are created
	/// and sent to the Ark Server. At this point, input VTXOs are still valid and
	/// can be safely exited since the Ark Server cannot double spend them via a
	/// forfeit transaction. The wallet can safely move on to another round.
	/// Includes a [RoundAbandonedState] to ensure proper round state cleanup.
	BeforeSigningForfeit(RoundAbandonedState),

	/// Occurs after forfeit signatures are created
	/// and sent to the Ark Server. This is a critical error since the Ark Server
	/// now has valid forfeit signatures for the input VTXOs and could broadcast
	/// them at any time, potentially invalidating those VTXOs. The wallet must
	/// cancel the round and take precautions against potential VTXO invalidation.
	AfterSigningForfeit,

	/// Occurs when updating the round state fails.
	DatabaseError(String),

	/// Occurs when the events stream breaks.
	StreamError(anyhow::Error),
}

impl fmt::Display for AttemptError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			AttemptError::BeforeSigningForfeit(abandoned) => {
				write!(f, "An error occured in round attempt before forfeit signature. \
					Round was abandoned: {:?}", abandoned,
				)
			},
			AttemptError::AfterSigningForfeit => {
				write!(f, "An error occured in round attempt after forfeit signature.")
			},
			AttemptError::DatabaseError(msg) => {
				write!(f, "An error occured while updating the round state: {}", msg)
			},
			AttemptError::StreamError(e) => {
				write!(f, "An error occured while processing the events stream: {}", e)
			},
		}
	}
}

impl std::error::Error for AttemptError {}

/// Result of a round attempt.
pub enum AttemptResult {
	/// A new round was started by the server.
	///
	/// Includes the new round info to let caller process it.
	NewRoundStarted(RoundInfo),

	/// The attempt could not be completed and the client should wait for
	/// a new round to be started by the server.
	WaitNewRound,

	/// A new attempt was started by the server, most probably because one of the participants
	/// dropped out during the round.
	///
	/// Includes the updated round state to let caller process it.
	NewAttemptStarted((AttemptStartedState, VtxoOwnershipChallenge)),

	/// The attempt was successfully processed and its transaction is now
	/// pending confirmations. Should be sync regularly to check when movement
	/// can be settled and new vtxos created.
	///
	/// Includes the round result.
	Success(RoundResult),
}

#[derive(Debug)]
pub struct RoundResult {
	pub round_id: RoundId,
}

pub enum ProgressResult<S> {
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

async fn check_round_cancelled<T: ToCancelled>(
	round: &T,
	tip: u32,
	chain: &ChainSource,
) -> anyhow::Result<Option<Txid>> {
	// If any of the round inputs were spent deeply enough, the round tx is not
	// valid anymore and we can safely consider the round cancelled
	let outpoints = round.round_tx().input
		.iter().map(|o| o.previous_output).collect::<Vec<_>>();
	let spent_outpoints = chain.txs_spending_inputs(outpoints, tip).await?;

	let confirmed_round_double_spend = spent_outpoints.map.values().find(|(_, status)| {
		if let TxStatus::Confirmed(block_ref) = status {
			tip - block_ref.height - 1 > ROUND_DEEPLY_CONFIRMED
		} else {
			false
		}
	});

	if let Some((txid, _)) = confirmed_round_double_spend {
		return Ok(Some(*txid));
	}

	Ok(None)
}

const ATTEMPT_STARTED: &'static str = "AttemptStarted";
const PAYMENT_SUBMITTED: &'static str = "PaymentSubmitted";
const VTXO_TREE_SIGNED: &'static str = "VtxoTreeSigned";
const FORFEIT_SIGNED: &'static str = "ForfeitSigned";
const PENDING_CONFIRMATION: &'static str = "PendingConfirmation";
const ROUND_CONFIRMED: &'static str = "RoundConfirmed";
const ROUND_ABANDONNED: &'static str = "RoundAbandonned";
const ROUND_CANCELLED: &'static str = "RoundCancelled";

/// Represents the type of round state.
///
/// This type is a compact, string-friendly discriminator for [`RoundState`].
/// It is useful for serialization, logging, UIs, and matching without
/// carrying the full state payload around.
///
/// See [`RoundState`] for the rich, data-carrying states
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum RoundStateKind {
	/// see [AttemptStartedState]
	AttemptStarted,
	/// see [PaymentSubmittedState]
	PaymentSubmitted,
	/// see [VtxoTreeSignedState]
	VtxoTreeSigned,
	/// see [ForfeitSignedState]
	ForfeitSigned,
	/// see [PendingConfirmationState]
	PendingConfirmation,
	/// see [RoundConfirmedState]
	RoundConfirmed,
	/// see [RoundAbandonedState]
	RoundAbandonned,
	/// see [RoundCancelledState]
	RoundCancelled,
}

impl RoundStateKind {
	/// Returns the canonical stable string for this kind.
	///
	/// The returned value is intended for persistence and interoperability.
	/// Use [`RoundStateKind::from_str`] to parse it back.
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

	/// Formats the kind as its canonical string (same as [`RoundStateKind::as_str`]).
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

/// Full, data-carrying state of a round attempt.
///
/// A round transitions through these states as it progresses with the
/// coordinator and the blockchain. Each variant carries the specific data
/// associated with that phase.
///
/// Use:
/// - [`RoundState::kind`] to get the lightweight discriminator.
/// - `into_*` helpers to downcast into a concrete variant.
/// - [`From`] impls to upcast concrete states into `RoundState`.
pub enum RoundState {
	/// see [AttemptStartedState]
	AttemptStarted(AttemptStartedState),
	/// see [PaymentSubmittedState]
	PaymentSubmitted(PaymentSubmittedState),
	/// see [VtxoTreeSignedState]
	VtxoTreeSigned(VtxoTreeSignedState),
	/// see [ForfeitSignedState]
	ForfeitSigned(ForfeitSignedState),
	/// see [PendingConfirmationState]
	PendingConfirmation(PendingConfirmationState),

	/// see [RoundConfirmedState]
	RoundConfirmed(RoundConfirmedState),
	/// see [RoundAbandonedState]
	RoundAbandoned(RoundAbandonedState),
	/// see [RoundCancelledState]
	RoundCancelled(RoundCancelledState),
}

impl RoundState {
	/// Returns the lightweight discriminator for this state.
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

	/// Returns the unique identifier of this round attempt.
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

	/// Returns the round participation context, if available for this state.
	///
	/// Not all states retain full participation details; `None` indicates the information is not
	/// applicable or no longer carried by this variant.
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

	/// Maybe progress the round state.
	///
	/// If the round state cannot progress, returns [None].
	///
	/// If the round state can progress, it will perform progress and return the progress result.
	pub async fn progress(self,
		event: Option<RoundEvent>,
		srv: &mut ServerConnection,
		wallet: &Wallet,
		challenge: VtxoOwnershipChallenge,
		participation: &RoundParticipation,
	) -> Option<Result<ProgressResult<Self>, AttemptError>> {
		match self {
			RoundState::AttemptStarted(state) => {
				let state = state.progress(srv, wallet, challenge, participation).await
					.map(|r| r.into_round_state_progress());
				Some(state)
			},
			RoundState::PaymentSubmitted(state) => {
				let event = event.expect("must be called with some event");
				let state = state.progress(event, srv, wallet).await
					.map(|r| r.into_round_state_progress());
				Some(state)
			},
			RoundState::VtxoTreeSigned(state) => {
				let event = event.expect("must be called with some event");
				let state = state.progress(event, srv, wallet).await
					.map(|r| r.into_round_state_progress());
				Some(state)
			},
			RoundState::ForfeitSigned(state) => {
				let state = state.progress(event, wallet).await
					.map(|r| r.into_round_state_progress());
				Some(state)
			},
			RoundState::PendingConfirmation(state) => {
				let state = state.progress(wallet).await
					.map(|r| r.into_round_state_progress());
				Some(state)
			},
			RoundState::RoundConfirmed(_) => { None },
			RoundState::RoundAbandoned(_) => { None },
			RoundState::RoundCancelled(_) => { None },
		}
	}

	/// Converts this state into [AttemptStartedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_attempt_started(self) -> Option<AttemptStartedState> {
		match self {
			RoundState::AttemptStarted(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [PaymentSubmittedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_payment_submitted(self) -> Option<PaymentSubmittedState> {
		match self {
			RoundState::PaymentSubmitted(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [VtxoTreeSignedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_vtxo_tree_signed(self) -> Option<VtxoTreeSignedState> {
		match self {
			RoundState::VtxoTreeSigned(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [ForfeitSignedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_forfeit_signed(self) -> Option<ForfeitSignedState> {
		match self {
			RoundState::ForfeitSigned(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [PendingConfirmationState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_pending_confirmation(self) -> Option<PendingConfirmationState> {
		match self {
			RoundState::PendingConfirmation(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [RoundConfirmedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_round_confirmed(self) -> Option<RoundConfirmedState> {
		match self {
			RoundState::RoundConfirmed(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [RoundAbandonedState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
	pub fn into_round_abandoned(self) -> Option<RoundAbandonedState> {
		match self {
			RoundState::RoundAbandoned(state) => Some(state),
			_ => None,
		}
	}

	/// Converts this state into [RoundCancelledState] if it matches that variant.
	///
	/// Returns `None` if the current variant is different.
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
	pub round_seq: Option<RoundSeq>,
	pub attempt_seq: Option<usize>,
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

/// Trait to restrict transition to [AttemptStartedState] state for a given round state
pub trait StartNewAttempt: Sized + GetRoundContext + Into<RoundState> {
	fn start_new_attempt(
		self,
		db: &Arc<dyn BarkPersister>,
		attempt_seq: usize,
	) -> anyhow::Result<AttemptStartedState> {
		let round_context = self.round_context();

		db.store_round_state(RoundState::RoundAbandoned(RoundAbandonedState {
			round_attempt_id: round_context.round_attempt_id,
		}), self.into())?;

		Ok(db.store_new_round_attempt(
			round_context.round_seq.expect("round seq should be present"),
			attempt_seq,
			round_context.participation.clone())?)
	}
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

		let updated = db.store_round_state(RoundState::RoundCancelled(state), self.into())?;
		Ok(updated.into_round_cancelled().expect("we just update to cancelled state"))
	}
}

/// Trait to restrict transition to [RoundAbandonedState] state for a given round state
pub trait ToAbandoned: Sized + GetRoundContext + Into<RoundState> {
	fn to_abandoned_state(self, db: &Arc<dyn BarkPersister>) -> anyhow::Result<RoundAbandonedState> {
		let round_context = self.round_context();
		let state = RoundAbandonedState { round_attempt_id: round_context.round_attempt_id };
		db.take_secret_nonces(round_context.round_attempt_id)?;
		let updated = db.store_round_state(RoundState::RoundAbandoned(state), self.into())?;
		Ok(updated.into_round_abandoned().expect("we just update to abandoned state"))
	}
}

/// When the Server has started a new attempt
///
/// Can transition to states:
/// - [PaymentSubmittedState]: when payment submission step is over
/// - [RoundAbandonedState]: when client decides to leave the current round
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
			round_seq: Some(self.round_seq),
			attempt_seq: Some(self.attempt_seq),
			participation: self.participation.clone(),
		}
	}
}

/// Should be called when an error occurs before forfeiting.
///
/// This will transition the round to the [RoundAbandonedState] state.
pub  fn error_before_forfeit<Rst: ToAbandoned>(
	db: &Arc<dyn BarkPersister>,
	round_state: Rst,
) -> AttemptError {
	match round_state.to_abandoned_state(db) {
		Ok(r) => AttemptError::BeforeSigningForfeit(r),
		Err(e) => {
			error!("DB error when trying to transition round to Abandoned: {}", e);
			AttemptError::DatabaseError(e.to_string())
		}
	}
}

impl AttemptStartedState {
	pub async fn progress<'a>(
		self,
		srv: &'a mut ServerConnection,
		wallet: &'a Wallet,
		challenge: VtxoOwnershipChallenge,
		participation: &'a RoundParticipation,
	) -> anyhow::Result<ProgressResult<PaymentSubmittedState>, AttemptError> {
		// Assign cosign pubkeys to the payment requests.
		let cosign_keys = iter::repeat_with(|| Keypair::new(&SECP, &mut rand::thread_rng()))
			.take(participation.outputs.len())
			.collect::<Vec<_>>();
		let vtxo_reqs = participation.outputs.iter().zip(cosign_keys.iter()).map(|(p, ck)| {
			SignedVtxoRequest { vtxo: p.to_vtxo_request(), cosign_pubkey: Some(ck.public_key()) }
		}).collect::<Vec<_>>();

		// Prepare round participation info.
		// For each of our requested vtxo output, we need a set of public and secret nonces.
		let cosign_nonces = cosign_keys.iter()
			.map(|key| {
				let mut secs = Vec::with_capacity(srv.info.nb_round_nonces);
				let mut pubs = Vec::with_capacity(srv.info.nb_round_nonces);
				for _ in 0..srv.info.nb_round_nonces {
					let (s, p) = musig::nonce_pair(key);
					secs.push(s);
					pubs.push(p);
				}
				(secs, pubs)
			})
			.take(vtxo_reqs.len())
			.collect::<Vec<(Vec<SecretNonce>, Vec<PublicNonce>)>>();

		// The round has now started. We can submit our payment.
		debug!("Submitting payment request with {} inputs, {} vtxo outputs and {} offboard outputs",
			participation.inputs.len(), vtxo_reqs.len(), participation.offboards.len(),
		);

		let res = srv.client.submit_payment(protos::SubmitPaymentRequest {
			input_vtxos: participation.inputs.iter().map(|vtxo| {
				let keypair = wallet.get_vtxo_key(&vtxo)
					.expect("owned vtxo key should be in database");

				protos::InputVtxo {
					vtxo_id: vtxo.id().to_bytes().to_vec(),
					ownership_proof: {
						let sig = challenge
							.sign_with(vtxo.id(), &vtxo_reqs, &participation.offboards, keypair);
						sig.serialize().to_vec()
					},
				}
			}).collect(),
			vtxo_requests: vtxo_reqs.iter().zip(cosign_nonces.iter()).map(|(r, n)| {
				protos::SignedVtxoRequest {
					vtxo: Some(protos::VtxoRequest {
						amount: r.vtxo.amount.to_sat(),
						policy: r.vtxo.policy.serialize(),
					}),
					cosign_pubkey: r.cosign_pubkey.expect("just set").serialize().to_vec(),
					public_nonces: n.1.iter().map(|n| n.serialize().to_vec()).collect(),
				}
			}).collect(),
			offboard_requests: participation.offboards.iter().map(|r| {
				protos::OffboardRequest {
					amount: r.amount.to_sat(),
					offboard_spk: r.script_pubkey.to_bytes(),
				}
			}).collect(),
		}).await;

		if let Err(e) = res {
			// TODO: maybe make this more robust
			if [Code::InvalidArgument, Code::NotFound].contains(&e.code()) {
				error!("Ark Server refused our payment submission, leaving round: {}", e);
				return Err(error_before_forfeit(&wallet.db, self));
			} else {
				error!("Could not submit payment, trying next round: {}", e);
				return Ok(ProgressResult::WaitNewRound);
			}
		}

		let state = PaymentSubmittedState {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: participation.clone(),
			cosign_keys,
		};

		let secret_nonces = cosign_nonces.into_iter().map(|(sec, _pub)| sec).collect();
		wallet.db.store_secret_nonces(self.round_attempt_id, secret_nonces)
			.map_err(|e| AttemptError::DatabaseError(e.to_string()))?;

		let state = RoundState::PaymentSubmitted(state);
		let state = match wallet.db.store_round_state(state, self.into()) {
			Ok(state) => state.into_payment_submitted()
				.expect("we just updated to payment submitted state"),
			Err(e) => {
				error!("Could not store payment submitted state: {}", e);
				return Err(AttemptError::DatabaseError(e.to_string()));
			}
		};

		Ok(ProgressResult::Progress { state })
	}
}

/// Each time the client has submitted a new payment request (either
/// after new round start or because of round attempt failure and retry)
///
/// At this point, we have secret nonces stored in the database.
///
/// Can transition to states:
/// - [AttemptStartedState]: when a new round attempt is started
/// - [VtxoTreeSignedState]: when payment submission step is over
/// - [RoundAbandonedState]: when client decides to leave the current round
#[derive(Debug)]
pub struct PaymentSubmittedState {
	pub round_attempt_id: i64,
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub participation: RoundParticipation,
	pub cosign_keys: Vec<Keypair>,
}

impl StartNewAttempt for PaymentSubmittedState {}
impl ToAbandoned for PaymentSubmittedState {}

impl GetRoundContext for PaymentSubmittedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: Some(self.round_seq),
			attempt_seq: Some(self.attempt_seq),
			participation: self.participation.clone(),
		}
	}
}

impl PaymentSubmittedState {
	pub async fn progress<'a>(
		self,
		event: RoundEvent,
		srv: &'a mut ServerConnection,
		wallet: &'a Wallet,
	) -> anyhow::Result<ProgressResult<VtxoTreeSignedState>, AttemptError> {
		let (vtxo_tree, unsigned_round_tx, cosign_agg_nonces) = {
			match event {
				RoundEvent::VtxoProposal {
					round_seq,
					unsigned_round_tx,
					vtxos_spec,
					cosign_agg_nonces,
					..
				} => {
					if round_seq != self.round_seq {
						warn!("Unexpected different round id");
						return Ok(ProgressResult::WaitNewRound);
					}
					(vtxos_spec, unsigned_round_tx, cosign_agg_nonces)
				},
				RoundEvent::Start(round_info) => {
					return Ok(ProgressResult::NewRoundStarted(round_info));
				},
				RoundEvent::Attempt(attempt) if attempt.round_seq == self.round_seq => {
					let state = self.start_new_attempt(&wallet.db, attempt.attempt_seq)
						.map_err(|e| {
							error!("Could not store attempt started state: {}", e);
							AttemptError::DatabaseError(e.to_string())
						})?;
					return Ok(ProgressResult::NewAttemptStarted((state, attempt.challenge)))
				},
				other => {
					warn!("Unexpected message, waiting for new round: {:?}", other);
					return Ok(ProgressResult::WaitNewRound);
				}
			}
		};

		if unsigned_round_tx.output.len() < MIN_ROUND_TX_OUTPUTS {
			error!("server sent round tx with less than 2 outputs: {}", serialize_hex(&unsigned_round_tx));
			return Err(error_before_forfeit(&wallet.db, self));
		}

		let vtxos_utxo = OutPoint::new(unsigned_round_tx.compute_txid(), ROUND_TX_VTXO_TREE_VOUT);

		let my_vtxos = self.participation.outputs.iter().zip(self.cosign_keys.iter())
			.map(|(r, k)| SignedVtxoRequest {
				vtxo: VtxoRequest {
					amount: r.amount,
					policy: r.request_policy.clone(),
				},
				cosign_pubkey: Some(k.public_key()),
			})
			.collect::<Vec<_>>();

		// Check that the proposal contains our inputs.
		{
			let mut my_vtxos = self.participation.outputs.clone();
			for vtxo_req in vtxo_tree.iter_vtxos() {
				if let Some(i) = my_vtxos.iter().position(|v| {
					v.request_policy == vtxo_req.vtxo.policy && v.amount == vtxo_req.vtxo.amount
				}) {
					my_vtxos.swap_remove(i);
				}
			}
			if !my_vtxos.is_empty() {
				error!("server didn't include all of our vtxos, missing: {:?}", my_vtxos);
				return Ok(ProgressResult::WaitNewRound);
			}

			let mut my_offbs = self.participation.offboards.to_vec();
			for offb in unsigned_round_tx.output.iter().skip(2) {
				if let Some(i) = my_offbs.iter().position(|o| o.to_txout() == *offb) {
					my_offbs.swap_remove(i);
				}
			}
			if !my_offbs.is_empty() {
				error!("server didn't include all of our offboards, missing: {:?}", my_offbs);
				return Ok(ProgressResult::WaitNewRound);
			}
		}

		let secret_nonces = wallet.db.take_secret_nonces(self.round_attempt_id)
			.map_err(|e| AttemptError::DatabaseError(e.to_string()))?;

		let secret_nonces = match secret_nonces {
			Some(secret_nonces) => secret_nonces,
			None => {
				warn!("No cosign nonces found, abandoning round");
				return Err(error_before_forfeit(&wallet.db, self));
			}
		};

		// Make vtxo signatures from top to bottom, just like sighashes are returned.
		let unsigned_vtxos = vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);
		for ((req, key), sec) in my_vtxos.iter().zip(&self.cosign_keys).zip(secret_nonces) {
			let leaf_idx = unsigned_vtxos.spec.leaf_idx_of(req).expect("req included");
			let part_sigs_res = unsigned_vtxos.cosign_branch(
				&cosign_agg_nonces, leaf_idx, key, sec,
			).context("failed to cosign branch: our request not part of tree");

			match part_sigs_res {
				Ok(part_sigs) => {
					info!("Sending {} partial vtxo cosign signatures for pk {}",
						part_sigs.len(), key.public_key(),
					);

					let res = srv.client.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
						pubkey: key.public_key().serialize().to_vec(),
						signatures: part_sigs.iter().map(|s| s.serialize().to_vec()).collect(),
					}).await;

					if let Err(e) = res {
						error!("An error occured when providing vtxo signatures: {}", e);
						return Err(error_before_forfeit(&wallet.db, self));
					}
				},
				Err(e) => {
					error!("Could not cosign branch: {}", e);
					return Err(error_before_forfeit(&wallet.db, self));
				}
			}
		}

		let state = VtxoTreeSignedState {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
			unsigned_round_tx: unsigned_round_tx.clone(),
			round_txid: RoundId::from(unsigned_round_tx.compute_txid()),
			vtxo_tree: vtxo_tree,
		};

		let state = RoundState::VtxoTreeSigned(state);
		let state = match wallet.db.store_round_state(state, self.into()) {
			Ok(state) => state.into_vtxo_tree_signed()
				.expect("we just update to vtxo tree signed state"),
			Err(e) => {
				error!("Could not store vtxo tree signed state: {}", e);
				return Err(AttemptError::DatabaseError(e.to_string()));
			}
		};

		Ok(ProgressResult::Progress { state })
	}
}

/// When client has submitted VTXO tree signatures to the Ark Server
///
/// Can transition to states:
/// - [AttemptStartedState]: when new round attempt is started (most probably
/// VTXO signatures submission step is over and some participant failed to
///provide them in time
/// - [ForfeitSignedState]: when VTXO signatures submission step is
/// over and all participants submitted
/// - [RoundAbandonedState]: when client decides to leave the current round
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

impl StartNewAttempt for VtxoTreeSignedState {}
impl ToAbandoned for VtxoTreeSignedState {}

impl GetRoundContext for VtxoTreeSignedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: Some(self.round_seq),
			attempt_seq: Some(self.attempt_seq),
			participation: self.participation.clone(),
		}
	}
}

impl VtxoTreeSignedState {
	pub async fn progress<'a>(
		self,
		event: RoundEvent,
		srv: &'a mut ServerConnection,
		wallet: &'a Wallet) -> anyhow::Result<ProgressResult<ForfeitSignedState>, AttemptError>
	{
		let (vtxo_cosign_sigs, forfeit_nonces, connector_pubkey) = {
			match event {
				RoundEvent::RoundProposal { round_seq, cosign_sigs, forfeit_nonces, connector_pubkey, .. } => {
					if round_seq != self.round_seq {
						warn!("Unexpected different round id");
						return Ok(ProgressResult::WaitNewRound);
					}
					(cosign_sigs, forfeit_nonces, connector_pubkey)
				},
				RoundEvent::Start(e) => {
					return Ok(ProgressResult::NewRoundStarted(e));
				},
				RoundEvent::Attempt(attempt) if attempt.round_seq == self.round_seq => {
					let state = self.start_new_attempt(&wallet.db, attempt.attempt_seq)
						.map_err(|e| {
							warn!("Could not store attempt started state: {}", e);
							AttemptError::DatabaseError(e.to_string())
						})?;
					return Ok(ProgressResult::NewAttemptStarted((state, attempt.challenge)))
				},
				other => {
					warn!("Unexpected message, waiting for new round: {:?}", other);
					return Ok(ProgressResult::WaitNewRound);
				}
			}
		};

		let round_txid = self.unsigned_round_tx.compute_txid();
		let vtxos_utxo = OutPoint::new(round_txid, ROUND_TX_VTXO_TREE_VOUT);

		let vtxo_tree = self.vtxo_tree.clone().into_unsigned_tree(vtxos_utxo);

		// Validate the vtxo tree.
		if vtxo_tree.verify_cosign_sigs(&vtxo_cosign_sigs).is_err() {
			error!("Received incorrect vtxo cosign signatures from server");
			return Err(error_before_forfeit(&wallet.db, self));
		}

		let signed_vtxos = vtxo_tree.clone().into_signed_tree(vtxo_cosign_sigs);

		// Check that the connector key is correct.
		let conn_txout = self.unsigned_round_tx.output.get(ROUND_TX_CONNECTOR_VOUT as usize)
			.expect("checked before");
		let expected_conn_txout = ConnectorChain::output(forfeit_nonces.len(), connector_pubkey);
		if *conn_txout != expected_conn_txout {
			error!("round tx from server has unexpected connector output: {:?} (expected {:?})",
				conn_txout, expected_conn_txout,
			);
			return Err(error_before_forfeit(&wallet.db, self));
		}

		let conns_utxo = OutPoint::new(
			self.unsigned_round_tx.compute_txid(),
			ROUND_TX_CONNECTOR_VOUT,
		);

		// Make forfeit signatures.
		let connectors = ConnectorChain::new(
			forfeit_nonces.values().next().unwrap().len(),
			conns_utxo,
			connector_pubkey,
		);

		let mut forfeited_vtxos = vec![];
		let forfeit_sigs_res = self.participation.inputs.iter().map(|vtxo| {
			let keypair = wallet.get_vtxo_key(&vtxo)?;

			let sigs = connectors.connectors().enumerate().map(|(i, (conn, _))| {
				let (sighash, _tx) = ark::forfeit::forfeit_sighash_exit(
					vtxo, conn, connector_pubkey,
				);
				let srv_nonce = forfeit_nonces.get(&vtxo.id())
					.with_context(|| format!("missing srv forfeit nonce for {}", vtxo.id()))?
					.get(i)
					.context("srv didn't provide enough forfeit nonces")?;

				let (nonce, sig) = musig::deterministic_partial_sign(
					&keypair,
					[srv.info.server_pubkey],
					&[srv_nonce],
					sighash.to_byte_array(),
					Some(vtxo.output_taproot().tap_tweak().to_byte_array()),
				);
				Ok((nonce, sig))
			}).collect::<anyhow::Result<Vec<_>>>()?;

			forfeited_vtxos.push(VtxoForfeitedInRound {
				round_attempt_id: self.round_attempt_id,
				vtxo_id: vtxo.id(),
				double_spend_txid: None,
			});

			Ok((vtxo.id(), sigs))
		}).collect::<anyhow::Result<HashMap<_, _>>>();

		let forfeit_sigs = match forfeit_sigs_res {
			Ok(sigs) => sigs,
			Err(e) => {
				error!("An error occured when signing forfeits. {}", e);
				return Err(error_before_forfeit(&wallet.db, self));
			}
		};

		let signed_vtxos = signed_vtxos.into_cached_tree();

		let mut new_vtxos = vec![];
		for (idx, req) in signed_vtxos.spec.spec.vtxos.iter().enumerate() {
			let req = self.participation.outputs.iter().find(|p| p.to_vtxo_request() == req.vtxo);
			if req.is_some() {
				let vtxo = wallet.build_vtxo(&signed_vtxos, idx).map_err(|e| {
					error!("Error building vtxo: {}", e);
					AttemptError::AfterSigningForfeit
				})?.expect("must be in tree");

				// validate the received vtxos
				// This is more like a sanity check since we crafted them ourselves.
				vtxo.validate(&self.unsigned_round_tx).map_err(|e| {
					error!("Built invalid vtxo: {}", e);
					AttemptError::AfterSigningForfeit
				})?;

				info!("New VTXO from round: {} ({}, {})",
					vtxo.id(), vtxo.amount(), vtxo.policy_type(),
				);

				new_vtxos.push(vtxo);
			}
		}

		let state = ForfeitSignedState {
			round_attempt_id: self.round_attempt_id,
			round_seq: self.round_seq,
			attempt_seq: self.attempt_seq,
			participation: self.participation.clone(),
			vtxos: new_vtxos,
			forfeited_vtxos,
			unsigned_round_tx: self.unsigned_round_tx.clone(),
			round_txid: RoundId::from(self.unsigned_round_tx.compute_txid()),
		};

		// NB: we store ForfeitSignedState first, so that if server doesn't respond
		// on sigs send, we still have the correct state in the DB.
		let state = RoundState::ForfeitSigned(state);
		let state = match wallet.db.store_round_state(state, self.into()) {
			Ok(state) => state.into_forfeit_signed()
				.expect("we just updated to forfeit signed state"),
			Err(e) => {
				error!("Could not store forfeit signed state: {}", e);
				return Err(AttemptError::DatabaseError(e.to_string()));
			}
		};

		debug!("Sending {} sets of forfeit signatures for our inputs", forfeit_sigs.len());
		let res = srv.client.provide_forfeit_signatures(protos::ForfeitSignaturesRequest {
			signatures: forfeit_sigs.into_iter().map(|(id, sigs)| {
				protos::ForfeitSignatures {
					input_vtxo_id: id.to_bytes().to_vec(),
					pub_nonces: sigs.iter().map(|s| s.0.serialize().to_vec()).collect(),
					signatures: sigs.iter().map(|s| s.1.serialize().to_vec()).collect(),
				}
			}).collect(),
		}).await;

		if let Err(e) = res {
			error!("Could not provide forfeit signatures, trying next round: {}", e);
			return Ok(ProgressResult::WaitNewRound);
		}

		Ok(ProgressResult::Progress { state })
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
/// - [AttemptStartedState]: when new round attempt is started (most probably
/// forfeit signatures submission step is over and some participant failed to
/// provide them in time
/// - [PendingConfirmationState]: when VTXO signatures submission step is
/// over and all participants submitted
/// - [RoundCancelledState]: when the Ark Server decided to invalidate a round,
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

impl StartNewAttempt for ForfeitSignedState {}
impl GetRoundContext for ForfeitSignedState {
	fn round_context(&self) -> RoundContext {
		RoundContext {
			round_attempt_id: self.round_attempt_id,
			round_seq: Some(self.round_seq),
			attempt_seq: Some(self.attempt_seq),
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

impl ForfeitSignedState {
	/// Transition to [PendingConfirmationState] state
	///
	/// Note: this consumes the previous [StatefulRound] to make sure we always
	/// deal with latest stored data
	fn to_pending_confirmation(
		self,
		db: &Arc<dyn BarkPersister>,
		round_tx: Transaction,
		vtxos: Vec<Vtxo>,
	) -> anyhow::Result<PendingConfirmationState> {
		debug_assert_eq!(self.round_txid, RoundId::from(round_tx.compute_txid()));
		let state = PendingConfirmationState {
			round_attempt_id: self.round_attempt_id,
			round_seq: Some(self.round_seq),
			attempt_seq: Some(self.attempt_seq),
			participation: self.participation.clone(),
			forfeited_vtxos: self.forfeited_vtxos.clone(),
			round_txid: self.round_txid,
			round_tx,
			vtxos,
		};

		let state = db.store_round_state(RoundState::PendingConfirmation(state), self.into())?;
		Ok(state.into_pending_confirmation().expect("we just update to pending confirmation state"))
	}

	pub async fn progress<'a>(self, event: Option<RoundEvent>, wallet: &'a Wallet)
		-> Result<ProgressResult<RoundState>, AttemptError>
	{
		// If the tx is seen onchain or in the mempool, we can transition to pending confirmation
		if let Ok(Some(tx)) = wallet.chain.get_tx(&self.round_txid).await {
			let vtxos = self.vtxos.clone();
			let state = self.to_pending_confirmation(&wallet.db, tx, vtxos)
				.map_err(|e| {
					error!("DB error when trying to transition round to \
						PendingConfirmationState: {}", e,
					);
					AttemptError::DatabaseError(e.to_string())
				})?;
			return Ok(ProgressResult::Progress { state: state.into() });
		} else {
			let tip = wallet.chain.tip().await.map_err(|e| {
				error!("Could not get tip: {}", e);
				AttemptError::StreamError(e)
			})?;

			let round_context = self.round_context();
			if let Ok(Some(txid)) = check_round_cancelled(&self, tip, &wallet.chain).await {
				info!("Round {} has been cancelled before broadcast", self.round_seq);
				let state = self.to_cancelled_state(&wallet.db, txid)
					.map_err(|e| {
						error!("DB error when trying to transition round to \
							RoundCancelledState: {}", e,
						);
						AttemptError::DatabaseError(e.to_string())
					})?;

				return Ok(ProgressResult::Progress { state: state.into() });
			} else {
				trace!("Round {} for which forfeit were signed is still not confirmed nor cancelled.",
					round_context.round_attempt_id,
				);
			}
		}

		let signed_round_tx = match event {
			Some(RoundEvent::Finished { round_seq, signed_round_tx, .. }) => {
				if round_seq != self.round_seq {
					error!("Unexpected round ID from round finished event: {} != {}",
						round_seq, self.round_seq);
				}
				signed_round_tx
			},
			Some(RoundEvent::Start(round_info)) => {
				return Ok(ProgressResult::NewRoundStarted(round_info));
			},
			Some(RoundEvent::Attempt(attempt)) if attempt.round_seq == self.round_seq => {
				let state = self.start_new_attempt(&wallet.db, attempt.attempt_seq)
					.map_err(|e| {
						error!("Could not store attempt started state: {}", e);
						AttemptError::DatabaseError(e.to_string())
					})?;
				return Ok(ProgressResult::NewAttemptStarted((state, attempt.challenge)));
			},
			None => {
				error!("Expected one last event once forfeits are signed if round is not seen onchain");
				return Err(AttemptError::AfterSigningForfeit);
			},
			other => {
				error!("Unexpected message, waiting for new round: {:?}", other);
				return Err(AttemptError::AfterSigningForfeit);
			}
		};

		if signed_round_tx.compute_txid() != self.unsigned_round_tx.compute_txid() {
			error!("srv changed the round transaction during the round!");
			error!("unsigned tx: {}", serialize_hex(&self.unsigned_round_tx));
			error!("signed tx: {}", serialize_hex(&signed_round_tx));
			error!("unsigned and signed round txids don't match");
			return Err(AttemptError::AfterSigningForfeit);
		}

		// We also broadcast the tx, just to have it go around faster.
		info!("Broadcasting round tx {}", signed_round_tx.compute_txid());
		if let Err(e) = wallet.chain.broadcast_tx(&signed_round_tx).await {
			error!("Couldn't broadcast round tx: {}", e);
		}

		let vtxos = self.vtxos.clone();

		let state = self.to_pending_confirmation(&wallet.db, signed_round_tx.clone(), vtxos)
			.map_err(|e| {
				error!("DB error when trying to transition round to PendingConfirmationState: {}", e);
				AttemptError::DatabaseError(e.to_string())
			})?;

		Ok(ProgressResult::Progress { state: state.into() })
	}
}

/// When Ark Server successfully finished the round and provided the
/// funding tx to client but it is not confirmed yet
///
/// Can transition to states:
/// - [RoundConfirmedState]: when funding tx has been confirmed deeply enough.
/// Input VTXO can then be marked as spent and new VTXOs created
/// - [RoundCancelledState]: when the Ark Server decided to invalidate a round,
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
	pub round_seq: Option<RoundSeq>,
	pub attempt_seq: Option<usize>,
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

impl PendingConfirmationState {
	/// Check if the round pending confirmation state is confirmed
	/// If so, register the movement and transition to confirmed state
	/// If not, rebroadcast the tx and wait for confirmation
	pub async fn progress<'a>(self, wallet: &'a Wallet)
		-> Result<ProgressResult<RoundState>, AttemptError>
	{
		let params = Params::new(wallet.properties().unwrap().network);
		let round_tx = self.round_tx.clone();


		let tip = wallet.chain.tip().await.map_err(|e| {
			error!("Could not get tip: {}", e);
			AttemptError::StreamError(e)
		})?;

		let confirmed_in = wallet.chain.tx_confirmed(round_tx.compute_txid()).await;
		if let Ok(Some(confirmed_in)) = confirmed_in {
			let confs = tip - (confirmed_in - 1);
			if confs >= ROUND_DEEPLY_CONFIRMED {
				let vtxos = wallet.db.get_in_round_vtxos().map_err(|e| {
					error!("DB error when trying to get in round vtxos: {}", e);
					AttemptError::DatabaseError(e.to_string())
				})?;

				let input_ids = self.forfeited_vtxos.iter()
					.map(|f| f.vtxo_id).collect::<Vec<_>>();
				let filter = VtxoFilter::new(wallet).include_many(input_ids);
				let inputs = filter.filter(vtxos).map_err(|e| {
					error!("DB error when trying to get filtered vtxos: {}", e);
					AttemptError::DatabaseError(e.to_string())
				})?;

				debug_assert_eq!(inputs.len(), self.forfeited_vtxos.len());

				// Finally we save state after refresh
				let vtxos = self.vtxos.clone().into_iter().map(|vtxo| {
					let req = self.participation.outputs.iter()
						.find(|p| &p.request_policy == vtxo.policy() && p.amount == vtxo.amount());
					// If the vtxo is not in the payment requests, we default to spendable
					let state = req.map(|r| r.state.clone()).unwrap_or(VtxoState::Spendable);
					WalletVtxo { vtxo, state }
				}).collect::<Vec<_>>();

				let sent = self.participation.offboards.iter().map(|o| {
					let address = Address::from_script(&o.script_pubkey, &params)
						.expect("script should be valid here");
					(address.to_string(), o.amount)
				}).collect::<Vec<_>>();

				debug_assert_eq!(self.round_txid, RoundId::from(round_tx.compute_txid()));
				let state = RoundConfirmedState {
					round_attempt_id: self.round_attempt_id,
					round_tx,
					attempt_seq: self.attempt_seq,
					round_seq: self.round_seq,
					round_txid: self.round_txid,
				};
				let state = RoundState::RoundConfirmed(state);
				let state = wallet.db.store_round_state(state, self.into()).map_err(|e| {
					error!("DB error when trying to store round confirmed state: {}", e);
					AttemptError::DatabaseError(e.to_string())
				})?;

				let register_res = wallet.db.register_movement(MovementArgs {
					kind: MovementKind::Round,
					spends: &inputs.iter().map(|v| &v.vtxo).collect::<Vec<_>>(),
					receives: &vtxos.iter()
						.map(|v| (&v.vtxo, v.state.clone()))
						.collect::<Vec<_>>(),
					recipients: &sent.iter()
						.map(|(addr, amt)| (addr.as_str(), *amt))
						.collect::<Vec<_>>(),
					fees: None
				}).context("failed to store OOR vtxo");

				if let Err(e) = register_res {
					error!("Failed to store VTXOs received in round: {}", e);
				}

				return Ok(ProgressResult::Progress { state });
			}
		}

		if let Ok(Some(txid)) = check_round_cancelled(&self, tip, &wallet.chain).await {
			info!("Round {} has been cancelled after broadcast", self.round_attempt_id);
			let state = self.to_cancelled_state(&wallet.db, txid)
				.map_err(|e| {
					error!("DB error when trying to transition round to RoundCancelledState: {}", e);
					AttemptError::DatabaseError(e.to_string())
				})?;

			return Ok(ProgressResult::Progress { state: state.into() });
		}

		// Rebroadcast the tx to help confirm
		if let Err(e) = wallet.chain.broadcast_tx(&round_tx).await {
			error!("Couldn't re-broadcast round tx: {}", e);
		};

		// TODO: after some point, if the round tx is still not confirmed, we might want to ask
		// srv to cancel the round

		Ok(ProgressResult::Wait(self.into()))
	}

}

/// When round's funding tx has been confirmed deeply enough.
///
/// This is a final state.
#[derive(Debug)]
pub struct RoundConfirmedState {
	pub round_attempt_id: i64,
	pub round_seq: Option<RoundSeq>,
	pub attempt_seq: Option<usize>,
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
	pub round_seq: Option<RoundSeq>,
	pub attempt_seq: Option<usize>,
	pub round_txid: RoundId,
	pub forfeited_vtxos: Vec<VtxoForfeitedInRound>,
}

impl Wallet {
	fn fund_round(
		&self,
		desired: &DesiredRoundParticipation,
		offboard_feerate: FeeRate,
	) -> anyhow::Result<RoundParticipation> {
		match desired {
			DesiredRoundParticipation::Funded(p) => Ok(p.clone()),
			DesiredRoundParticipation::Offboard { vtxos, destination } => {
				let fee = OffboardRequest::calculate_fee(&destination, offboard_feerate)
					.expect("bdk created invalid scriptPubkey");

				let vtxo_sum = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

				if fee > vtxo_sum {
					bail!("offboarded amount is lower than fees. Need {fee}, got: {vtxo_sum}");
				}

				let offb = OffboardRequest {
					amount: vtxo_sum - fee,
					script_pubkey: destination.clone(),
				};

				Ok(RoundParticipation {
					inputs: vtxos.clone(),
					outputs: Vec::new(),
					offboards: vec![offb],
				})
			},
			DesiredRoundParticipation::OnchainPayment { destination, amount } => {
				let offb = OffboardRequest {
					script_pubkey: destination.clone(),
					amount: *amount,
				};

				let spent_amount = offb.amount + offb.fee(offboard_feerate)?;
				let input_vtxos = self.select_vtxos_to_cover(spent_amount, None, None)?;

				let in_sum = input_vtxos.iter().map(|v| v.amount()).sum::<Amount>();

				let change = {
					if in_sum < offb.amount {
						// unreachable, because we checked for enough balance above
						bail!("Balance too low");
					} else if in_sum <= spent_amount + P2TR_DUST {
						info!("No change, emptying wallet.");
						None
					} else {
						let change_amount = in_sum - spent_amount;
						let (change_keypair, _) = self.derive_store_next_keypair()?;
						info!("Adding change vtxo for {}", change_amount);
						Some(VtxoRequest {
							amount: change_amount,
							policy: VtxoPolicy::new_pubkey(change_keypair.public_key()),
						})
					}
				};

				Ok(RoundParticipation {
					inputs: input_vtxos.clone(),
					outputs: change.into_iter()
						.map(|c| StoredVtxoRequest::from_parts(c, VtxoState::Spendable)).collect(),
					offboards: vec![offb],
				})
			},
		}
	}

	async fn new_round_attempt<S: Stream<Item = anyhow::Result<RoundEvent>> + Unpin>(
		&self,
		events: &mut S,
		challenge: VtxoOwnershipChallenge,
		round_state: AttemptStartedState,
		participation: &RoundParticipation,
	) -> Result<AttemptResult, AttemptError> {
		debug!("New round attempt. round seq: {}, attempt seq: {}, challenge: {}",
			round_state.round_seq, round_state.attempt_seq, challenge.inner().as_hex());

		let mut srv = match self.require_server() {
			Ok(srv) => srv,
			Err(e) => {
				error!("Cannot get Server connection: {}", e);
				return Err(error_before_forfeit(&self.db, round_state));
			}
		};

		let mut round_state = RoundState::from(round_state);
		// We don't have an event at first because this function is already
		// triggered by the attempt start one
		let mut event = None;

		loop {
			let progress_res = round_state.progress(
				event,
				&mut srv,
				&self,
				challenge,
				participation,
			).await.expect("tried to progress a round state that cannot progress")?;

			round_state = match progress_res {
				ProgressResult::Progress { state } => {
					if let RoundState::PendingConfirmation(state) = state {
						return Ok(AttemptResult::Success(RoundResult {
							round_id: state.round_txid,
						}));
					}

					event = Some(events.next().await.context("event stream broke")
						.map_err(|e| AttemptError::StreamError(e))?
						.map_err(|e| AttemptError::StreamError(e))?);

					state
				}
				ProgressResult::Wait(state) => {
					event = Some(events.next().await.context("event stream broke")
						.map_err(|e| AttemptError::StreamError(e))?
						.map_err(|e| AttemptError::StreamError(e))?);

					tokio::time::sleep(Duration::from_secs(1)).await;

					state
				}
				ProgressResult::WaitNewRound => {
					return Ok(AttemptResult::WaitNewRound)
				}
				ProgressResult::NewRoundStarted(round_info) => {
					return Ok(AttemptResult::NewRoundStarted(round_info));
				}
				ProgressResult::NewAttemptStarted((round_state, challenge)) => {
					return Ok(AttemptResult::NewAttemptStarted((round_state, challenge)));
				}
			};
		}
	}

	/// Participate in a round.
	///
	/// NB Instead of taking the input and output data as arguments, we take a closure that is
	/// called to get these values. This is so because for offboards, the fee rate used for the
	/// offboards is only announced in the beginning of the round and can change between round
	/// attempts. Lateron this will also be useful so we can randomize destinations between failed
	/// round attempts for better privacy.
	pub(crate) async fn participate_round(
		&self,
		participation: DesiredRoundParticipation,
	) -> anyhow::Result<RoundResult> {
		let mut srv = self.require_server()?;

		info!("Waiting for a round start...");
		let mut events = srv.client.subscribe_rounds(protos::Empty {}).await?.into_inner()
			.map(|m| {
				let m = m.context("received error on event stream")?;
				let e = RoundEvent::try_from(m).context("error converting rpc round event")?;
				trace!("Received round event: {}", e);
				Ok::<_, anyhow::Error>(e)
			});

		// We keep this Option with the latest round info.
		// It allows us to conveniently restart when something unexpected happens:
		// - when a new attempt starts, we update the info and restart
		// - when a new round starts, we set it to the new round info and restart
		// - when the server misbehaves, we set it to None and restart
		let mut next_round_info = None;

		'round: loop {
			// If we don't have a round info yet, wait for round start.
			let round_info = if let Some(info) = next_round_info.take() {
				warn!("Unexpected new round started...");
				info
			} else {
				debug!("Waiting for a new round to start...");
				loop {
					match events.next().await.context("events stream broke")?? {
						RoundEvent::Start(info) => {
							break info;
						},
						e => trace!("ignoring irrelevant event: {}", e),
					}
				}
			};

			info!("Round started");
			debug!("Started round #{}", round_info.round_seq);

			let participation = self.fund_round(&participation, round_info.offboard_feerate)
				.context("failed to fund round")?;

			if let Some(payreq) = participation.outputs.iter().find(|p| p.amount < P2TR_DUST) {
				bail!("VTXO amount must be at least {}, requested {}", P2TR_DUST, payreq.amount);
			}

			if let Some(offb) = participation.offboards.iter().find(|o| o.amount < P2TR_DUST) {
				bail!("Offboard amount must be at least {}, requested {}", P2TR_DUST, offb.amount);
			}

			// then we expect the first attempt message
			let (mut updated, mut challenge)= match events.next().await.context("events stream broke")?? {
				RoundEvent::Attempt(attempt) if attempt.round_seq == round_info.round_seq => {
					let round_state = self.db.store_new_round_attempt(
						round_info.round_seq, attempt.attempt_seq, participation.clone(),
					)?;
					(round_state, attempt.challenge)
				},
				RoundEvent::Start(e) => {
					next_round_info = Some(e);
					continue 'round;
				},
				//TODO(stevenroose) make this robust
				other => panic!("Unexpected message: {:?}", other),
			};

			'attempt: loop {
				let attempt_res = self.new_round_attempt(
					&mut events,
					challenge,
					updated,
					&participation,
				).await?;

				match attempt_res {
					AttemptResult::NewRoundStarted(new_round_info) => {
						next_round_info = Some(new_round_info);
						continue 'round;
					},
					AttemptResult::NewAttemptStarted((state, new_challenge)) => {
						updated = state;
						challenge = new_challenge;
						continue 'attempt;
					},
					AttemptResult::WaitNewRound => {
						continue 'round;
					},
					AttemptResult::Success(round_result) => {
						return Ok(round_result)
					},
				}
			}
		}
	}

	pub(crate) async fn sync_pending_rounds(&self) -> anyhow::Result<()> {
		let tip = self.chain.tip().await?;
		info!("Syncing pending rounds at tip: {}", tip);
		let rounds = self.db.list_pending_rounds()?;

		for round in rounds {
			match round {
				RoundState::AttemptStarted(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::PaymentSubmitted(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::VtxoTreeSigned(state) => {
					// TODO: later we can try to catch up last event
					state.to_abandoned_state(&self.db)?;
				},
				RoundState::ForfeitSigned(state) => {
					// TODO: later we can try to catch up last event
					state.progress(None, self).await?;
				},
				RoundState::PendingConfirmation(state) => {
					// TODO: later we can try to catch up last event
					state.progress(self).await?;
				},
				RoundState::RoundConfirmed(_)
					| RoundState::RoundAbandoned(_)
					| RoundState::RoundCancelled(_) =>
				{
					continue;
				},
			}
		}

		Ok(())
	}
}
