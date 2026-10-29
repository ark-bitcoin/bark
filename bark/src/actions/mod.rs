//! Wallet action infrastructure.
//!
//! A *wallet action* is a multi-step operation that moves vtxos (e.g. a
//! lightning send). Each step is small, persists its outcome to a
//! checkpoint, and is safe to re-drive after a crash.
//!
//! This module defines the generic vocabulary; per-kind machinery (state
//! machines, transition functions) lives in submodules.

pub mod arkoor_send;
pub mod board;
pub mod lightning;
pub mod offboard;

use std::fmt;
use std::time::Duration;

use anyhow::Context;
use log::{debug, trace, warn};
use server_rpc::StatusExt;

use ark::VtxoId;

use crate::movement::error::MovementError;
use crate::{Wallet, WalletVtxo};
use crate::actions::arkoor_send::ArkoorSend;
use crate::actions::board::Board;
use crate::actions::lightning::pay::LightningSend;
use crate::actions::lightning::receive::LightningReceive;
use crate::actions::offboard::Offboard;
use crate::lock_manager::LockGuard;
use crate::vtxo::{VtxoState, VtxoStateKind, VtxoValidationError};

pub(crate) const BASE_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Tagged union of every kind of checkpoint the wallet persists.
///
/// Used as the serialization boundary for the
/// `bark_wallet_action_checkpoint` table; per-kind logic lives on each
/// variant's payload type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletActionCheckpoint {
	LightningSend(LightningSend),
	LightningReceive(LightningReceive),
	ArkoorSend(ArkoorSend),
	Board(Board),
	Offboard(Offboard),
}

impl WalletActionCheckpoint {
	pub fn id(&self) -> WalletActionId {
		match self {
			WalletActionCheckpoint::LightningSend(s) => s.id(),
			WalletActionCheckpoint::LightningReceive(r) => r.id(),
			WalletActionCheckpoint::ArkoorSend(s) => s.id(),
			WalletActionCheckpoint::Board(s) => s.id(),
			WalletActionCheckpoint::Offboard(o) => o.id(),
		}
	}

	pub fn as_lightning_send(&self) -> Option<&LightningSend> {
		match self {
			WalletActionCheckpoint::LightningSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_lightning_send(self) -> Option<LightningSend> {
		match self {
			WalletActionCheckpoint::LightningSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_lightning_receive(&self) -> Option<&LightningReceive> {
		match self {
			WalletActionCheckpoint::LightningReceive(r) => Some(r),
			_ => None,
		}
	}

	pub fn into_lightning_receive(self) -> Option<LightningReceive> {
		match self {
			WalletActionCheckpoint::LightningReceive(r) => Some(r),
			_ => None,
		}
	}

	pub fn as_arkoor_send(&self) -> Option<&ArkoorSend> {
		match self {
			WalletActionCheckpoint::ArkoorSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_arkoor_send(self) -> Option<ArkoorSend> {
		match self {
			WalletActionCheckpoint::ArkoorSend(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_board(&self) -> Option<&Board> {
		match self {
			WalletActionCheckpoint::Board(s) => Some(s),
			_ => None,
		}
	}

	pub fn into_board(self) -> Option<Board> {
		match self {
			WalletActionCheckpoint::Board(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_offboard(&self) -> Option<&Offboard> {
		match self {
			WalletActionCheckpoint::Offboard(o) => Some(o),
			_ => None,
		}
	}

	pub fn into_offboard(self) -> Option<Offboard> {
		match self {
			WalletActionCheckpoint::Offboard(o) => Some(o),
			_ => None,
		}
	}
}

impl From<LightningSend> for WalletActionCheckpoint {
	fn from(s: LightningSend) -> Self {
		WalletActionCheckpoint::LightningSend(s)
	}
}

impl From<LightningReceive> for WalletActionCheckpoint {
	fn from(r: LightningReceive) -> Self {
		WalletActionCheckpoint::LightningReceive(r)
	}
}

impl From<ArkoorSend> for WalletActionCheckpoint {
	fn from(s: ArkoorSend) -> Self {
		WalletActionCheckpoint::ArkoorSend(s)
	}
}

impl From<Board> for WalletActionCheckpoint {
	fn from(s: Board) -> Self {
		WalletActionCheckpoint::Board(s)
	}
}

impl From<Offboard> for WalletActionCheckpoint {
	fn from(o: Offboard) -> Self {
		WalletActionCheckpoint::Offboard(o)
	}
}

/// Stable identifier for a wallet action.
///
/// The id must be derivable from the action's identity (e.g. the payment
/// hash for a lightning send) so that restarting the same action picks
/// up the same checkpoint row.
pub type WalletActionId = String;

/// Outcome of one `WalletAction::advance` call.
///
/// The executor uses these to decide whether to persist, loop, schedule
/// a wake-up or remove the checkpoint.
pub enum Advance<A> {
	/// Transition to a new state. Executor persists `state` and calls
	/// `advance` on it.
	Next(A),
	/// Pause until something external (notification, periodic sync) or
	/// `wake_after` (when set) re-drives the action. Executor persists
	/// `state` and returns.
	///
	/// `wake_after` is a hint, not a guarantee: it lives only in this
	/// process and is lost across restarts. `advance` MUST tolerate
	/// being called before the hint has elapsed.
	///
	/// `error` is the error that caused the park, if any.
	Park {
		state: A,
		wake_after: Option<Duration>,
		error: Option<anyhow::Error>,
	},
	/// The step failed transiently; re-run it later. Executor persists state,
	/// counts the attempt (in memory, per drive) and either backs off
	/// quadratically in the number of consecutive retries and re-drives
	/// ([DriveMode::UntilDone]) or returns `error` to the caller
	/// ([DriveMode::UntilParkOrDone]).
	Retry {
		state: A,
		error: anyhow::Error,
	},
	/// Terminal: executor removes the checkpoint row. Any permanent fact
	/// the action wants to retain (e.g. an "invoice paid" record) must
	/// be written to its own table before returning `Done`.
	Done,
	/// Terminal: executor removes the checkpoint row because of a fatal error.
	/// This advance should only be returned when no server change occured yet
	/// or when process has checked server status is expected one and it is
	/// safe to remove checkpoint
	Failed(anyhow::Error),
}

/// How a step of an action failed. An action's [WalletAction::advance] returns
/// it and the executor hands it to [WalletAction::on_retry] or
/// [WalletAction::on_abort] together with the state the step started from.
///
/// Every error crossing into a step function is classified explicitly with
/// [IntoAdvanceError] or [AdvanceResultExt]; there is no implicit conversion,
/// so a `?` on an unclassified error is a compile error rather than an
/// accidental retry.
#[derive(Debug)]
pub enum AdvanceError {
	/// Redoing the exact same step later may succeed
	Retry(anyhow::Error),
	/// Redoing the same step can never succeed
	Abort(anyhow::Error),
}

/// The plain error behind a failed call, classified or not.
///
/// Lets [or_retry] take both an `anyhow::Result` and a
/// `Result<_, AdvanceError>`: a failure while handling a failed step is
/// retried whatever its own classification was.
trait IntoAnyhow {
	fn into_anyhow(self) -> anyhow::Error;
}

impl IntoAnyhow for anyhow::Error {
	fn into_anyhow(self) -> anyhow::Error {
		self
	}
}

impl IntoAnyhow for AdvanceError {
	fn into_anyhow(self) -> anyhow::Error {
		match self {
			Self::Retry(e) => e,
			Self::Abort(e) => e,
		}
	}
}

impl fmt::Display for AdvanceError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			AdvanceError::Retry(e) => write!(f, "action advance error (retry): {:#}", e),
			AdvanceError::Abort(e) => write!(f, "action advance error (abort): {:#}", e),
		}
	}
}

/// Extention trait on [Result<T, AdvanceError>]
pub(crate) trait AdvanceResultExt<T> {
	/// Convert into [anyhow::Result<T>]
	fn into_anyhow(self) -> anyhow::Result<T>;
}

impl<T> AdvanceResultExt<T> for Result<T, AdvanceError> {
	fn into_anyhow(self) -> anyhow::Result<T> {
	    self.map_err(|e| e.into_anyhow())
	}
}

/// Similar to `bail!` but returns an [AdvanceError::Abort] error
macro_rules! abort {
	($msg:literal $(,)?) => {
		return Err(AdvanceError::Abort(::anyhow::anyhow!($msg)))
	};
	($err:expr $(,)?) => {
		return Err(AdvanceError::Abort(::anyhow::anyhow!($err)))
	};
	($fmt:expr, $($arg:tt)*) => {
		return Err(AdvanceError::Abort(::anyhow::anyhow!($fmt, $($arg)*)))
	};
}
use abort;

/// Similar to `bail!` but returns an [AdvanceError::Retry] error
macro_rules! retry {
	($msg:literal $(,)?) => {
		return Err(AdvanceError::Retry(::anyhow::anyhow!($msg)))
	};
	($err:expr $(,)?) => {
		return Err(AdvanceError::Retry(::anyhow::anyhow!($err)))
	};
	($fmt:expr, $($arg:tt)*) => {
		return Err(AdvanceError::Retry(::anyhow::anyhow!($fmt, $($arg)*)))
	};
}
use retry;

/// Unwrap a fallible call made while handling a failed step.
///
/// `?` can't hand the action back on failure, so this returns
/// [Advance::Retry] with `$state` as it was: the step runs again later and
/// gets to fail (and be handled) again.
macro_rules! or_retry {
	($state:expr, $result:expr $(,)?) => {
		match $result {
			Ok(v) => v,
			Err(e) => return crate::actions::Advance::Retry {
				state: $state,
				error: crate::actions::IntoAnyhow::into_anyhow(e),
			},
		}
	};
}
use or_retry;

/// Classify an error for a step function.
///
/// `retry` means "repeat this exact step later". An error type that can prove
/// repeating is futile routes `retry` to [AdvanceError::Abort] itself: a
/// server rejection never becomes a success by resending the request.
///
/// Deliberately not a blanket impl: every type that reaches a `?` inside a
/// step gets an explicit impl here, everything else goes through
/// `anyhow::Context` first.
trait IntoAdvanceError {
	fn retry(self) -> AdvanceError;
	fn abort(self) -> AdvanceError;
}

/// Implement [IntoAdvanceError] by converting to an [anyhow::Error]
macro_rules! impl_into_advance_err {
	($error:ty) => {
		impl IntoAdvanceError for $error {
			fn retry(self) -> AdvanceError { AdvanceError::Retry(self.into()) }
			fn abort(self) -> AdvanceError { AdvanceError::Abort(self.into()) }
		}
	};
}
impl_into_advance_err!(anyhow::Error);
impl_into_advance_err!(MovementError);
impl_into_advance_err!(VtxoValidationError);

/// [IntoAdvanceError] on the `Err` of a `Result`, so a step reads
/// `wallet.foo().await.retry()?`.
trait IntoAdvanceResult<T> {
	fn retry(self) -> Result<T, AdvanceError>;
	fn abort(self) -> Result<T, AdvanceError>;
}

impl<T, E: IntoAdvanceError> IntoAdvanceResult<T> for Result<T, E> {
	fn retry(self) -> Result<T, AdvanceError> {
		self.map_err(|e| e.retry())
	}
	fn abort(self) -> Result<T, AdvanceError> {
		self.map_err(|e| e.abort())
	}
}

/// Extension trait that maps tonic status codes associated with rejection into
/// the abort category and retry otherwise
trait RetryUnlessRejected<T> {
	/// Map the error to a [AdvanceError::Retry] unless it's a rejection
	///
	/// See [StatusExt::is_rejection] for more info about rejections.
	fn retry_unless_rejected(self) -> Result<T, AdvanceError>;
}

impl<T> RetryUnlessRejected<T> for Result<T, tonic::Status> {
	fn retry_unless_rejected(self) -> Result<T, AdvanceError> {
		self.map_err(|e| if e.is_rejection() {
			AdvanceError::Abort(e.into())
		} else {
			AdvanceError::Retry(e.into())
		})
	}
}

impl<T> RetryUnlessRejected<T> for anyhow::Result<T> {
	fn retry_unless_rejected(self) -> Result<T, AdvanceError> {
		self.map_err(|e| {
			if let Some(s) = e.downcast_ref::<tonic::Status>() && s.is_rejection() {
				AdvanceError::Abort(e.into())
			} else {
				AdvanceError::Retry(e.into())
			}
		})
	}
}

/// Whether to double-drive each action step to check reentrancy, set via the
/// `BARK_DOUBLE_DRIVE_ACTIONS` env var. Empty, `0` and `false` count as unset.
/// Debug-only, compiled out of release.
/// See `just int-bark-sdk-action-reentrancy`.
#[cfg(debug_assertions)]
fn double_drive_actions() -> bool {
	match std::env::var("BARK_DOUBLE_DRIVE_ACTIONS") {
		Ok(v) => !matches!(v.trim(), "" | "0" | "false"),
		Err(_) => false,
	}
}

/// Assert advancing the same state twice produced an equivalent outcome (same
/// [`Advance`] kind, same checkpoint for non-terminal kinds); a divergence is a
/// non-idempotency bug and panics, naming the offending step. Two errors count
/// as equivalent: `anyhow::Error` isn't comparable.
#[cfg(debug_assertions)]
fn assert_reentrant<A>(first: &Advance<A>, second: &Advance<A>)
where
	A: Into<WalletActionCheckpoint> + Clone,
{
	fn describe<A: Into<WalletActionCheckpoint> + Clone>(
		advance: &Advance<A>,
	) -> (&'static str, Option<WalletActionCheckpoint>) {
		match advance {
			Advance::Next(state) => ("Next", Some(state.clone().into())),
			Advance::Park { state, .. } => ("Park", Some(state.clone().into())),
			Advance::Retry { state, .. } => ("Retry", Some(state.clone().into())),
			Advance::Done => ("Done", None),
			Advance::Failed(_) => ("Failed", None),
		}
	}

	assert_eq!(
		describe(first), describe(second),
		"wallet action is not reentrant: advancing the same state twice diverged",
	);
}

/// A wallet action that can be driven step-by-step.
///
/// Implementors define the per-kind state machine; the executor owns the
/// loop, persistence, retry tracking and wake scheduling.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait WalletAction: Sized + Send + Sync {
	/// Get an identifier for this action
	///
	/// The `id` returned MUST be stable across calls on the same logical
	/// action (different states of the same action share an id).
	fn id(&self) -> WalletActionId;

	/// Get the action back from its stored checkpoint, `None` if the
	/// checkpoint holds another kind of action.
	fn from_checkpoint(checkpoint: WalletActionCheckpoint) -> Option<Self>;

	/// The IDs of VTXOs which are currently in-use, either being spent or being
	/// created, by the action and should be included in the wallet's balance.
	/// The VTXOs should not be stored as spendable in the wallet, but they should
	/// be retrievable via [BarkPersister].
	///
	/// See [crate::Wallet::balance] for more information.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId>;

	/// Called to advance the action state
	///
	/// MUST be re-entrant: it may be called more than once for the same logical
	/// step (after a crash, after an early wake, after a notification arrives).
	/// All side effects it triggers must therefore be idempotent.
	///
	/// A failed step returns an [AdvanceError]. The executor hands it, with
	/// the state the step started from, to [WalletAction::on_retry] or
	/// [WalletAction::on_abort].
	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError>;

	/// Called when a step failed transiently.
	///
	/// `self` is the state the step started from. The default re-runs the
	/// same step later with backoff; implementations can give up on the step
	/// instead once waiting no longer makes sense.
	async fn on_retry(self, _wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
		Advance::Retry { state: self, error }
	}

	/// Called when a step gave up on its current state: the server rejected
	/// the request or the step can't be completed as-is.
	///
	/// `self` is the state the step started from. MUST be re-entrant for the
	/// same reason as [WalletAction::advance]: it may run partially, crash,
	/// and be re-driven against the state the action subsequently lands in.
	async fn on_abort(self, wallet: &Wallet, error: anyhow::Error) -> Advance<Self>;
}

/// The lock of a wallet action, with the checkpoint of the action as read
/// while holding the lock.
///
/// Checkpoints are only written through this type. A write therefore always
/// starts from the state stored under the lock, never from a copy that was
/// read before another driver advanced or finished the action. Get one with
/// [Wallet::try_lock_action] or [Wallet::lock_action].
pub(crate) struct GuardedCheckpoint<A> {
	id: WalletActionId,
	/// `None` when the action has no checkpoint: it is not created yet, or
	/// it has finished.
	action: Option<A>,
	_guard: Box<dyn LockGuard>,
}

impl<A> GuardedCheckpoint<A>
where
	A: WalletAction + Into<WalletActionCheckpoint> + Clone,
{
	pub fn get(&self) -> Option<&A> {
		self.action.as_ref()
	}

	/// Store the first checkpoint of the action.
	pub async fn create(&mut self, wallet: &Wallet, action: A) -> anyhow::Result<()> {
		if self.action.is_some() {
			bail!("action {} already has a checkpoint", self.id);
		}
		self.save(wallet, action).await
	}

	/// Change the checkpoint of the action outside of a step, like a setting
	/// the user changes.
	pub async fn update(&mut self, wallet: &Wallet, change: impl FnOnce(&mut A)) -> anyhow::Result<()> {
		let mut action = self.action.take()
			.with_context(|| format!("action {} has no checkpoint", self.id))?;
		change(&mut action);
		self.save(wallet, action).await
	}

	/// Finish the action: release its vtxo locks and remove its checkpoint.
	///
	/// The normal terminal path is [Advance::Done] or [Advance::Failed] from
	/// a step. Calling this directly is for actions that end outside of a
	/// step, like a cancel.
	pub async fn finish(self, wallet: &Wallet) -> anyhow::Result<()> {
		wallet.release_action_locks(&self.id).await?;
		self.remove(wallet).await
	}

	/// Remove the checkpoint of the action, and keep the vtxos it locked
	/// locked.
	pub async fn remove(self, wallet: &Wallet) -> anyhow::Result<()> {
		wallet.inner.db.remove_wallet_action_checkpoint(&self.id).await?;
		Ok(())
	}

	/// Private to this module: only the executor stores the state a step
	/// returns, see [Wallet::drive_checkpoint].
	async fn save(&mut self, wallet: &Wallet, action: A) -> anyhow::Result<()> {
		debug_assert_eq!(action.id(), self.id, "checkpoint saved under another action id");
		wallet.inner.db.upsert_wallet_action_checkpoint(&self.id, &action.clone().into()).await?;
		self.action = Some(action);
		Ok(())
	}
}

/// How aggressively the executor should drive an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveMode {
	/// Drive until the action parks or completes, then return.
	UntilParkOrDone,
	/// Drive past parks, sleeping between iterations, until the action
	/// returns [`Advance::Done`].
	UntilDone,
}

impl Wallet {
	/// List the VTXOs currently locked by a specific wallet action.
	///
	/// Used by the executor to free reservations when an action fails
	/// terminally without having transitioned its vtxos through the
	/// normal Spent/Spendable channels.
	async fn get_vtxos_locked_by_action(
		&self,
		action_id: &WalletActionId,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let all = self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Locked]).await?;
		Ok(all.into_iter().filter(|v| match &v.state {
			VtxoState::Locked { holder: Some(crate::vtxo::VtxoLockHolder::Action { id }) } => {
				id == action_id
			},
			_ => false,
		}).collect())
	}

	/// Release every vtxo currently locked by the given action,
	/// returning each one to [`crate::vtxo::VtxoState::Spendable`].
	///
	/// Cheap when nothing is held (no-op). Used as the cleanup hook by
	/// [`GuardedCheckpoint::finish`].
	pub async fn release_action_locks(&self, action_id: &WalletActionId) -> anyhow::Result<()> {
		let vtxos = self.get_vtxos_locked_by_action(action_id).await?;
		if vtxos.is_empty() {
			return Ok(());
		}
		debug!("releasing {} vtxo lock(s) held by action {}", vtxos.len(), action_id);
		self.unlock_vtxos(
			vtxos, Some(crate::vtxo::VtxoLockHolder::Action { id: action_id.clone() }),
		).await
	}

	/// Take the lock of a wallet action without waiting, and read its
	/// checkpoint under it. `None` if another driver holds the lock.
	pub(crate) async fn try_lock_action<A>(&self, id: &WalletActionId)
		-> anyhow::Result<Option<GuardedCheckpoint<A>>>
	where
		A: WalletAction,
	{
		match self.inner.lock_manager.try_lock(id).await {
			Some(guard) => Ok(Some(self.read_checkpoint(id, guard).await?)),
			None => Ok(None),
		}
	}

	/// Take the lock of a wallet action, waiting up to `timeout` for it, and
	/// read its checkpoint under it.
	pub(crate) async fn lock_action<A>(&self, id: &WalletActionId, timeout: Duration)
		-> anyhow::Result<GuardedCheckpoint<A>>
	where
		A: WalletAction,
	{
		let guard = self.inner.lock_manager.lock(id, timeout).await?;
		self.read_checkpoint(id, guard).await
	}

	async fn read_checkpoint<A>(&self, id: &WalletActionId, guard: Box<dyn LockGuard>)
		-> anyhow::Result<GuardedCheckpoint<A>>
	where
		A: WalletAction,
	{
		let action = match self.inner.db.get_wallet_action_checkpoint(id).await? {
			Some(checkpoint) => Some(A::from_checkpoint(checkpoint)
				.with_context(|| format!("checkpoint {} holds another kind of action", id))?),
			None => None,
		};
		Ok(GuardedCheckpoint { id: id.clone(), action, _guard: guard })
	}

	/// Drive a wallet action to its next park or terminal state.
	///
	/// Holds a per-action-id in-flight guard so concurrent drives of
	/// the same action (e.g. the periodic sync racing a user call)
	/// don't step on each other. If another driver holds it, or the action
	/// has finished, nothing is driven.
	pub(crate) async fn drive_action<A>(&self, id: &WalletActionId, mode: DriveMode) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		match self.try_lock_action::<A>(id).await? {
			Some(checkpoint) => self.drive_checkpoint(checkpoint, mode).await,
			None => {
				trace!("action {} is already being driven, skipping", id);
				Ok(())
			},
		}
	}

	/// Drive a wallet action whose lock the caller already holds. The lock
	/// is released when this function returns. If the action has no
	/// checkpoint, it has finished: nothing is driven.
	pub(crate) async fn drive_checkpoint<A>(
		&self,
		checkpoint: GuardedCheckpoint<A>,
		mode: DriveMode,
	) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		// Box the driver so its state machine lives on the heap rather
		// than inline in the caller's future.
		Box::pin(self.run_action_loop(checkpoint, mode)).await
	}

	/// Run one `advance` step and hand a failure to the action's handler.
	async fn run_step<A>(&self, action: A) -> Advance<A>
	where
		A: WalletAction + Clone,
	{
		// `advance` consumes the action and the handlers need the state the
		// step started from.
		let snapshot = action.clone();
		match action.advance(self).await {
			Ok(advance) => advance,
			Err(error) => {
				warn!("action {} step failed: {}", snapshot.id(), error);
				match error {
					AdvanceError::Retry(e) => snapshot.on_retry(self, e).await,
					AdvanceError::Abort(e) => snapshot.on_abort(self, e).await,
				}
			},
		}
	}

	/// Run one `advance` step, including its retry or abort handling.
	///
	/// In debug builds with `BARK_DOUBLE_DRIVE_ACTIONS` set (see
	/// [`double_drive_actions`]) the step runs twice from the same state and
	/// [`assert_reentrant`] checks both reach an equivalent checkpoint,
	/// exercising `advance`'s idempotency contract. Keep the second run; its
	/// side effects are the ones the persisted state references.
	async fn advance_step<A>(&self, action: A) -> Advance<A>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		#[cfg(debug_assertions)]
		if double_drive_actions() {
			let snapshot = action.clone();
			let first = self.run_step(action).await;
			let second = self.run_step(snapshot).await;

			// A first run that parks or retries made no committed progress:
			// it is a "nothing finished, re-drive me later" outcome (waiting
			// on a confirmation, polling for an incoming payment, a transient
			// server failure). The second run is that later re-drive and may
			// legitimately diverge once the awaited condition clears,
			// progressing to the next step or completing. So only assert
			// equivalence when the first run committed a step (Next),
			// finished (Done) or failed terminally.
			let first_waited = matches!(first, Advance::Park { .. } | Advance::Retry { .. });
			if !first_waited {
				assert_reentrant(&first, &second);
			}
			return second;
		}

		self.run_step(action).await
	}

	async fn run_action_loop<A>(&self, mut checkpoint: GuardedCheckpoint<A>, mode: DriveMode)
		-> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		let id = checkpoint.id.clone();
		// In-memory counter of consecutive retries, for the backoff curve.
		// Lives only for this drive_action call so the curve resets between
		// drives.
		let mut retries: u32 = 0;

		loop {
			let action = match checkpoint.action.take() {
				Some(action) => action,
				None => {
					trace!("action {} has already finished, skipping", id);
					return Ok(());
				},
			};

			match self.advance_step(action).await {
				Advance::Next(next) => {
					retries = 0;
					checkpoint.save(self, next).await?;
				},
				Advance::Retry { state, error } => {
					retries = retries.saturating_add(1);
					checkpoint.save(self, state).await?;
					match mode {
						DriveMode::UntilParkOrDone => {
							warn!("action {} failed, leaving checkpoint for retry: {:#}", id, error);
							return Err(error);
						},
						DriveMode::UntilDone => {
							let delay = retries.pow(2) * BASE_RETRY_BACKOFF;
							warn!("action {} failed, retrying in {:?}: {:#}", id, delay, error);
							bark_runtime::sleep(delay).await;
						},
					}
				},
				Advance::Park { state, wake_after, error } => {
					checkpoint.save(self, state).await?;
					match mode {
						DriveMode::UntilParkOrDone => {
							return match error {
								Some(error) => Err(error),
								None => Ok(()),
							};
						},
						DriveMode::UntilDone => {
							if let Some(delay) = wake_after {
								debug!("action {} parked; sleeping {:?} before re-drive", id, delay);
								bark_runtime::sleep(delay).await;
							} else {
								return match error {
									Some(error) => Err(error),
									None => Ok(()),
								};
							}
						},
					}
				},
				Advance::Done => {
					if let Err(e) = checkpoint.finish(self).await {
						warn!("action {} done but couldn't cancel: {:#}", id, e);
					}
					return Ok(());
				},
				Advance::Failed(e) => {
					if let Err(e) = checkpoint.finish(self).await {
						warn!("action {} failed but couldn't cancel: {:#}", id, e);
					}
					return Err(e);
				},
			}
		}
	}
}
