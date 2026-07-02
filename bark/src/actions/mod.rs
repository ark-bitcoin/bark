//! Wallet action infrastructure.
//!
//! A *wallet action* is a multi-step operation that moves vtxos (e.g. a
//! lightning send). Each step is small, persists its outcome to a
//! checkpoint, and is safe to re-drive after a crash.
//!
//! This module defines the generic vocabulary; per-kind machinery (state
//! machines, transition functions) lives in submodules.

pub mod lightning;
pub mod arkoor_send;
pub mod board;

use std::time::Duration;

use log::{debug, trace, warn};
use server_rpc::StatusExt;

use crate::{Wallet, WalletVtxo};
use crate::actions::arkoor_send::ArkoorSend;
use crate::actions::board::Board;
use crate::actions::lightning::pay::LightningSend;
use crate::actions::lightning::receive::LightningReceive;
use crate::lock_manager::LockGuard;
use crate::vtxo::{VtxoState, VtxoStateKind};

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
}

impl WalletActionCheckpoint {
	pub fn id(&self) -> WalletActionId {
		match self {
			WalletActionCheckpoint::LightningSend(s) => s.id(),
			WalletActionCheckpoint::LightningReceive(r) => r.id(),
			WalletActionCheckpoint::ArkoorSend(s) => s.id(),
			WalletActionCheckpoint::Board(s) => s.id(),
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
		error: Option<AdvanceError>,
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

#[derive(Debug, thiserror::Error)]
pub enum AdvanceError {
	#[error("An error occurred while communicating with the server: {0}")]
	Server(tonic::Status),
	#[error("An error occurred while processing the action: {0}")]
	Other(#[from] anyhow::Error),
}

impl AdvanceError {
	pub fn is_server_rejection(&self) -> bool {
		match self {
			AdvanceError::Server(err) => err.is_rejection(),
			_ => false,
		}
	}
}

pub fn park_with_backoff<A: WalletAction>(state: A, attempts: u32) -> Advance<A> {
	let delay = attempts.pow(2) * BASE_RETRY_BACKOFF;
	debug!("action {} retrying; sleeping {:?} before re-drive", state.id(), delay);
	Advance::Park { state, wake_after: Some(delay), error: None }
}

/// Whether to double-drive each action step to check reentrancy, set via the
/// `BARK_DOUBLE_DRIVE_ACTIONS` env var. Debug-only, compiled out of release.
/// See `just int-bark-sdk-action-reentrancy`.
#[cfg(debug_assertions)]
fn double_drive_actions() -> bool {
	std::env::var_os("BARK_DOUBLE_DRIVE_ACTIONS").is_some()
}

/// Assert advancing the same state twice produced an equivalent outcome (same
/// [`Advance`] kind, same checkpoint for non-terminal kinds); a divergence is a
/// non-idempotency bug and panics, naming the offending step. Two errors count
/// as equivalent: [`AdvanceError`] isn't comparable.
#[cfg(debug_assertions)]
fn assert_reentrant<A>(
	first: &Result<Advance<A>, AdvanceError>,
	second: &Result<Advance<A>, AdvanceError>,
) where
	A: Into<WalletActionCheckpoint> + Clone,
{
	fn describe<A: Into<WalletActionCheckpoint> + Clone>(
		result: &Result<Advance<A>, AdvanceError>,
	) -> (&'static str, Option<WalletActionCheckpoint>) {
		match result {
			Ok(Advance::Next(state)) => ("Next", Some(state.clone().into())),
			Ok(Advance::Park { state, .. }) => ("Park", Some(state.clone().into())),
			Ok(Advance::Done) => ("Done", None),
			Ok(Advance::Failed(_)) => ("Failed", None),
			Err(_) => ("Err", None),
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

	/// Called to advance the action state
	///
	/// MUST be re-entrant: it may be called more than once for the same logical
	/// step (after a crash, after an early wake, after a notification arrives).
	/// All side effects it triggers must therefore be idempotent.
	async fn advance(self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError>;

	/// Called when the action should be retried
	async fn on_retry(self, _wallet: &Wallet, attempts: u32) -> anyhow::Result<Advance<Self>> {
		Ok(park_with_backoff(self, attempts))
	}

	/// Called when the server rejected one of our requests
	///
	/// MUST be re-entrant for the same reason as [WalletAction::advance]:
	/// it may run partially, crash, and be re-driven against the state the action
	/// subsequently lands in.
	async fn on_rejection(self, _wallet: &Wallet, _error: AdvanceError)
		-> anyhow::Result<Advance<Self>>;
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
	/// the executor on `Advance::Done` and by manual cancellation via
	/// [`Self::cancel_wallet_action`].
	pub async fn release_action_locks(&self, action_id: &WalletActionId) -> anyhow::Result<()> {
		let vtxos = self.get_vtxos_locked_by_action(action_id).await?;
		if vtxos.is_empty() {
			return Ok(());
		}
		debug!("releasing {} vtxo lock(s) held by action {}", vtxos.len(), action_id);
		self.unlock_vtxos(vtxos).await
	}

	/// Finish a wallet action: release its vtxo locks and remove the
	/// checkpoint row. Intended for manual cleanup of stuck actions;
	/// the normal terminal path is `Advance::Done` from `advance`.
	pub async fn stop_wallet_action(&self, action_id: &WalletActionId) -> anyhow::Result<()> {
		self.release_action_locks(action_id).await?;
		self.inner.db.remove_wallet_action_checkpoint(action_id).await?;
		Ok(())
	}

	/// Drive a wallet action to its next park or terminal state.
	///
	/// Holds a per-action-id in-flight guard so concurrent drives of
	/// the same action (e.g. the periodic sync racing a user call)
	/// don't step on each other.
	pub async fn drive_action<A>(&self, action: A, mode: DriveMode) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		let guard = match self.inner.lock_manager.try_lock(&action.id()).await {
			Some(g) => g,
			None => {
				trace!("action {} is already being driven, skipping", action.id());
				return Ok(());
			},
		};

		self.drive_action_with_guard(action, mode, guard).await
	}

	/// Drive an action assuming the caller already holds its per-id
	/// lock. `lock_guard` MUST be the guard returned by
	/// `lock_manager.try_lock(&lock_key::<A>(&action.id()))`; it is
	/// held for RAII and dropped when this function returns.
	pub(crate) async fn drive_action_with_guard<A>(
		&self,
		action: A,
		mode: DriveMode,
		_lock_guard: Box<dyn LockGuard>,
	) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		// Box the driver so its state machine lives on the heap rather
		// than inline in the caller's future.
		Box::pin(self.run_action_loop(action, mode)).await
	}

	/// Run one `advance` step.
	///
	/// In debug builds with `BARK_DOUBLE_DRIVE_ACTIONS` set (see
	/// [`double_drive_actions`]) the step runs twice from the same state and
	/// [`assert_reentrant`] checks both reach an equivalent checkpoint,
	/// exercising `advance`'s idempotency contract. Keep the second run; its
	/// side effects are the ones the persisted state references.
	async fn advance_step<A>(&self, action: A) -> Result<Advance<A>, AdvanceError>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		#[cfg(debug_assertions)]
		if double_drive_actions() {
			let snapshot = action.clone();
			let first = action.advance(self).await;
			let second = snapshot.advance(self).await;
			assert_reentrant(&first, &second);
			return second;
		}

		action.advance(self).await
	}

	async fn run_action_loop<A>(&self, mut action: A, mode: DriveMode) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		// In-memory counter for transient errors. Lives only for this
		// drive_action call so the backoff curve resets between drives.
		let mut retries: u32 = 0;

		loop {
			let id = action.id();
			// Snapshot for the error path: advance consumes self, and
			// on_rejection also takes self by value, so we need a
			// copy around if budget exhausts.
			let snapshot = action.clone();

			let advance = match self.advance_step(action).await {
				Ok(advance) => { advance },
				Err(e) if e.is_server_rejection() => {
					warn!("action {} got rejected by server: {:#}", id, e);
					snapshot.on_rejection(self, e).await.inspect_err(|err| {
						warn!("action {} on_rejection failed, leaving checkpoint for retry: {:#}", id, err);
					})?
				}
				Err(e) => {
					retries = retries.saturating_add(1);
					log::error!("Got error {:?} from action {}, retrying", e, id);
					snapshot.on_retry(self, retries).await.inspect_err(|err| {
						warn!("action {} on_retry failed, leaving checkpoint for retry: {:#}", id, err);
					})?
				},
			};

			match advance {
				Advance::Next(next) => {
					retries = 0;
					let checkpoint: WalletActionCheckpoint = next.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
					action = next;
				},
				Advance::Park { state, wake_after, error } => {
					let checkpoint: WalletActionCheckpoint = state.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
					match mode {
						DriveMode::UntilParkOrDone => {
							return match error {
								Some(error) => Err(error.into()),
								None => Ok(()),
							};
						},
						DriveMode::UntilDone => {
							if let Some(delay) = wake_after {
								debug!("action {} parked; sleeping {:?} before re-drive", id, delay);
								tokio::time::sleep(delay).await;
								action = state;
							} else {
								return match error {
									Some(error) => Err(error.into()),
									None => Ok(()),
								};
							}
						},
					}
				},
				Advance::Done => {
					if let Err(e) = self.stop_wallet_action(&id).await {
						warn!("action {} done but couldn't cancel: {:#}", id, e);
					}
					return Ok(());
				},
				Advance::Failed(e) => {
					if let Err(e) = self.stop_wallet_action(&id).await {
						warn!("action {} failed but couldn't cancel: {:#}", id, e);
					}
					return Err(e);
				},
			}
		}
	}
}
