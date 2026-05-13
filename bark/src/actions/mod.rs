//! Wallet action infrastructure.
//!
//! A *wallet action* is a multi-step operation that moves vtxos (e.g. a
//! lightning send). Each step is small, persists its outcome to a
//! checkpoint, and is safe to re-drive after a crash.
//!
//! This module defines the generic vocabulary; per-kind machinery (state
//! machines, transition functions) lives in submodules.

use std::time::Duration;

use log::{debug, trace, warn};

use crate::vtxo::{VtxoState, VtxoStateKind};
use crate::{Wallet, WalletVtxo};
use crate::lock_manager::LockGuard;

/// Tagged union of every kind of checkpoint the wallet persists.
///
/// Used as the serialization boundary for the
/// `bark_wallet_action_checkpoint` table; per-kind logic lives on each
/// variant's payload type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletActionCheckpoint {
	Dummy { id: String },
}

impl WalletActionCheckpoint {
	pub fn id(&self) -> WalletActionId {
		match self {
			WalletActionCheckpoint::Dummy { id } => id.clone(),
		}
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
	/// Terminal: executor removes the checkpoint row. Any permanent fact
	/// the action wants to retain (e.g. an "invoice paid" record) must
	/// be written to its own table before returning `Done`.
	Done,
	/// Terminal: executor removes the checkpoint row because of a fatal error.
	/// This advance should only be returned when no server change occured yet
	/// or when process has checked server status is expected one and it is not.
	Failed(anyhow::Error),
}

pub fn lock_key<A: WalletAction>(id: &WalletActionId) -> String {
	format!("{}.{}", A::namespace(), id)
}

/// A wallet action that can be driven step-by-step.
///
/// Implementors define the per-kind state machine; the executor owns the
/// loop, persistence, retry tracking and wake scheduling.
///
/// # Invariants
///
/// - `advance` MUST be re-entrant: it may be called more than once for
///   the same logical step (after a crash, after an early wake, after a
///   notification arrives). All side effects it triggers must therefore
///   be idempotent.
/// - The `id` returned MUST be stable across calls on the same logical
///   action (different states of the same action share an id).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait WalletAction: Sized + Send + Sync {
	fn namespace() -> &'static str;
	fn id(&self) -> WalletActionId;

	async fn advance(self, wallet: &Wallet) -> anyhow::Result<Advance<Self>>;
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

	/// Cancel a wallet action: release its vtxo locks and remove the
	/// checkpoint row. Intended for manual cleanup of stuck actions;
	/// the normal terminal path is `Advance::Done` from `advance`.
	pub async fn cancel_wallet_action(&self, action_id: &WalletActionId) -> anyhow::Result<()> {
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
		let guard = match self.inner.lock_manager.try_lock(&lock_key::<A>(&action.id())).await {
			Some(g) => g,
			None => {
				trace!("action {} in namespace {} is already being driven, skipping", action.id(), A::namespace());
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
		self.run_action_loop(action, mode).await
	}

	async fn run_action_loop<A>(&self, mut action: A, mode: DriveMode) -> anyhow::Result<()>
	where
		A: WalletAction + Into<WalletActionCheckpoint> + Clone,
	{
		loop {
			let id = action.id();
			match action.advance(self).await {
				Ok(Advance::Next(next)) => {
					let checkpoint: WalletActionCheckpoint = next.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
					action = next;
				},
				Ok(Advance::Park { state, wake_after, error }) => {
					let checkpoint: WalletActionCheckpoint = state.clone().into();
					self.inner.db.upsert_wallet_action_checkpoint(&id, &checkpoint).await?;
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
								tokio::time::sleep(delay).await;
								action = state;
							} else {
								return Ok(());
							}
						},
					}
				},
				Ok(Advance::Done) => {
					if let Err(e) = self.release_action_locks(&id).await {
						warn!("action {} done but couldn't release stale locks: {:#}", id, e);
					}
					if let Err(e) = self.inner.db.remove_wallet_action_checkpoint(&id).await {
						warn!("action {} finished but removal failed: {:#}", id, e);
					}
					return Ok(());
				},
				Ok(Advance::Failed(e)) => {
					if let Err(e) = self.inner.db.remove_wallet_action_checkpoint(&id).await {
						warn!("action {} failed but removal failed: {:#}", id, e);
					}
					return Err(e);
				},
				Err(e) => {
					return Err(e);
				},
			}
		}
	}
}
