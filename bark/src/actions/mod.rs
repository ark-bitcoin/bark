//! Wallet action infrastructure.
//!
//! A *wallet action* is a multi-step operation that moves vtxos (e.g. a
//! lightning send). Each step is small, persists its outcome to a
//! checkpoint, and is safe to re-drive after a crash.
//!
//! This module defines the generic vocabulary; per-kind machinery (state
//! machines, transition functions) lives in submodules.

use std::time::Duration;

use crate::Wallet;

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
