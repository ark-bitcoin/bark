//! In-process named locks with a process-wide shared keyspace.
//!
//! All [`MemoryLockManager`] instances within a process share a single
//! global key map: two `MemoryLockManager::new()` calls produce handles
//! into the same lock universe. Two instances cannot accidentally end
//! up with disjoint lock universes the way direct
//! [`InternalMemoryLockManager`](super::internal_memory::InternalMemoryLockManager)
//! instances would.
//!
//! Compare with
//! [`InternalMemoryLockManager`](super::internal_memory::InternalMemoryLockManager),
//! whose keyspace is per-instance and exists for composition by
//! file-based backends — each backend needs its own private in-process
//! map so two unrelated lock directories don't falsely contend on the
//! same key. That type is crate-private; this one is the public
//! in-memory backend.
//!
//! Gives no cross-process, cross-machine, or cross-tab guarantees —
//! coordination is only within the current OS process.
//!
//! # Platform support
//!
//! All platforms. Pure Rust over `tokio::sync::Mutex`; no I/O, no
//! syscalls.
//!
//! # When to use
//!
//! - You've already enforced that exactly one bark instance opens this
//!   dataset at a time (single-process service, container exclusivity,
//!   external pid lock).
//! - Unit and integration tests.

use std::sync::OnceLock;
use std::time::Duration;

use super::{LockGuard, LockManager};
use super::internal_memory::InternalMemoryLockManager;

/// In-process named locks with a process-wide shared keyspace. See the
/// [module docs](self) for the comparison with
/// [`InternalMemoryLockManager`].
pub struct MemoryLockManager;

impl MemoryLockManager {
	pub fn new() -> Self {
		// Touch the static so initialization happens at construction
		// time rather than on first use.
		let _ = Self::shared();
		Self
	}

	fn shared() -> &'static InternalMemoryLockManager {
		static SHARED: OnceLock<InternalMemoryLockManager> = OnceLock::new();
		SHARED.get_or_init(InternalMemoryLockManager::new)
	}
}

impl Default for MemoryLockManager {
	fn default() -> Self { Self::new() }
}

impl std::fmt::Debug for MemoryLockManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("MemoryLockManager").finish()
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl LockManager for MemoryLockManager {
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>> {
		Self::shared().try_lock(key).await
	}

	async fn lock(&self, key: &str, timeout: Duration) -> anyhow::Result<Box<dyn LockGuard>> {
		Self::shared().lock(key, timeout).await
	}
}

// Uses `tokio::test` (tokio rt feature, desktop-only).
#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
	use super::*;

	#[tokio::test]
	async fn two_instances_share_keys() {
		let a = MemoryLockManager::new();
		let b = MemoryLockManager::new();
		let g = a.try_lock("bark.shared.test").await.unwrap();
		let busy = b.try_lock("bark.shared.test").await;
		assert!(busy.is_none(), "second instance should observe the lock");
		drop(g);
		let g2 = b.try_lock("bark.shared.test").await;
		assert!(g2.is_some(), "second instance can acquire after release");
	}
}
