//! In-process named locks with a per-instance keyspace.
//!
//! Each [`InternalMemoryLockManager`] owns its own key map: two
//! instances in the same process do **not** coordinate. This is what
//! file-based backends embed for in-process serialization — each
//! backend needs its own private map so two unrelated lock directories
//! don't falsely contend on the same key.
//!
//! Direct callers usually want
//! [`super::memory::MemoryLockManager`] instead, which has a
//! process-wide keyspace and removes the "two instances don't
//! coordinate" footgun. This module is crate-private for that reason.
//!
//! # Platform support
//!
//! All platforms. Pure Rust over `tokio::sync::Mutex`; no I/O, no
//! syscalls.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use super::{LockGuard, LockManager, key::validate_key};

/// How often `key_mutex` triggers an auto-purge of dead entries.
const DEFAULT_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// In-process locks keyed by string.
///
/// Holds a `Weak` per key so the per-key mutex is dropped automatically
/// once the last guard goes away. The map slot stays until either an
/// explicit [`purge`](Self::purge) or the periodic auto-purge sweeps it.
pub struct InternalMemoryLockManager {
	keys: parking_lot::Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
	last_purge: parking_lot::Mutex<Instant>,
	purge_interval: Duration,
}

impl InternalMemoryLockManager {
	pub fn new() -> Self {
		Self {
			keys: parking_lot::Mutex::new(HashMap::new()),
			last_purge: parking_lot::Mutex::new(Instant::now()),
			purge_interval: DEFAULT_PURGE_INTERVAL,
		}
	}

	/// Override the auto-purge interval. Intended for tests; production
	/// callers should leave the default in place.
	#[cfg(test)]
	fn set_purge_interval(&mut self, interval: Duration) {
		self.purge_interval = interval;
	}

	/// Drop map entries whose `Weak` no longer upgrades. Returns the
	/// number of entries removed. Safe to call at any time — live
	/// holders are never disturbed because their `Arc` keeps the `Weak`
	/// upgradable.
	pub fn purge(&self) -> usize {
		let mut keys = self.keys.lock();
		let before = keys.len();
		keys.retain(|_, weak| weak.strong_count() > 0);
		before - keys.len()
	}

	fn key_mutex(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
		self.maybe_purge();
		let mut keys = self.keys.lock();
		if let Some(weak) = keys.get(key) {
			if let Some(arc) = weak.upgrade() {
				return arc;
			}
		}
		let arc = Arc::new(tokio::sync::Mutex::new(()));
		keys.insert(key.to_string(), Arc::downgrade(&arc));
		arc
	}

	fn maybe_purge(&self) {
		let now = Instant::now();
		let mut last = self.last_purge.lock();
		if now.duration_since(*last) >= self.purge_interval {
			*last = now;
			drop(last);
			self.purge();
		}
	}
}

impl Default for InternalMemoryLockManager {
	fn default() -> Self { Self::new() }
}

impl std::fmt::Debug for InternalMemoryLockManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InternalMemoryLockManager").finish()
	}
}

#[async_trait::async_trait]
impl LockManager for InternalMemoryLockManager {
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>> {
		if let Err(e) = validate_key(key) {
			log::warn!("rejecting lock key {:?}: {:#}", key, e);
			return None;
		}
		let guard = self.key_mutex(key).try_lock_owned().ok()?;
		Some(Box::new(InternalMemoryGuard { _guard: guard }))
	}

	/// Override the polling default to use the underlying tokio mutex's
	/// wait queue, so contended waiters are woken on release rather than
	/// after the next poll tick.
	async fn lock(
		&self,
		key: &str,
		timeout: std::time::Duration,
	) -> anyhow::Result<Box<dyn LockGuard>> {
		super::key::validate_key(key)?;
		let mutex = self.key_mutex(key);
		match tokio::time::timeout(timeout, mutex.lock_owned()).await {
			Ok(guard) => Ok(Box::new(InternalMemoryGuard { _guard: guard })),
			Err(_) => anyhow::bail!(
				"timed out acquiring lock {:?} after {:?}", key, timeout,
			),
		}
	}
}

struct InternalMemoryGuard {
	_guard: tokio::sync::OwnedMutexGuard<()>,
}

impl LockGuard for InternalMemoryGuard {}

impl std::fmt::Debug for InternalMemoryGuard {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("InternalMemoryGuard").finish()
	}
}

// Uses `tokio::test` (tokio rt feature, desktop-only).
#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
	use super::*;

	#[tokio::test]
	async fn purge_drops_dead_entries_only() {
		let mut mgr = InternalMemoryLockManager::new();
		// Disable auto-purge so we test the explicit call in isolation.
		mgr.set_purge_interval(Duration::from_secs(3600));

		// Two entries whose Arcs we drop, one we keep live.
		{
			let _g = mgr.try_lock("dead-a").await.unwrap();
		}
		{
			let _g = mgr.try_lock("dead-b").await.unwrap();
		}
		let _alive = mgr.try_lock("alive").await.unwrap();

		assert_eq!(mgr.purge(), 2, "should drop the two dead entries");
		assert_eq!(mgr.purge(), 0, "second purge has nothing to do");
	}

	#[tokio::test]
	async fn auto_purges_on_try_lock_after_interval() {
		let mut mgr = InternalMemoryLockManager::new();
		// Every call triggers a purge.
		mgr.set_purge_interval(Duration::from_millis(0));

		{
			let _g = mgr.try_lock("dead").await.unwrap();
		}
		// The next try_lock should sweep "dead" before inserting "next".
		let _g = mgr.try_lock("next").await.unwrap();

		// Nothing left to reclaim — the auto-purge already ran.
		assert_eq!(mgr.purge(), 0);
	}
}
