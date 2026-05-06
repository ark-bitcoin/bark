//! Named locks usable across async tasks, threads, processes, or browser
//! tabs — depending on the backend you pick.
//!
//! # What it is
//!
//! bark needs to coordinate access to a shared dataset (e.g. a wallet
//! database) so that two callers don't trample each other. The
//! [`LockManager`] trait is where you plug in *how that coordination is
//! enforced* on the target platform.
//!
//! Pick a manager whose enforcement scope matches the reach of the
//! dataset bark is opening:
//!
//! - A wallet that only ever runs in a single process? An in-memory
//!   manager is enough.
//! - A wallet running in the browser, possibly opened in multiple tabs?
//!   You need the Web Locks backend.
//!
//! Pick the wrong scope and bark will silently allow concurrent access.
//! The rest of this page is the picking guide.
//!
//! # Platform support
//!
//! | Backend                                            | Linux | macOS | iOS | Android | Windows | Web (wasm32) |
//! |----------------------------------------------------|:-----:|:-----:|:---:|:-------:|:-------:|:------------:|
//! | [`MemoryLockManager`](memory::MemoryLockManager)   |   ✓   |   ✓   |  ✓  |    ✓    |    ✓    |      ✓       |
//! | [`WebLockManager`](web_locks::WebLockManager)      |       |       |     |         |         |      ✓       |
//!
//! # Safety scope
//!
//! Each backend prevents concurrent access by callers under a different
//! scope. Pick the one that matches the threat you actually have:
//!
//! | Backend     | Same async runtime | Same OS process | Across processes | Across browser tabs |
//! |-------------|:------------------:|:---------------:|:----------------:|:-------------------:|
//! | `Memory`    |         ✓          |        ✓        |                  |                     |
//! | `WebLocks`  |         ✓          |    (n/a)        |     (n/a)        |          ✓          |
//!
//! # Picking a backend
//!
//! - **Single-process apps and tests** —
//!   [`MemoryLockManager`](memory::MemoryLockManager) is the safe
//!   default: every instance in the process shares one key map, so two
//!   callers cannot accidentally end up with disjoint lock universes.
//! - **Web (wasm32)** — only [`WebLockManager`](web_locks::WebLockManager)
//!   (which delegates to `navigator.locks`) is available. Prevents
//!   concurrent access across same-origin tabs in the same browser;
//!   gives no guarantees across different browsers or incognito
//!   sessions.
//!
//! # What callers must guarantee
//!
//! - **Use one backend per dataset, forever.** Two distinct managers do
//!   not exclude each other; mixing backends or directories on the same
//!   data is silently unsafe.
//! - **Use the same lock directory in every instance** for a given
//!   dataset.

mod key;
mod internal_memory;
pub mod memory;
#[cfg(target_arch = "wasm32")]
pub mod web_locks;

use std::time::Duration;
use anyhow::bail;

const POLL_INTERVAL: Duration = Duration::from_millis(50);


/// A handle that holds a named lock until dropped.
///
/// Trait objects are returned from [`LockManager`] methods so callers do
/// not need to spell the backend's concrete guard type.
pub trait LockGuard: Send + std::fmt::Debug {}

/// Acquire and release named locks.
///
/// Implementations only need to provide [`try_lock`](Self::try_lock); the
/// default [`lock`](Self::lock) polls it under a [`tokio::time::timeout`].
#[async_trait::async_trait]
pub trait LockManager: Send + Sync + std::fmt::Debug {
	/// Try to acquire the named lock without waiting. Returns `None` if
	/// it is already held, the key is rejected by [`validate_key`], or
	/// the backend cannot acquire the lock for any other reason.
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>>;

	/// Acquire the named lock, polling [`try_lock`](Self::try_lock) until
	/// it succeeds or `timeout` elapses.
	///
	/// `timeout` is mandatory to make accidental deadlocks impossible at
	/// the API level. Pass [`Duration::MAX`] if you really want to wait
	/// indefinitely.
	async fn lock(&self, key: &str, timeout: Duration)
		-> anyhow::Result<Box<dyn LockGuard>>
	{
		let result = tokio::time::timeout(timeout, async {
			loop {
				if let Some(g) = self.try_lock(key).await {
					return g;
				}
				tokio::time::sleep(POLL_INTERVAL).await;
			}
		}).await;
		match result {
			Ok(g) => Ok(g),
			Err(_) => bail!("timed out acquiring lock {:?} after {:?}", key, timeout),
		}
	}
}


// The shared test harness uses `tokio::spawn` / `tokio::sync::Barrier`
// / `tokio::time::timeout`, all of which require the `rt` feature that
// is desktop-only. The web_locks backend has its own wasm-bindgen-test
// suite in its module.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
	use super::*;

	use std::path::PathBuf;
	use std::fs;
	use std::sync::Arc;

	const TEST_TIMEOUT: Duration = Duration::from_secs(5);

	struct TestBackend {
		name: &'static str,
		mgr: Arc<dyn LockManager>,
		// `None` for backends that don't use a directory (Memory).
		dir: Option<PathBuf>,
	}

	impl Drop for TestBackend {
		fn drop(&mut self) {
			if let Some(d) = &self.dir {
				let _ = fs::remove_dir_all(d);
			}
		}
	}

	/// Every backend available on this target.
	fn managers() -> Vec<TestBackend> {
		let mut v = Vec::new();

		v.push(TestBackend {
			name: "InternalMemory",
			mgr: Arc::new(internal_memory::InternalMemoryLockManager::new()),
			dir: None,
		});

		v.push(TestBackend {
			name: "Memory",
			mgr: Arc::new(memory::MemoryLockManager::new()),
			dir: None,
		});

		#[cfg(target_arch = "wasm32")]
		{
			let _ = tmp_dir;
			v.push(TestBackend {
				name: "Web",
				mgr: Arc::new(web_locks::WebLockManager::new()),
				dir: None,
			});
		}

		v
	}

	#[tokio::test]
	async fn acquire_and_release() {
		for tb in managers() {
			let g = tb.mgr.lock("bark.ln_receive.1", TEST_TIMEOUT).await.unwrap();
			if let Some(d) = &tb.dir {
				assert!(d.join("bark.ln_receive.1.lock").exists(),
					"{} should create the lock file", tb.name);
			}
			drop(g);
			let _g2 = tb.mgr.lock("bark.ln_receive.1", TEST_TIMEOUT).await.unwrap();
		}
	}

	#[tokio::test]
	async fn try_lock_returns_none_when_held() {
		for tb in managers() {
			let g = tb.mgr.lock("k", TEST_TIMEOUT).await.unwrap();
			let busy = tb.mgr.try_lock("k").await;
			assert!(busy.is_none(), "{}: second try_lock should be blocked", tb.name);
			drop(g);
			let g2 = tb.mgr.try_lock("k").await;
			assert!(g2.is_some(), "{}: try_lock should succeed after release", tb.name);
		}
	}

	#[tokio::test]
	async fn distinct_keys_dont_block() {
		for tb in managers() {
			let _g1 = tb.mgr.lock("a", TEST_TIMEOUT).await.unwrap();
			let _g2 = tb.mgr.lock("b", TEST_TIMEOUT).await.unwrap();
		}
	}

	#[tokio::test]
	async fn lock_returns_timeout_error() {
		for tb in managers() {
			let _held = tb.mgr.lock("k", TEST_TIMEOUT).await.unwrap();

			// Acquire from another task so holding `_held` doesn't block
			// the test on its own memory-mutex wait.
			let mgr = Arc::clone(&tb.mgr);
			let result = tokio::spawn(async move {
				mgr.lock("k", Duration::from_millis(150)).await
			}).await.unwrap();

			assert!(result.is_err(), "{}: expected timeout, got {:?}", tb.name, result);
			assert!(result.unwrap_err().to_string().contains("timed out"));
		}
	}

	#[tokio::test]
	async fn waiter_unblocks_after_drop() {
		for tb in managers() {
			let g = tb.mgr.lock("k", TEST_TIMEOUT).await.unwrap();

			let mgr = Arc::clone(&tb.mgr);
			let waiter = tokio::spawn(async move {
				mgr.lock("k", TEST_TIMEOUT).await.unwrap()
			});

			tokio::time::sleep(Duration::from_millis(150)).await;
			drop(g);

			let result = tokio::time::timeout(Duration::from_secs(2), waiter).await;
			assert!(result.is_ok(), "{}: waiter should succeed after holder dropped", tb.name);
		}
	}

	#[tokio::test]
	async fn ten_concurrent_try_lock_only_one_wins() {
		// Asserts that `try_lock` is atomic under contention: when N
		// callers race for the same key, exactly one observes it as free.
		//
		// Force 10 tasks to call try_lock at the same point via a barrier.
		// Whichever the executor polls first will hold the guard for
		// 100 ms; that is long enough for the other 9 tasks to be polled
		// and observe the lock as held.
		use tokio::sync::Barrier;
		const N: usize = 10;

		for tb in managers() {
			let barrier = Arc::new(Barrier::new(N));
			let mut handles = Vec::with_capacity(N);

			for _ in 0..N {
				let mgr = Arc::clone(&tb.mgr);
				let barrier = Arc::clone(&barrier);
				handles.push(tokio::spawn(async move {
					barrier.wait().await;
					let guard = mgr.try_lock("contested").await;
					let acquired = guard.is_some();
					if acquired {
						tokio::time::sleep(Duration::from_millis(100)).await;
					}
					acquired
				}));
			}

			let mut successes = 0usize;
			for h in handles {
				successes += h.await.unwrap() as usize;
			}
			assert_eq!(
				successes, 1,
				"{}: expected exactly 1 successful try_lock out of {}, got {}",
				tb.name, N, successes,
			);
		}
	}

	#[tokio::test]
	async fn reject_bad_keys() {
		for tb in managers() {
			// Empty.
			assert!(tb.mgr.try_lock("").await.is_none(), "{}: empty", tb.name);
			// Disallowed character (path separator).
			assert!(tb.mgr.try_lock("a/b").await.is_none(), "{}: slash", tb.name);
			// Disallowed character (angle bracket).
			assert!(tb.mgr.try_lock("a<b>").await.is_none(), "{}: angle", tb.name);
			// Disallowed start (dot).
			assert!(tb.mgr.try_lock(".abc").await.is_none(), "{}: leading dot", tb.name);
			// Disallowed start (underscore).
			assert!(tb.mgr.try_lock("_abc").await.is_none(), "{}: leading underscore", tb.name);
			// Disallowed end (dash).
			assert!(tb.mgr.try_lock("abc-").await.is_none(), "{}: trailing dash", tb.name);
			// Disallowed end (dot).
			assert!(tb.mgr.try_lock("abc.").await.is_none(), "{}: trailing dot", tb.name);
			// Path-traversal sentinels.
			assert!(tb.mgr.try_lock(".").await.is_none(), "{}: dot", tb.name);
			assert!(tb.mgr.try_lock("..").await.is_none(), "{}: dotdot", tb.name);

			// Allowed: bark's actual key shapes.
			assert!(tb.mgr.try_lock("bark.lightning.send.42").await.is_some(),
				"{}: bark.lightning.send.42 should be valid", tb.name);
			// Allowed: digit start (hex wallet fingerprint).
			assert!(tb.mgr.try_lock("01abcdef.round.7").await.is_some(),
				"{}: 01abcdef.round.7 should be valid", tb.name);
		}
	}

	#[test]
	fn managers_covers_every_compiled_backend() {
		// If a backend is dropped from `managers()`, this assertion goes red.
		let names: Vec<_> = managers().iter().map(|tb| tb.name).collect();
		assert!(names.contains(&"Memory"), "missing Memory: {:?}", names);
		#[cfg(target_arch = "wasm32")]
		assert!(names.contains(&"Web"), "missing Web: {:?}", names);
	}
}
