
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};
use std::time::{Duration, Instant};

use tokio::signal;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use crate::telemetry;

/// A struct to be held in scope while a process is working.
pub struct WorkerGuard {
	mgr: RuntimeManager,
	id: u64,
	name: String,
	critical: bool,

	extra_notify: Option<Arc<Notify>>,
}

impl WorkerGuard {
	pub fn with_notify(mut self, notify: Arc<Notify>) -> Self {
		self.extra_notify = Some(notify);
		self
	}
}

impl std::ops::Drop for WorkerGuard {
	fn drop(&mut self) {
		if let Some(ref notify) = self.extra_notify {
			notify.notify_waiters();
		}
		self.mgr.drop_worker(self.id, &self.name, self.critical);
	}
}

struct Inner {
	shutdown: CancellationToken,
	workers: parking_lot::Mutex<HashMap<u64, String>>,
	next_id: AtomicU64,
	notify: Notify,
	/// The first critical worker that stopped before shutdown was requested.
	failed_worker: parking_lot::Mutex<Option<String>>,
}

/// Manager of thread coordination during runtime.
#[derive(Clone)]
pub struct RuntimeManager {
	inner: Arc<Inner>,
}

impl RuntimeManager {
	pub fn new() -> RuntimeManager {
		RuntimeManager {
			inner: Arc::new(Inner {
				shutdown: CancellationToken::new(),
				workers: parking_lot::Mutex::new(HashMap::new()),
				next_id: AtomicU64::new(0),
				failed_worker: parking_lot::Mutex::new(None),
				notify: Notify::new(),
			}),
		}
	}

	/// Runs a thread that will watch for SIGTERM and ctrl-c signals.
	///
	/// Upon receipt, or once shutdown starts otherwise, like when a critical
	/// worker stops, it will
	/// - call the [RuntimeManager::shutdown] method.
	/// - If [RuntimeManager::shutdown_complete] does not return true within
	///   the `timeout` duration, it will exit the process forcibly with
	///   status 1.
	pub fn run_shutdown_signal_listener(&self, timeout: Duration) {
		let rt = self.clone();
		tokio::spawn(async move {
			let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
				.expect("Failed to listen for SIGTERM");

			tokio::select! {
				_ = sigterm.recv() => info!("SIGTERM received! Sending shutdown signal..."),
				r = signal::ctrl_c() => match r {
					Ok(()) => info!("Ctrl+C received! Sending shutdown signal..."),
					Err(e) => panic!("failed to listen to ctrl-c signal: {e:#}"),
				},
				// A worker can be busy without watching for shutdown, like a
				// frontier reindex, so bound this shutdown too.
				_ = rt.shutdown_signal() => info!("Shutdown started, waiting for workers..."),
			}

			let _ = rt.shutdown();
			let deadline = Instant::now() + timeout;
			while !rt.shutdown_complete() {
				let now = Instant::now();
				if let Some(time_left) = deadline.checked_duration_since(now) {
					info!("Forced exit in {} seconds... Waiting on workers: {:?}",
						time_left.as_secs(), rt.remaining_worker_names());
					tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
				} else {
					error!("Graceful shutdown took too long, exiting... Remaining workers: {:?}",
						rt.remaining_worker_names());
					std::process::exit(1);
				}
			}
		});
	}

	fn drop_worker(&self, id: u64, name: &str, critical: bool) {
		// Held from removing the worker until the failure is decided, so a
		// concurrent shutdown can't complete in between.
		let mut failed = self.inner.failed_worker.lock();
		let removed = self.inner.workers.lock().remove(&id);
		assert!(removed.is_some(), "worker {} ({}) was not registered", id, name);
		let failed_now = critical && self.shutdown_for_failed_worker(&mut failed, name);
		drop(failed);

		telemetry::worker_dropped(name);

		if failed_now {
			slog!(CriticalWorkerStopped, name: name.into());
		} else {
			slog!(WorkerStopped, name: name.into());
		}

		// Only now, so a woken waiter also sees the shutdown started above.
		self.inner.notify.notify_waiters();
	}

	/// Record `name` as the failed worker and start shutdown, unless shutdown
	/// already started. Returns whether it did.
	fn shutdown_for_failed_worker(&self, failed: &mut Option<String>, name: &str) -> bool {
		if self.inner.shutdown.is_cancelled() {
			return false;
		}
		*failed = Some(name.to_owned());
		self.inner.shutdown.cancel();
		true
	}

	fn inner_spawn(&self, name: impl AsRef<str>, critical: bool) -> WorkerGuard {
		let id = self.inner.next_id.fetch_add(1, atomic::Ordering::SeqCst);
		let name = name.as_ref().to_string();
		self.inner.workers.lock().insert(id, name.clone());
		self.inner.notify.notify_waiters();

		slog!(WorkerStarted, name: name.clone(), critical);

		telemetry::worker_spawned(&name);

		WorkerGuard {
			mgr: self.clone(),
			id,
			name,
			critical,
			extra_notify: None,
		}
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	pub fn spawn(&self, name: impl AsRef<str>) -> WorkerGuard {
		self.inner_spawn(name, false)
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	///
	/// When a critical worker ends, shutdown will be triggered.
	pub fn spawn_critical(&self, name: impl AsRef<str>) -> WorkerGuard {
		self.inner_spawn(name, true)
	}

	/// Start system shutdown.
	pub fn shutdown(&self) {
		{
			// Serialized with a failing critical worker, which records its
			// name only if it starts the shutdown.
			let _failed = self.inner.failed_worker.lock();
			self.inner.shutdown.cancel();
		}
		self.inner.notify.notify_waiters();
	}

	pub fn shutdown_complete(&self) -> bool {
		self.shutdown_requested() && self.worker_count() == 0
	}

	/// The critical worker whose unexpected stop shut the system down, if any.
	pub fn failed_worker(&self) -> Option<String> {
		self.inner.failed_worker.lock().clone()
	}

	/// Whether [RuntimeManager::shutdown] has been called.
	pub fn shutdown_requested(&self) -> bool {
		self.inner.shutdown.is_cancelled()
	}

	/// Number of currently live workers.
	pub fn worker_count(&self) -> usize {
		self.inner.workers.lock().len()
	}

	/// Names of currently live workers. Useful for diagnosing slow shutdowns.
	pub fn remaining_worker_names(&self) -> Vec<String> {
		let mut names: Vec<String> = self.inner.workers.lock()
			.values().cloned().collect();
		names.sort();
		names
	}

	/// Wait for shutdown to finish.
	pub async fn wait(&self) {
		loop {
			// Register before checking, so a notification in between isn't lost.
			let mut notified = std::pin::pin!(self.inner.notify.notified());
			notified.as_mut().enable();
			if self.shutdown_complete() {
				return;
			}
			notified.await;
		}
	}

	/// Start system shutdown and wait for it to finish.
	pub async fn shutdown_wait(&self) {
		self.shutdown();
		self.wait().await;
	}

	pub fn shutdown_signal(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
		self.inner.shutdown.cancelled()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_empty_runtime_manager_shutdown() {
		let mgr = RuntimeManager::new();
		assert!(!mgr.shutdown_requested());
		assert!(!mgr.shutdown_complete());

		mgr.shutdown();
		assert!(mgr.shutdown_requested());
		assert!(mgr.shutdown_complete());
	}

	#[test]
	fn test_non_critical_worker_doesnt_trigger_shutdown() {
		let mgr = RuntimeManager::new();
		let guard1 = mgr.spawn("worker-1");
		let guard2 = mgr.spawn("worker-2");
		assert_eq!(mgr.worker_count(), 2);

		drop(guard1);
		assert_eq!(mgr.worker_count(), 1);
		assert!(!mgr.shutdown_requested());

		drop(guard2);
		assert_eq!(mgr.worker_count(), 0);
		assert!(!mgr.shutdown_requested());
	}

	#[test]
	fn test_duplicate_worker_names_are_independent() {
		let mgr = RuntimeManager::new();
		let guard1 = mgr.spawn("worker");
		let guard2 = mgr.spawn("worker");
		let guard3 = mgr.spawn("worker");
		assert_eq!(mgr.worker_count(), 3);

		drop(guard1);
		assert_eq!(mgr.worker_count(), 2);

		drop(guard2);
		assert_eq!(mgr.worker_count(), 1);

		drop(guard3);
		assert_eq!(mgr.worker_count(), 0);
		assert!(!mgr.shutdown_requested());
	}

	#[tokio::test]
	async fn test_critical_worker_triggers_shutdown() {
		let mgr = RuntimeManager::new();
		let guard1 = mgr.spawn_critical("critical-1");
		let guard2 = mgr.spawn_critical("critical-2");
		let guard3 = mgr.spawn_critical("critical-3");
		assert_eq!(mgr.worker_count(), 3);
		assert!(!mgr.shutdown_requested());

		let mgr2 = mgr.clone();
		tokio::spawn(async move {
			mgr2.shutdown_signal().await;
			drop(guard2);
		});
		let mgr3 = mgr.clone();
		tokio::spawn(async move {
			mgr3.shutdown_signal().await;
			drop(guard3);
		});

		drop(guard1);
		assert!(mgr.shutdown_requested());

		mgr.wait().await;
		assert_eq!(mgr.worker_count(), 0);
		assert!(mgr.shutdown_complete());
		// The others stopped because of the shutdown.
		assert_eq!(mgr.failed_worker().as_deref(), Some("critical-1"));
	}

	#[tokio::test]
	async fn test_wait_returns_when_the_last_worker_is_a_failing_critical_one() {
		let mgr = RuntimeManager::new();
		let guard = mgr.spawn_critical("critical");
		let waiting = tokio::spawn({
			let mgr = mgr.clone();
			async move { mgr.wait().await }
		});
		tokio::task::yield_now().await;
		drop(guard);
		tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await
			.expect("wait must return").unwrap();
		assert_eq!(mgr.failed_worker().as_deref(), Some("critical"));
	}

	#[tokio::test]
	async fn test_wait_returns_on_shutdown_without_workers() {
		let mgr = RuntimeManager::new();
		drop(mgr.spawn("worker"));
		let waiting = tokio::spawn({
			let mgr = mgr.clone();
			async move { mgr.wait().await }
		});
		tokio::task::yield_now().await;
		mgr.shutdown();
		tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await
			.expect("wait must return").unwrap();
		assert_eq!(mgr.failed_worker(), None);
	}

	#[test]
	fn test_requested_shutdown_has_no_failed_worker() {
		let mgr = RuntimeManager::new();
		let guard = mgr.spawn_critical("critical");
		mgr.shutdown();
		drop(guard);
		assert!(mgr.shutdown_complete());
		assert_eq!(mgr.failed_worker(), None);
	}
}
