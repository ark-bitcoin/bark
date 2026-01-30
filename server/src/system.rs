
use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};
use std::time::{Duration, Instant};

use tokio::signal;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use crate::telemetry;

/// A struct to be held in scope while a process is working.
pub struct RuntimeWorker {
	mgr: RuntimeManager,
	name: String,
	critical: bool,

	extra_notify: Option<Arc<Notify>>,
}

impl RuntimeWorker {
	pub fn with_notify(mut self, notify: Arc<Notify>) -> Self {
		self.extra_notify = Some(notify);
		self
	}
}

impl std::ops::Drop for RuntimeWorker {
	fn drop(&mut self) {
		if let Some(ref notify) = self.extra_notify {
			notify.notify_waiters();
		}
		self.mgr.drop_worker(&self.name, self.critical);
	}
}

struct Inner {
	shutdown: CancellationToken,
	workers: AtomicUsize,
	notify: Notify,
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
				workers: AtomicUsize::new(0),
				notify: Notify::new(),
			}),
		}
	}

	/// Runs a thread that will watch for SIGTERM and ctrl-c signals.
	///
	/// Upon receipt, it will
	/// - call the [RuntimeManager::shutdown] method.
	/// - If [RuntimeManager::shutdown_done] does not return true within
	///   the `timeout` duration, it will exit the process forcibly.
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
			}

			let _ = rt.shutdown();
			let deadline = Instant::now() + timeout;
			while !rt.shutdown_done() {
				let now = Instant::now();
				if let Some(time_left) = deadline.checked_duration_since(now) {
					info!("Forced exit in {} seconds...", time_left.as_secs());
					tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
				} else {
					error!("Graceful shutdown took too long, exiting...");
					std::process::exit(0);
				}
			}
		});
	}

	fn drop_worker(&self, name: &str, critical: bool) {
		let old = self.inner.workers.fetch_sub(1, atomic::Ordering::SeqCst);
		assert_ne!(old, 0);
		self.inner.notify.notify_waiters();

		telemetry::worker_dropped(name);

		if critical && !self.inner.shutdown.is_cancelled() {
			slog!(CriticalWorkerStopped, name: name.into());
			self.shutdown();
		} else {
			slog!(WorkerStopped, name: name.into());
		}
	}

	fn inner_spawn(&self, name: impl AsRef<str>, critical: bool) -> RuntimeWorker {
		let _old = self.inner.workers.fetch_add(1, atomic::Ordering::SeqCst);
		self.inner.notify.notify_waiters();

		let name = name.as_ref();
		slog!(WorkerStarted, name: name.into(), critical);

		telemetry::worker_spawned(name);

		RuntimeWorker {
			mgr: self.clone(),
			name: name.into(),
			critical,
			extra_notify: None,
		}
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	pub fn spawn(&self, name: impl AsRef<str>) -> RuntimeWorker {
		self.inner_spawn(name, false)
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	///
	/// When a critical worker ends, shutdown will be triggered.
	pub fn spawn_critical(&self, name: impl AsRef<str>) -> RuntimeWorker {
		self.inner_spawn(name, true)
	}

	/// Start system shutdown.
	pub fn shutdown(&self) {
		self.inner.shutdown.cancel();
	}

	pub fn shutdown_done(&self) -> bool {
		self.inner.workers.load(atomic::Ordering::SeqCst) == 0
	}

	/// Wait for shutdown to finish.
	pub async fn wait(&self) {
		loop {
			if self.shutdown_done() {
				return;
			}
			self.inner.notify.notified().await;
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
