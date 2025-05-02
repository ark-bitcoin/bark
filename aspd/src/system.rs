
use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};

use opentelemetry::metrics::Gauge;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;


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
	// For telemetry only.
	spawn_gauge: Option<Gauge<u64>>,
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
				spawn_gauge: None,
			}),
		}
	}

	pub fn new_with_telemetry(spawn_gauge: Gauge<u64>) -> RuntimeManager {
		RuntimeManager {
			inner: Arc::new(Inner {
				shutdown: CancellationToken::new(),
				workers: AtomicUsize::new(0),
				notify: Notify::new(),
				spawn_gauge: Some(spawn_gauge),
			}),
		}
	}

	fn drop_worker(&self, name: &str, critical: bool) {
		let old = self.inner.workers.fetch_sub(1, atomic::Ordering::SeqCst);
		assert_ne!(old, 0);
		self.inner.notify.notify_waiters();

		if let Some(ref gauge) = self.inner.spawn_gauge {
			gauge.record(old as u64 - 1, &[]);
		}

		if critical && !self.inner.shutdown.is_cancelled() {
			slog!(CriticalWorkerStopped, name: name.into());
			self.shutdown();
		} else {
			slog!(WorkerStopped, name: name.into());
		}
	}

	fn inner_spawn(&self, name: impl AsRef<str>, critical: bool) -> RuntimeWorker {
		let old = self.inner.workers.fetch_add(1, atomic::Ordering::SeqCst);
		self.inner.notify.notify_waiters();

		let name = name.as_ref();
		slog!(WorkerStarted, name: name.into(), critical);

		if let Some(ref gauge) = self.inner.spawn_gauge {
			gauge.record(old as u64 + 1, &[]);
		}

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
