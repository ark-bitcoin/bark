
use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};

use opentelemetry::metrics::Gauge;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;


/// A struct to be held in scope while a process is working.
pub struct RuntimeWorker {
	mgr: RuntimeManager,
	name: &'static str,
	critical: bool,
}

impl std::ops::Drop for RuntimeWorker {
	fn drop(&mut self) {
		self.mgr.drop_worker(self.name, self.critical);
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

	fn add_worker(&self) {
		let old = self.inner.workers.fetch_add(1, atomic::Ordering::SeqCst);
		self.inner.notify.notify_waiters();
		if let Some(ref gauge) = self.inner.spawn_gauge {
			gauge.record(old as u64 + 1, &[]);
		}
	}

	fn sub_worker(&self) {
		let old = self.inner.workers.fetch_sub(1, atomic::Ordering::SeqCst);
		assert_ne!(old, 0);
		self.inner.notify.notify_waiters();
		if let Some(ref gauge) = self.inner.spawn_gauge {
			gauge.record(old as u64 - 1, &[]);
		}
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	pub fn spawn(&self, name: &'static str) -> RuntimeWorker {
		self.add_worker();
		slog!(WorkerStarted, name: name.into());
		RuntimeWorker {
			mgr: self.clone(),
			name: name,
			critical: false,
		}
	}

	/// Create a worker that will inform the [RuntimeManager] when it goes out of scope.
	///
	/// When a critical worker ends, shutdown will be triggered.
	pub fn spawn_critical(&self, name: &'static str) -> RuntimeWorker {
		self.add_worker();
		slog!(WorkerStarted, name: name.into());
		RuntimeWorker {
			mgr: self.clone(),
			name: name,
			critical: true,
		}
	}

	fn drop_worker(&self, name: &'static str, critical: bool) {
		self.sub_worker();
		if critical && !self.inner.shutdown.is_cancelled() {
			slog!(CriticalWorkerStopped, name: name.into());
			self.shutdown();
		} else {
			slog!(WorkerStopped, name: name.into());
		}
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
