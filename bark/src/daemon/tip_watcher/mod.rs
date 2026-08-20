//! Watch blockchain tip changes.

mod polling;
mod source;
#[cfg(all(feature = "bitcoind-rpc", not(target_arch = "wasm32")))]
mod zmq;

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use bark_runtime::CancellationToken;
use bitcoin_ext::BlockRef;

pub use source::TipSource;

use polling::PollingTipWatcher;
#[cfg(all(feature = "bitcoind-rpc", not(target_arch = "wasm32")))]
use zmq::ZmqTipWatcher;

#[derive(Clone)]
pub struct TipWatcher {
	shutdown: CancellationToken,
	/// Stops the watcher task once the last clone is dropped.
	_shutdown_on_drop: Arc<ShutdownGuard>,
	rx: watch::Receiver<BlockRef>,
}

struct ShutdownGuard(CancellationToken);

impl Drop for ShutdownGuard {
	fn drop(&mut self) {
		self.0.cancel();
	}
}

impl TipWatcher {
	fn new(shutdown: CancellationToken, rx: watch::Receiver<BlockRef>) -> Self {
		let guard = ShutdownGuard(shutdown.clone());
		Self { shutdown, _shutdown_on_drop: Arc::new(guard), rx }
	}

	pub async fn start_poll<S: TipSource + 'static>(
		source: Arc<S>,
		poll_interval: Duration,
	) -> anyhow::Result<Self> {
		let initial = source.tip_ref().await?;
		let (tx, rx) = watch::channel(initial);
		let shutdown = CancellationToken::new();
		let proc = PollingTipWatcher {
			source,
			poll_interval,
			shutdown: shutdown.clone(),
			tx,
		};

		bark_runtime::spawn(proc.run());
		Ok(Self::new(shutdown, rx))
	}

	/// Start a watcher that follows the chain tip of `source`.
	///
	/// The watcher has two sources of tip updates and trusts both.
	///
	/// bitcoind announces the hash of each new block on `zmq_endpoint`.
	/// The watcher makes this hash the new tip and increases the height
	/// by one. No backend call is necessary for this update.
	///
	/// After each `reconcile_interval`, the watcher reads the tip from
	/// `source`. A changed value becomes the new tip. This read corrects
	/// the tip after a lost notification or a reorg.
	#[cfg(all(feature = "bitcoind-rpc", not(target_arch = "wasm32")))]
	pub async fn start_zmq<S: TipSource + 'static>(
		source: Arc<S>,
		zmq_endpoint: &str,
		reconcile_interval: Duration,
	) -> anyhow::Result<Self> {
		let socket = zmq::connect(zmq_endpoint).await?;
		let initial = source.tip_ref().await?;
		let (tx, rx) = watch::channel(initial);
		let shutdown = CancellationToken::new();

		let proc = ZmqTipWatcher {
			source,
			reconcile_interval,
			shutdown: shutdown.clone(),
			tx,
			socket,
		};

		bark_runtime::spawn(proc.run());
		Ok(Self::new(shutdown, rx))
	}

	pub fn tip(&self) -> BlockRef {
		*self.rx.borrow()
	}

	/// Subscribe to tip changes.
	///
	/// The subscription keeps the watcher task alive.
	pub fn subscribe(&self) -> TipSubscription {
		TipSubscription {
			rx: self.rx.clone(),
			_shutdown_on_drop: self._shutdown_on_drop.clone(),
		}
	}

	/// Wait until the tip reaches the given height.
	pub async fn wait_for_height(&self, height: u32) -> anyhow::Result<BlockRef> {
		// watch::Receiver::wait_for needs a mutable receiver,
		// so we subscribe with our own copy
		let mut subscription = self.rx.clone();
		let tip = subscription.wait_for(|tip| tip.height >= height).await?;
		Ok(*tip)
	}

	pub fn stop(&self) {
		self.shutdown.cancel();
	}
}

/// A subscription to tip changes handed out by [TipWatcher::subscribe].
///
/// Keeps the watcher task alive for as long as it is held.
#[derive(Clone)]
pub struct TipSubscription {
	rx: watch::Receiver<BlockRef>,
	_shutdown_on_drop: Arc<ShutdownGuard>,
}

impl TipSubscription {
	/// The current tip.
	pub fn tip(&self) -> BlockRef {
		*self.rx.borrow()
	}

	/// Wait for the tip to change and return the new tip.
	///
	/// Errors when the watcher task has stopped, e.g. after
	/// [TipWatcher::stop] or when its backend connection broke.
	pub async fn changed(&mut self) -> anyhow::Result<BlockRef> {
		self.rx.changed().await?;
		// borrow_and_update marks the returned value as seen, so the next
		// call only wakes for a tip newer than the one returned here.
		Ok(*self.rx.borrow_and_update())
	}
}
