use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ark::rounds::RoundEvent;
use futures::{FutureExt, StreamExt};
use log::{info, trace, warn};
use tokio::sync::RwLock;
#[cfg(not(feature = "wasm-web"))]
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::Wallet;
use crate::onchain::OnchainWalletTrait;
use crate::utils::ReconnectBackoff;
use crate::utils::time::sleep;



/// A handle to a running background daemon
#[cfg(not(feature = "wasm-web"))]
pub struct DaemonHandle {
	shutdown: CancellationToken,
	jh: JoinHandle<()>,
}

/// A handle to a running background daemon for WASM
#[cfg(feature = "wasm-web")]
pub struct DaemonHandle {
	shutdown: CancellationToken,
}

impl DaemonHandle {
	/// Trigger the daemon process to stop
	pub fn stop(&self) {
		self.shutdown.cancel();
	}

	/// Stop the daemon process and wait for it to finish
	pub async fn stop_wait(self) -> anyhow::Result<()> {
		self.stop();
		#[cfg(not(feature = "wasm-web"))]
		self.jh.await?;
		Ok(())
	}
}

pub(crate) fn start_daemon(
	wallet: Wallet,
	onchain: Option<Arc<RwLock<dyn OnchainWalletTrait>>>,
) -> DaemonHandle {
	let shutdown = CancellationToken::new();
	let proc = DaemonProcess::new(shutdown.clone(), wallet, onchain);

	#[cfg(not(feature = "wasm-web"))]
	{
		let jh = crate::utils::spawn(proc.run());
		DaemonHandle { shutdown, jh }
	}
	#[cfg(feature = "wasm-web")]
	{
		crate::utils::spawn(proc.run());
		DaemonHandle { shutdown }
	}
}

/// The daemon is responsible for running the wallet and performing the
/// necessary actions to keep the wallet in a healthy state
struct DaemonProcess {
	shutdown: CancellationToken,

	connected: AtomicBool,
	wallet: Wallet,
	onchain: Option<Arc<RwLock<dyn OnchainWalletTrait>>>,
}

impl DaemonProcess {
	fn new(
		shutdown: CancellationToken,
		wallet: Wallet,
		onchain: Option<Arc<RwLock<dyn OnchainWalletTrait>>>,
	) -> DaemonProcess {
		DaemonProcess {
			connected: AtomicBool::new(false),
			shutdown,
			wallet,
			onchain,
		}
	}

	fn sync_interval(&self) -> Duration {
		Duration::from_secs(self.wallet.config().daemon_sync_interval_secs)
	}

	/// Recursively resubscribe to mailbox message stream by waiting and
	/// calling [Wallet::subscribe_store_mailbox_messages] again until
	/// the daemon is shutdown.
	///
	/// The mailbox stream is always-on and sets `connected` to `false`
	/// when it breaks, so other processes can back off.
	async fn run_mailbox_messages_process(&self) {
		loop {
			let shutdown = self.shutdown.clone();
			if self.connected.load(Ordering::Relaxed) {
				let r = self.wallet.subscribe_process_mailbox_messages(None, shutdown).await;
				if let Err(e) = r {
					warn!("An error occurred while processing mailbox messages: {e:#}");
					self.connected.store(false, Ordering::Relaxed);
				}
			}

			futures::select! {
				_ = sleep(self.sync_interval()).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting mailbox messages process...");
					break;
				},
			}
		}
	}

	/// Sync pending boards, register new ones if needed
	async fn run_boards_sync(&self) {
		if let Err(e) = self.wallet.sync_pending_boards().await {
			warn!("An error occured while syncing pending board: {e:#}");
		}
	}

	/// Sync pending offboards, check for confirmations
	async fn run_offboards_sync(&self) {
		if let Err(e) = self.wallet.sync_pending_offboards().await {
			warn!("An error occured while syncing pending offboards: {e:#}");
		}
	}

	/// Sync pending rounds, check for confirmations and finalize VTXOs
	async fn run_rounds_sync(&self) {
		if let Err(e) = self.wallet.sync_pending_rounds().await {
			warn!("An error occured while syncing pending rounds: {e:#}");
		}
	}

	/// Update cached fee rates from the chain source
	async fn run_fee_rate_update(&self) {
		if let Err(e) = self.wallet.chain().update_fee_rates(self.wallet.config().fallback_fee_rate).await {
			warn!("An error occured while updating fee rates: {e:#}");
		}
	}

	/// Sync onchain wallet
	async fn run_onchain_sync(&self) {
		if let Some(onchain) = &self.onchain {
			let mut onchain = onchain.write().await;
			if let Err(e) = onchain.sync(self.wallet.chain()).await {
				warn!("An error occured while syncing onchain: {e:#}");
			}
		}
	}

	/// Progress any ongoing unilateral exits and sync the exit statuses
	async fn run_exits(&self) {
		if let Some(onchain) = &self.onchain {
			let mut onchain = onchain.write().await;
			if let Err(e) = self.wallet.exit_mgr().progress_exits_with_bdk(&self.wallet, &mut *onchain, None).await {
				warn!("An error occurred while progressing exits: {e:#}");
			}
		}
	}

	async fn handle_round_event(&self, event: &RoundEvent) -> anyhow::Result<()> {
		// Do a refresh if you need to
		match &event {
			&RoundEvent::Attempt(attempt) => {
				if attempt.attempt_seq == 0 {
					if let Err(err) = self.wallet.join_round_for_maintenance_refresh(attempt).await {
						warn!("Failed to join round for maintenance refresh: {:#}", err);
					}
				};
			},
			_ => {},
		};

		self.wallet.progress_pending_rounds(Some(event)).await
	}

	/// Subscribe to the round event stream and process events
	/// until it closes or the daemon shuts down.
	///
	/// `backoff` is reset whenever an event arrives, so a stream that stays
	/// healthy for a while reconnects promptly after it eventually drops.
	async fn process_round_event_stream(
		&self,
		backoff: &mut ReconnectBackoff,
	) -> anyhow::Result<()> {
		let mut events = self.wallet.subscribe_round_events().await?;

		loop {
			futures::select! {
				res = events.next().fuse() => {
					match res {
						Some(Ok(event)) => {
							backoff.reset();
							if let Err(e) = self.handle_round_event(&event).await {
								warn!("Error processing round event: {e:#}");
							}
						},
						Some(Err(e)) => {
							return Err(e.context("error on event stream"));
						},
						None => {
							return Ok(());
						},
					}
				},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting round events stream...");
					return Ok(());
				},
			}
		}
	}

	/// Keep the round events subscription alive for the
	/// lifetime of the daemon, reconnecting as needed.
	async fn run_round_events_process(&self) {
		let mut backoff = ReconnectBackoff::new();
		loop {
			if self.shutdown.is_cancelled() {
				info!("Shutdown signal received! Shutting round events process...");
				break;
			}

			match self.process_round_event_stream(&mut backoff).await {
				Ok(()) => {},
				// A tonic h2 stream reset is almost always a
				// proxy- or server-side idle timeout rather than
				// a real failure; resubscribe quietly.
				Err(e) if crate::utils::is_h2_stream_error(&e) => {
					trace!("Round events stream reset by server, reconnecting: {e:#}");
				},
				Err(e) => {
					warn!("An error occured while processing pending rounds: {e:#}");
				},
			}

			// Always back off before resubscribing. Otherwise a stream the
			// server keeps closing quickly — including when it is rate-limiting
			// us by resetting our streams — becomes a tight reconnect loop that
			// floods the server with opened-then-reset streams. The backoff
			// resets itself once a stream delivers an event, so healthy
			// reconnects stay prompt.
			futures::select! {
				_ = backoff.wait().fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting round events process...");
					break;
				},
			}
		}
	}

	/// Periodically try to reconnect when the server is not reachable.
	///
	/// Sets `connected` to `true` on success so the round-events
	/// and mailbox streams start subscribing again.
	async fn run_server_connection_check_process(&self) {
		loop {
			futures::select! {
				_ = sleep(self.sync_interval()).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting server connection check process...");
					break;
				},
			}

			if self.connected.load(Ordering::Relaxed) {
				continue;
			}

			let result = self.wallet.refresh_server().await;
			if let Err(ref e) = result {
				warn!("Ark server reconnect failed: {:#}", e);
			} else {
				info!("Ark server reconnected");
				self.connected.store(true, Ordering::Relaxed);
			}
		}
	}

	async fn run_sync_processes(&self) {
		let mut sync_interval = tokio::time::interval(self.sync_interval());

		loop {
			futures::select! {
				_ = sync_interval.tick().fuse() => {
					if self.connected.load(Ordering::Relaxed) {
						self.run_fee_rate_update().await;
						self.run_boards_sync().await;
						self.run_offboards_sync().await;
					}
					self.run_onchain_sync().await;
					self.run_rounds_sync().await;
					self.run_exits().await;
					sync_interval.reset();
				},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting sync processes...");
					break;
				},
			}
		}
	}

	/// Run processes that only need to be run once on startup
	async fn run_startup_tasks(&self) {
		// Eagerly refresh the server connection before starting the other
		// daemon tasks so they don't race the first connection check and
		// skip their initial iteration with `connected = false` (which
		// would delay mailbox subscription by `slow_interval`).
		let result = self.wallet.refresh_server().await;
		if let Err(ref e) = result {
			warn!("Ark server refresh failed: {:#}", e);
		}
		let connected = self.wallet.inner.server.initialized();
		self.connected.store(connected, Ordering::Relaxed);

		if !self.wallet.config().daemon_manual_sync {
			self.wallet.sync().await;
		}
	}

	pub async fn run(self) {
		info!("Starting daemon for wallet {}", self.wallet.fingerprint());

		self.run_startup_tasks().await;

		if self.wallet.config().daemon_manual_sync {
			// In manual-sync mode only the server connection heartbeat keeps
			// running; everything else must be triggered via the REST API.
			info!("Daemon running in manual-sync mode; background sync disabled");
			let _ = self.run_server_connection_check_process().await;
		} else {
			#[cfg(not(feature = "wasm-web"))]
			{
				// Each loop runs in its own tokio task so that a panic in one
				// (e.g. from a crafted round proposal) cannot silently kill the
				// others — in particular exit monitoring / CPFP fee-bumping.
				let proc = Arc::new(self);
				let p1 = Arc::clone(&proc);
				let p2 = Arc::clone(&proc);
				let p3 = Arc::clone(&proc);
				let p4 = Arc::clone(&proc);
				let _ = futures::join!(
					supervised("server-connection", move || {
						let p = Arc::clone(&p1);
						async move { p.run_server_connection_check_process().await }
					}),
					supervised("round-events", move || {
						let p = Arc::clone(&p2);
						async move { p.run_round_events_process().await }
					}),
					supervised("sync", move || {
						let p = Arc::clone(&p3);
						async move { p.run_sync_processes().await }
					}),
					supervised("mailbox", move || {
						let p = Arc::clone(&p4);
						async move { p.run_mailbox_messages_process().await }
					}),
				);
			}
			#[cfg(feature = "wasm-web")]
			{
				let _ = futures::join!(
					self.run_server_connection_check_process(),
					self.run_round_events_process(),
					self.run_sync_processes(),
					self.run_mailbox_messages_process(),
				);
			}
		}

		info!("Daemon gracefully stopped");
	}
}

/// Run `f` in its own [`tokio::spawn`] task, restarting it if it panics.
///
/// A clean return (shutdown signal) breaks the loop immediately.
#[cfg(not(feature = "wasm-web"))]
async fn supervised<F, Fut>(name: &'static str, f: F)
where
	F: Fn() -> Fut,
	Fut: std::future::Future<Output = ()> + Send + 'static,
{
	loop {
		match tokio::spawn(f()).await {
			Ok(()) => break,
			Err(e) => {
				warn!("Daemon task '{}' terminated unexpectedly, restarting: {e}", name);
				tokio::time::sleep(Duration::from_secs(1)).await;
			},
		}
	}
}
