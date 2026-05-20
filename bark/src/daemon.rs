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
use crate::onchain::DaemonizableOnchainWallet;


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
	wallet: Arc<Wallet>,
	onchain: Option<Arc<RwLock<dyn DaemonizableOnchainWallet>>>,
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
	wallet: Arc<Wallet>,
	onchain: Option<Arc<RwLock<dyn DaemonizableOnchainWallet>>>,
}

impl DaemonProcess {
	fn new(
		shutdown: CancellationToken,
		wallet: Arc<Wallet>,
		onchain: Option<Arc<RwLock<dyn DaemonizableOnchainWallet>>>,
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
				_ = tokio::time::sleep(self.sync_interval()).fuse() => {},
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
		if let Err(e) = self.wallet.chain.update_fee_rates(self.wallet.config.fallback_fee_rate).await {
			warn!("An error occured while updating fee rates: {e:#}");
		}
	}

	/// Sync onchain wallet
	async fn run_onchain_sync(&self) {
		if let Some(onchain) = &self.onchain {
			let mut onchain = onchain.write().await;
			if let Err(e) = onchain.sync(&self.wallet.chain).await {
				warn!("An error occured while syncing onchain: {e:#}");
			}
		}
	}

	/// Progress any ongoing unilateral exits and sync the exit statuses
	async fn run_exits(&self) {
		if let Some(onchain) = &self.onchain {
			let mut onchain = onchain.write().await;
			let mut exit_lock = self.wallet.exit.write().await;
			if let Err(e) = exit_lock.sync_no_progress(&*onchain).await {
				warn!("An error occurred while syncing exits: {e:#}");
			}

			if let Err(e) = exit_lock.progress_exits(&self.wallet, &mut *onchain, None).await {
				warn!("An error occurred while progressing exits: {e:#}");
			}
		}
	}

	async fn handle_round_event(&self, event: &RoundEvent) -> anyhow::Result<()> {
		// Do a refresh if you need to
		match &event {
			&RoundEvent::Attempt(attempt) => {
				if attempt.attempt_seq == 0 {
					match self.wallet.maybe_schedule_maintenance_refresh().await {
						Ok(_) => {},
						Err(err) => warn!("Failed to schedule maintenance refresh: {:?}", err),
					}
				};
			},
			_ => {},
		};

		self.wallet.progress_pending_rounds(Some(event)).await
	}

	/// Subscribe to the round event stream and process events
	/// until it closes or the daemon shuts down.
	async fn process_round_event_stream(&self) -> anyhow::Result<()> {
		let mut events = self.wallet.subscribe_round_events().await?;

		loop {
			futures::select! {
				res = events.next().fuse() => {
					match res {
						Some(Ok(event)) => {
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
		loop {
			if self.shutdown.is_cancelled() {
				info!("Shutdown signal received! Shutting round events process...");
				break;
			}

			let started_at = std::time::Instant::now();
			if let Err(e) = self.process_round_event_stream().await {
				warn!("An error occured while processing pending rounds: {e:#}");
			}

			if started_at.elapsed() >= crate::HEALTHY_STREAM_DURATION {
				trace!("Round events stream closed after healthy session, reconnecting");
				continue;
			}

			futures::select! {
				_ = tokio::time::sleep(self.sync_interval()).fuse() => {},
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
				_ = tokio::time::sleep(self.sync_interval()).fuse() => {},
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
		let connected = self.wallet.server.initialized();
		self.connected.store(connected, Ordering::Relaxed);

		if !self.wallet.config.daemon_manual_sync {
			self.wallet.sync().await;
		}
	}

	pub async fn run(self) {
		info!("Starting daemon for wallet {}", self.wallet.fingerprint());

		self.run_startup_tasks().await;

		if self.wallet.config.daemon_manual_sync {
			// In manual-sync mode only the server connection heartbeat keeps
			// running; everything else must be triggered via the REST API.
			info!("Daemon running in manual-sync mode; background sync disabled");
			let _ = self.run_server_connection_check_process().await;
		} else {
			let _ = futures::join!(
				self.run_server_connection_check_process(),
				self.run_round_events_process(),
				self.run_sync_processes(),
				self.run_mailbox_messages_process(),
			);
		}

		info!("Daemon gracefully stopped");
	}
}
