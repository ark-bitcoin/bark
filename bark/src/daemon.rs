
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use log::{info, warn};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::Wallet;
use crate::onchain::DaemonizableOnchainWallet;

const FAST_INTERVAL: Duration = Duration::from_secs(1);
const MEDIUM_INTERVAL: Duration = Duration::from_secs(30);
const SLOW_INTERVAL: Duration = Duration::from_secs(60);

/// A handle to a running background daemon
pub struct DaemonHandle {
	shutdown: CancellationToken,
	jh: JoinHandle<()>,
}

impl DaemonHandle {
	/// Trigger the daemon process to stop
	pub fn stop(&self) {
		self.shutdown.cancel();
	}

	/// Stop the daemon process and wait for it to finish
	pub async fn stop_wait(self) -> anyhow::Result<()> {
		self.stop();
		self.jh.await?;
		Ok(())
	}
}

pub(crate) fn start_daemon(
	wallet: Arc<Wallet>,
	onchain: Arc<RwLock<dyn DaemonizableOnchainWallet>>,
) -> DaemonHandle {
	let shutdown = CancellationToken::new();
	let proc = DaemonProcess::new(shutdown.clone(), wallet, onchain);

	let jh = tokio::spawn(proc.run());

	DaemonHandle { shutdown, jh }
}

/// The daemon is responsible for running the wallet and performing the
/// necessary actions to keep the wallet in a healthy state
struct DaemonProcess {
	shutdown: CancellationToken,

	connected: AtomicBool,
	wallet: Arc<Wallet>,
	onchain: Arc<RwLock<dyn DaemonizableOnchainWallet>>,
}

impl DaemonProcess {
	fn new(
		shutdown: CancellationToken,
		wallet: Arc<Wallet>,
		onchain: Arc<RwLock<dyn DaemonizableOnchainWallet>>,
	) -> DaemonProcess {
		DaemonProcess {
			connected: AtomicBool::new(false),
			shutdown,
			wallet,
			onchain,
		}
	}

	/// Run lightning sync process
	/// - Try to claim all pending lightning receives
	/// - Sync pending lightning sends
	async fn run_lightning_sync(&self) {
		if let Err(e) = self.wallet.try_claim_all_lightning_receives(false).await {
			warn!("An error occured while checking and claiming pending lightning receives: {e:#}");
		}

		if let Err(e) = self.wallet.sync_pending_lightning_send_vtxos().await {
			warn!("An error occured while syncing pending lightning sends: {e:#}");
		}
	}

	/// Check for incoming arkoors
	async fn sync_mailbox(&self) {
		if let Err(e) = self.wallet.sync_mailbox().await {
			warn!("An error occurred while syncing mailbox: {e:#}");
		}
	}

	/// Sync pending boards, register new ones if needed
	async fn run_boards_sync(&self) {
		if let Err(e) = self.wallet.sync_pending_boards().await {
			warn!("An error occured while syncing pending board: {e:#}");
		}
	}

	/// Sync onchain wallet
	async fn run_onchain_sync(&self) {
		let mut onchain = self.onchain.write().await;
		if let Err(e) = onchain.sync(&self.wallet.chain).await {
			warn!("An error occured while syncing onchain: {e:#}");
		}
	}

	/// Perform library built-in maintenance refresh
	async fn run_maintenance_refresh_process(&self) {
		loop {
			if let Err(e) = self.wallet.maintenance_refresh().await {
				warn!("An error occured while performing maintenance refresh: {e:#}");
			}

			tokio::select! {
				_ = tokio::time::sleep(SLOW_INTERVAL) => {},

				_ = self.shutdown.cancelled() => {
					info!("Shutdown signal received! Shutting maintenance refresh process...");
					break;
				},
			}
		}
	}

	/// Progress any ongoing unilateral exits and sync the exit statuses
	async fn run_exits(&self) {
		let mut onchain = self.onchain.write().await;

		let mut exit_lock = self.wallet.exit.write().await;
		if let Err(e) = exit_lock.sync_no_progress(&*onchain).await {
			warn!("An error occurred while syncing exits: {e:#}");
		}

		if let Err(e) = exit_lock.progress_exits(&self.wallet, &mut *onchain, None).await {
			warn!("An error occurred while progressing exits: {e:#}");
		}
	}

	/// Subscribe to round event stream and process each incoming event
	async fn inner_process_pending_rounds(&self) -> anyhow::Result<()> {
		let mut events = self.wallet.subscribe_round_events().await?;

		loop {
			tokio::select! {
				res = events.next() => {
					let event = res.context("events stream broke")?
						.context("error on event stream")?;

					self.wallet.progress_pending_rounds(Some(&event)).await?;
				},
				_ = self.shutdown.cancelled() => {
					info!("Shutdown signal received! Shutting inner round events process...");
					return Ok(());
				},
			}
		}
	}

	/// Recursively resubscribe to round event stream by waiting and
	/// calling [Self::inner_process_pending_rounds] again until
	/// the daemon is shutdown.
	async fn run_round_events_process(&self) {
		loop {
			if self.connected.load(Ordering::Relaxed) {
				if let Err(e) = self.inner_process_pending_rounds().await {
					warn!("An error occured while processing pending rounds: {e:#}");
				}
			}

			tokio::select! {
				_ = tokio::time::sleep(SLOW_INTERVAL) => {},
				_ = self.shutdown.cancelled() => {
					info!("Shutdown signal received! Shutting round events process...");
					break;
				},
			}
		}
	}

	/// Run a process that will recursively check the server connection
	async fn run_server_connection_check_process(&self) {
		loop {
			tokio::select! {
				_ = tokio::time::sleep(FAST_INTERVAL) => {},
				_ = self.shutdown.cancelled() => {
					info!("Shutdown signal received! Shutting server connection check process...");
					break;
				},
			}

			let connected = self.wallet.refresh_server().await.is_ok();
			self.connected.store(connected, Ordering::Relaxed);
		}
	}

	async fn run_sync_processes(&self) {
		let mut fast_interval = tokio::time::interval(FAST_INTERVAL);
		fast_interval.reset();
		let mut medium_interval = tokio::time::interval(MEDIUM_INTERVAL);
		medium_interval.reset();
		let mut slow_interval = tokio::time::interval(SLOW_INTERVAL);
		slow_interval.reset();

		loop {
			tokio::select! {
				_ = fast_interval.tick() => {
					if !self.connected.load(Ordering::Relaxed) {
						continue;
					}

					self.run_lightning_sync().await;
					fast_interval.reset();
				},
				_ = medium_interval.tick() => {
					if !self.connected.load(Ordering::Relaxed) {
						continue;
					}

					self.sync_mailbox().await;
					self.run_boards_sync().await;
					medium_interval.reset();
				},
				_ = slow_interval.tick() => {
					if !self.connected.load(Ordering::Relaxed) {
						continue;
					}

					self.run_onchain_sync().await;
					self.run_exits().await;
					slow_interval.reset();
				},
				_ = self.shutdown.cancelled() => {
					info!("Shutdown signal received! Shutting sync processes...");
					break;
				},
			}
		}
	}

	pub async fn run(self) {
		let connected = self.wallet.server.read().is_some();
		self.connected.store(connected, Ordering::Relaxed);

		let _ = tokio::join!(
			self.run_server_connection_check_process(),
			self.run_round_events_process(),
			self.run_sync_processes(),
			self.run_maintenance_refresh_process(),
		);

		info!("Daemon gracefully stopped");
	}
}
