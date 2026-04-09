
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use futures::{FutureExt, StreamExt};
use log::{info, warn};
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

	fn fast_interval(&self) -> Duration {
		Duration::from_secs(self.wallet.config().daemon_fast_sync_interval_secs)
	}

	fn slow_interval(&self) -> Duration {
		Duration::from_secs(self.wallet.config().daemon_slow_sync_interval_secs)
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

	/// Recursively resubscribe to mailbox message stream by waiting and
	/// calling [Wallet::subscribe_store_mailbox_messages] again until
	/// the daemon is shutdown.
	async fn run_mailbox_messages_process(&self) {
		loop {
			let shutdown = self.shutdown.clone();
			if self.connected.load(Ordering::Relaxed) {
				let r = self.wallet.subscribe_process_mailbox_messages(None, shutdown).await;
				if let Err(e) = r {
					warn!("An error occurred while processing mailbox messages: {e:#}");
				}
			}

			futures::select! {
				_ = tokio::time::sleep(self.slow_interval()).fuse() => {},
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

	/// Perform library built-in maintenance refresh
	async fn run_maintenance_refresh_process(&self) {
		if let Err(e) = self.wallet.maintenance_refresh().await {
			warn!("An error occured while performing maintenance refresh: {e:#}");
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

	/// Subscribe to round event stream and process each incoming event
	async fn inner_process_pending_rounds(&self) -> anyhow::Result<()> {
		let mut events = self.wallet.subscribe_round_events().await?;

		loop {
			futures::select! {
				res = events.next().fuse() => {
					let event = res.context("events stream broke")?
						.context("error on event stream")?;

					self.wallet.progress_pending_rounds(Some(&event)).await?;
				},
				_ = self.shutdown.cancelled().fuse() => {
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

			futures::select! {
				_ = tokio::time::sleep(self.slow_interval()).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting round events process...");
					break;
				},
			}
		}
	}

	/// Run a process that will recursively check the server connection
	async fn run_server_connection_check_process(&self) {
		loop {
			futures::select! {
				_ = tokio::time::sleep(self.fast_interval()).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting server connection check process...");
					break;
				},
			}

			let connected = self.wallet.refresh_server().await.is_ok();
			self.connected.store(connected, Ordering::Relaxed);
		}
	}

	async fn run_sync_processes(&self) {
		let mut fast_interval = tokio::time::interval(self.fast_interval());
		fast_interval.reset();
		let mut slow_interval = tokio::time::interval(self.slow_interval());
		slow_interval.reset();

		loop {
			futures::select! {
				_ = fast_interval.tick().fuse() => {
					if !self.connected.load(Ordering::Relaxed) {
						continue;
					}

					self.run_lightning_sync().await;
					fast_interval.reset();
				},
				_ = slow_interval.tick().fuse() => {
					if !self.connected.load(Ordering::Relaxed) {
						continue;
					}

					self.run_fee_rate_update().await;
					self.run_boards_sync().await;
					self.run_offboards_sync().await;
					self.run_maintenance_refresh_process().await;
					self.run_onchain_sync().await;
					self.run_exits().await;
					slow_interval.reset();
				},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting sync processes...");
					break;
				},
			}
		}
	}

	pub async fn run(self) {
		let connected = self.wallet.server.read().is_some();
		self.connected.store(connected, Ordering::Relaxed);

		let _ = futures::join!(
			self.run_server_connection_check_process(),
			self.run_round_events_process(),
			self.run_sync_processes(),
			self.run_mailbox_messages_process(),
		);

		info!("Daemon gracefully stopped");
	}
}
