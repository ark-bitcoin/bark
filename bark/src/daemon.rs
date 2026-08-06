use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ark::rounds::RoundEvent;
use futures::{FutureExt, StreamExt};
use log::{info, trace, warn};
#[cfg(not(feature = "wasm-web"))]
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Wallet, WalletInner};
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
	wallet: &Wallet,
) -> DaemonHandle {
	let shutdown = CancellationToken::new();
	let proc = DaemonProcess::new(shutdown.clone(), wallet);

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

	/// Deliberately a [Weak] reference: the daemon task must not keep the
	/// wallet alive on its own. When the last user-held [Wallet] clone is
	/// dropped, [WalletInner]'s drop glue cancels `shutdown` and the daemon
	/// halts. See [DaemonProcess::wallet] for the upgrade rules.
	wallet: Weak<WalletInner>,

	/// Cached from the wallet config so the timer loops don't need to
	/// upgrade `wallet` just to know how long to sleep.
	sync_interval: Duration,

	/// Cached [crate::Config::daemon_manual_sync].
	manual_sync: bool,
}

impl DaemonProcess {
	fn new(
		shutdown: CancellationToken,
		wallet: &Wallet,
	) -> DaemonProcess {
		DaemonProcess {
			connected: AtomicBool::new(false),
			shutdown,
			sync_interval: Duration::from_secs(wallet.config().daemon_sync_interval_secs),
			manual_sync: wallet.config().daemon_manual_sync,
			wallet: Arc::downgrade(&wallet.inner),
		}
	}

	/// Upgrade the weak wallet reference for one unit of work.
	///
	/// The returned [Wallet] keeps the wallet alive for as long as it is
	/// held, so holds must stay bounded: a strong reference held across an
	/// always-on await point (like a message stream) would prevent the
	/// wallet's drop glue from ever cancelling the daemon, reintroducing
	/// the leak the [Weak] reference exists to fix.
	///
	/// Returns [None] once the last user-held [Wallet] clone is dropped;
	/// callers must treat that as a shutdown signal. The wallet's drop glue
	/// cancels our token in that case, but we cancel here too so a failed
	/// upgrade is a sufficient signal on its own.
	fn wallet(&self) -> Option<Wallet> {
		match self.wallet.upgrade() {
			Some(inner) => Some(Wallet { inner }),
			None => {
				self.shutdown.cancel();
				None
			},
		}
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
				trace!("Daemon subscribing to mailbox message stream");
				let r = Wallet::subscribe_process_mailbox_messages_weak(
					self.wallet.clone(), None, shutdown,
				).await;
				if let Err(e) = r {
					warn!("An error occurred while processing mailbox messages: {e:#}");
					self.connected.store(false, Ordering::Relaxed);
				}
			}

			futures::select! {
				_ = sleep(self.sync_interval).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting mailbox messages process...");
					break;
				},
			}
		}
	}

	async fn handle_round_event(&self, wallet: &Wallet, event: &RoundEvent) -> anyhow::Result<()> {
		// Do a refresh if you need to
		match &event {
			&RoundEvent::Attempt(attempt) => {
				if attempt.attempt_seq == 0 {
					if let Err(err) = wallet.join_round_for_maintenance_refresh(attempt).await {
						warn!("Failed to join round for maintenance refresh: {:#}", err);
					}
				};
			},
			_ => {},
		};

		wallet.progress_pending_rounds(Some(event)).await
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
		// Upgrade only to open the subscription: the stream owns just the
		// gRPC connection, so waiting on it doesn't keep the wallet alive.
		let mut events = {
			let Some(wallet) = self.wallet() else { return Ok(()) };
			trace!("Daemon subscribing to round event stream");
			wallet.subscribe_round_events().await?
		};
		trace!("Daemon connected to round event stream");

		loop {
			futures::select! {
				res = events.next().fuse() => {
					match res {
						Some(Ok(event)) => {
							backoff.reset();
							let Some(wallet) = self.wallet() else { return Ok(()) };
							if let Err(e) = self.handle_round_event(&wallet, &event).await {
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
				_ = sleep(self.sync_interval).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting server connection check process...");
					break;
				},
			}

			if self.connected.load(Ordering::Relaxed) {
				continue;
			}

			let Some(wallet) = self.wallet() else { break };
			let result = wallet.refresh_server().await;
			if let Err(ref e) = result {
				warn!("Ark server reconnect failed: {:#}", e);
			} else {
				info!("Ark server reconnected");
				self.connected.store(true, Ordering::Relaxed);
			}
		}
	}

	async fn run_sync_processes(&self) {
		// NB: tokio::time::interval needs Instant::now(), which panic on wasm
		loop {
			// using if let to scope the wallet variable
			if let Some(wallet) = self.wallet() {
				if self.connected.load(Ordering::Relaxed) {
					if let Err(e) = wallet.chain().update_fee_rates(wallet.config().fallback_fee_rate).await {
						warn!("An error occured while updating fee rates: {e:#}");
					}

					if let Err(e) = wallet.sync_pending_boards().await {
						warn!("An error occured while syncing pending board: {e:#}");
					}

					if let Err(e) = wallet.sync_pending_offboards().await {
						warn!("An error occured while syncing pending offboards: {e:#}");
					}
				}

				if let Err(e) = wallet.sync_onchain().await {
					warn!("An error occured while syncing onchain: {e:#}");
				}

				if let Err(e) = wallet.sync_pending_rounds().await {
					warn!("An error occured while syncing pending rounds: {e:#}");
				}
			} else {
				info!("Wallet has been dropped. Shutting down sync processes...");
				break;
			}

			futures::select! {
				_ = sleep(self.sync_interval).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting down sync processes...");
					break;
				},
			}
		}
	}

	/// Periodically progress unilateral exits.
	///
	/// This deliberately runs in its own loop rather than as part of
	/// [Self::run_sync_processes]: a repeatedly panicking sync step would
	/// restart that whole task from the top, and exit progression must not
	/// stay blocked behind it.
	async fn run_exit_progress_process(&self) {
		loop {
			if let Some(wallet) = self.wallet() {
				if wallet.inner.onchain.is_some() {
					if let Err(e) = wallet.exit_mgr().progress_exits_with_cpfp(&wallet, None).await {
						warn!("An error occurred while progressing exits: {:#}", e);
					}
				} else {
					if let Err(e) = wallet.exit_mgr().progress_exits(&wallet).await {
						warn!("An error occurred while progressing exits: {:#}", e);
					}
				}
			} else {
				info!("Wallet has been dropped. Shutting down exit progress process...");
				break;
			}

			futures::select! {
				_ = sleep(self.sync_interval).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting down exit progress process...");
					break;
				},
			}
		}
	}

	/// Run processes that only need to be run once on startup
	async fn run_startup_tasks(&self) {
		let Some(wallet) = self.wallet() else { return };

		// Eagerly refresh the server connection before starting the other
		// daemon tasks so they don't race the first connection check and
		// skip their initial iteration with `connected = false` (which
		// would delay mailbox subscription by `slow_interval`).
		let result = wallet.refresh_server().await;
		if let Err(ref e) = result {
			warn!("Ark server refresh failed: {:#}", e);
		}
		let connected = wallet.inner.server.initialized();
		self.connected.store(connected, Ordering::Relaxed);

		if !self.manual_sync {
			wallet.sync().await;
		}
	}

	pub async fn run(self) {
		{
			let Some(wallet) = self.wallet() else { return };
			info!("Starting daemon for wallet {}", wallet.fingerprint());
		}

		self.run_startup_tasks().await;
		trace!("Daemon startup tasks complete, starting background processes");

		if self.manual_sync {
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
				let p5 = Arc::clone(&proc);
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
					supervised("exit-progress", move || {
						let p = Arc::clone(&p4);
						async move { p.run_exit_progress_process().await }
					}),
					supervised("mailbox", move || {
						let p = Arc::clone(&p5);
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
					self.run_exit_progress_process(),
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
