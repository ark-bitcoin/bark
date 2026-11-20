pub mod tip_watcher;

use std::future::Future;
use std::sync::{Arc, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ark::rounds::RoundEvent;
use bark_runtime::Instant;
use futures::{FutureExt, StreamExt};
#[cfg(feature = "wasm-web")]
use futures::channel::oneshot;
#[cfg(feature = "wasm-web")]
use futures::future::AbortHandle;
use log::{info, trace, warn};
#[cfg(not(feature = "wasm-web"))]
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{Wallet, WalletInner};
use crate::utils::{RECONNECT_BACKOFF_MAX, ReconnectBackoff};


/// How long a restart lets the previous daemon
/// finish its work in flight before aborting it.
const RESTART_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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
	/// Aborts the daemon's task.
	abort: AbortHandle,
	/// Resolves once the daemon's task has finished or was aborted.
	done: oneshot::Receiver<()>,
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

	/// Stop the daemon process, wait up to `timeout` for it to finish its
	/// work in flight and abort whatever is still running after that.
	///
	/// An aborted task stops at its current await point, as if the process
	/// had been killed there, except that the locks it holds are released.
	///
	/// The daemon is also aborted if this future is dropped before the
	/// daemon has finished.
	#[cfg(not(feature = "wasm-web"))]
	async fn stop_wait_or_abort(self, timeout: Duration) {
		self.stop();

		let mut task = AbortOnDrop(self.jh);
		match bark_runtime::timeout(timeout, &mut task.0).await {
			Ok(Ok(())) => {},
			Ok(Err(e)) => warn!("Daemon terminated unexpectedly while stopping: {e}"),
			Err(_) => {
				warn!("Daemon still busy {timeout:?} after the stop signal, aborting its tasks");
				task.0.abort();
				let _ = (&mut task.0).await;
			},
		}
	}

	/// See the native variant.
	#[cfg(feature = "wasm-web")]
	async fn stop_wait_or_abort(self, timeout: Duration) {
		self.stop();

		let task = AbortOnDrop(self.abort);
		let mut done = self.done;
		if bark_runtime::timeout(timeout, &mut done).await.is_err() {
			warn!("Daemon still busy {timeout:?} after the stop signal, aborting its tasks");
			task.0.abort();
			let _ = done.await;
		}
	}
}

/// Run `fut` as the task of a daemon that shuts down on `shutdown`.
#[cfg(not(feature = "wasm-web"))]
fn spawn_daemon<F>(shutdown: CancellationToken, fut: F) -> DaemonHandle
where
	F: Future<Output = ()> + Send + 'static,
{
	DaemonHandle { shutdown, jh: crate::utils::spawn(fut) }
}

/// Run `fut` as the task of a daemon that shuts down on `shutdown`.
#[cfg(feature = "wasm-web")]
fn spawn_daemon<F>(shutdown: CancellationToken, fut: F) -> DaemonHandle
where
	F: Future<Output = ()> + 'static,
{
	let (fut, abort) = futures::future::abortable(fut);
	let (done_tx, done) = oneshot::channel();
	crate::utils::spawn(async move {
		let _ = fut.await;
		let _ = done_tx.send(());
	});
	DaemonHandle { shutdown, abort, done }
}

pub(crate) fn start_daemon(
	wallet: &Wallet,
) -> DaemonHandle {
	let shutdown = CancellationToken::new();
	let proc = DaemonProcess::new(shutdown.clone(), wallet);
	spawn_daemon(shutdown, proc.run())
}

/// Start a new daemon that first stops the `previous` one, if any.
///
/// A request the previous daemon has stuck on a dead connection can take
/// over a minute to fail, and it may hold a wallet lock the new daemon
/// needs. The previous daemon is therefore aborted if it has not finished
/// within [RESTART_DRAIN_TIMEOUT].
///
/// Stopping the previous daemon is part of the new daemon's task, so the
/// returned handle covers the whole restart: stopping it while the previous
/// daemon is still finishing keeps the new one from doing any work.
pub(crate) fn restart_daemon(
	wallet: &Wallet,
	previous: Option<DaemonHandle>,
) -> DaemonHandle {
	let shutdown = CancellationToken::new();
	let proc = DaemonProcess::new(shutdown.clone(), wallet);
	spawn_daemon(shutdown, async move {
		if let Some(previous) = previous {
			previous.stop_wait_or_abort(RESTART_DRAIN_TIMEOUT).await;
		}
		if proc.shutdown.is_cancelled() {
			info!("Daemon stopped before it finished restarting");
			return;
		}
		proc.run().await;
	})
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

	/// Keep the mailbox message subscription alive for the lifetime of
	/// the daemon, reconnecting as needed.
	///
	/// When the stream breaks or the server is marked unreachable, this
	/// process replaces the server connection itself and resubscribes
	/// after a reconnect backoff, which grows while attempts keep failing.
	///
	/// `connected` follows the outcome of that replacement, so other
	/// processes back off while the server is unreachable.
	async fn run_mailbox_messages_process(&self) {
		let mut backoff = ReconnectBackoff::new();
		loop {
			let mut needs_server_check = !self.connected.load(Ordering::Relaxed);
			if !needs_server_check {
				trace!("Daemon subscribing to mailbox message stream");
				let subscribed_at = Instant::now();
				let r = Wallet::subscribe_process_mailbox_messages_weak(
					self.wallet.clone(), None, self.shutdown.clone(),
				).await;
				if let Err(e) = r {
					warn!("An error occurred while processing mailbox messages: {e:#}");
					needs_server_check = true;
				}

				// A subscription that outlived the longest backoff step was
				// healthy, so the next reconnect is prompt again.
				if subscribed_at.elapsed() >= RECONNECT_BACKOFF_MAX {
					backoff.reset();
				}
			}

			futures::select! {
				_ = backoff.wait().fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting mailbox messages process...");
					break;
				},
			}

			if needs_server_check {
				let Some(wallet) = self.wallet() else {
					info!("Wallet has been dropped. Shutting down mailbox messages process...");
					break;
				};
				match wallet.reconnect_server().await {
					Ok(()) => self.connected.store(true, Ordering::Relaxed),
					Err(e) => {
						// The server connection check process reports
						// an unreachable server at a higher log level.
						trace!("Ark server reconnect before mailbox resubscribe failed: {e:#}");
						self.connected.store(false, Ordering::Relaxed);
					},
				}
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
	///
	/// While the server is marked unreachable, this process does not
	/// subscribe: a subscription on a connection that may have died
	/// hangs until its keepalive gives up.
	async fn run_round_events_process(&self) {
		let mut backoff = ReconnectBackoff::new();
		loop {
			if self.shutdown.is_cancelled() {
				info!("Shutdown signal received! Shutting round events process...");
				break;
			}

			if !self.connected.load(Ordering::Relaxed) {
				trace!("Round events subscription waits for the server to be reachable");
			} else {
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
				_ = bark_runtime::sleep(self.sync_interval).fuse() => {},
				_ = self.shutdown.cancelled().fuse() => {
					info!("Shutdown signal received! Shutting server connection check process...");
					break;
				},
			}

			if self.connected.load(Ordering::Relaxed) {
				continue;
			}

			let Some(wallet) = self.wallet() else { break };
			let result = wallet.reconnect_server().await;
			if let Err(ref e) = result {
				warn!("Ark server reconnect failed: {:#}", e);
			} else {
				info!("Ark server reconnected");
				self.connected.store(true, Ordering::Relaxed);
			}
		}
	}

	async fn run_sync_processes(&self) {
		// Watch the chain tip so new blocks trigger a sync pass immediately
		// instead of waiting for the full sync interval, which stays as a
		// backstop. On bitcoind the watcher listens on ZMQ when configured;
		// otherwise (including Esplora and wasm) it polls the backend.
		let mut tip_rx = match self.wallet() {
			Some(wallet) => match wallet.chain().tip_watcher(self.sync_interval).await {
				Ok(watcher) => Some(watcher.subscribe()),
				Err(e) => {
					warn!("Daemon failed to start tip watcher, syncing on interval only: {e:#}");
					None
				},
			},
			None => None,
		};

		// NB: a ticking interval needs Instant::now(), which panics on wasm,
		// so the loop sleeps between iterations instead.
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

					if let Err(e) = wallet.sync_pending_lightning_send_vtxos().await {
						warn!("An error occurred while syncing pending lightning sends: {e:#}");
					}

					if let Err(e) = wallet.sync_pending_arkoor_sends().await {
						warn!("An error occurred while syncing pending arkoor sends: {e:#}");
					}

					if let Err(e) = wallet.sync_pending_arkoor_receives().await {
						warn!("An error occurred while syncing pending arkoor receives: {e:#}");
					}

					// Ahead of the arkoor sends, so an arkoor send stuck on a
					// dead connection does not hold up a claim the payer waits on.
					if let Err(e) = wallet.sync_pending_lightning_receives().await {
						warn!("An error occurred while syncing pending lightning receives: {e:#}");
					}

					if let Err(e) = wallet.sync_pending_arkoor_sends().await {
						warn!("An error occurred while syncing pending arkoor sends: {e:#}");
					}
				}

				if let Err(e) = wallet.sync_onchain().await {
					warn!("An error occured while syncing onchain: {e:#}");
				}

				if let Err(e) = wallet.sync_pending_rounds().await {
					warn!("An error occured while syncing pending rounds: {e:#}");
				}

				// Runs last so the wallet state it scans is up to date.
				if let Err(e) = wallet.sync_force_exited_vtxos().await {
					warn!("An error occured while scanning for force-exited VTXOs: {e:#}");
				}
			} else {
				info!("Wallet has been dropped. Shutting down sync processes...");
				break;
			}

			futures::select! {
				_ = bark_runtime::sleep(self.sync_interval).fuse() => {},
				triggered = async {
					match tip_rx.as_mut() {
						Some(rx) => rx.changed().await.is_ok(),
						None => std::future::pending::<bool>().await,
					}
				}.fuse() => {
					if triggered {
						trace!("Daemon sync triggered by new chain tip");
					} else {
						warn!("Tip watcher stopped; daemon falls back to interval-only syncing");
						tip_rx = None;
					}
				},
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
					// Find new fee funds without waiting on the server-bound sync loop.
					// Not bounded: an esplora sync only applies once complete, and
					// CPFP needs the onchain wallet lock the sync holds anyway.
					if wallet.exit_mgr().has_pending_exits().await {
						futures::select! {
							res = wallet.sync_onchain().fuse() => if let Err(e) = res {
								warn!("An error occurred while syncing onchain for exits: {:#}", e);
							},
							_ = self.shutdown.cancelled().fuse() => {
								info!("Shutdown signal received! Shutting down exit progress process...");
								break;
							},
						}
					}

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
				_ = bark_runtime::sleep(self.sync_interval).fuse() => {},
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

		// Replace the server connection before starting the other daemon
		// tasks, so they don't race the first connection check and skip
		// their initial iteration with `connected = false`.
		//
		// If that fails, the existing connection may have died, so it does
		// not count as connected and the startup sync is skipped: a request
		// on a dead connection hangs until its keepalive gives up. The
		// mailbox process retries the replacement, and the periodic sync
		// resumes once it succeeds.
		if let Err(e) = wallet.reconnect_server().await {
			warn!("Ark server reconnect failed: {:#}", e);
			self.connected.store(false, Ordering::Relaxed);
			return;
		}
		self.connected.store(true, Ordering::Relaxed);

		if !self.manual_sync {
			wallet.sync().await;
		}
	}

	pub async fn run(self) {
		{
			let Some(wallet) = self.wallet() else { return };
			info!("Starting daemon for wallet {}", wallet.fingerprint());
		}

		if self.manual_sync {
			self.run_startup_tasks().await;
			// In manual-sync mode only the server connection heartbeat keeps
			// running; everything else must be triggered via the REST API.
			info!("Daemon running in manual-sync mode; background sync disabled");
			let _ = self.run_server_connection_check_process().await;
		} else {
			// Exit progression doesn't need the server, so it starts right away
			// instead of waiting for the startup tasks.
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
					supervised("exit-progress", move || {
						let p = Arc::clone(&p4);
						async move { p.run_exit_progress_process().await }
					}),
					async {
						proc.run_startup_tasks().await;
						trace!("Daemon startup tasks complete, starting background processes");
						futures::join!(
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
								let p = Arc::clone(&p5);
								async move { p.run_mailbox_messages_process().await }
							}),
						)
					},
				);
			}
			#[cfg(feature = "wasm-web")]
			{
				let _ = futures::join!(
					self.run_exit_progress_process(),
					async {
						self.run_startup_tasks().await;
						trace!("Daemon startup tasks complete, starting background processes");
						futures::join!(
							self.run_server_connection_check_process(),
							self.run_round_events_process(),
							self.run_sync_processes(),
							self.run_mailbox_messages_process(),
						)
					},
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
		// Abort the task when this future is dropped, so
		// aborting the daemon does not leave its tasks running.
		let mut task = AbortOnDrop(tokio::spawn(f()));
		match (&mut task.0).await {
			Ok(()) => break,
			Err(e) => {
				warn!("Daemon task '{}' terminated unexpectedly, restarting: {e}", name);
				bark_runtime::sleep(Duration::from_secs(1)).await;
			},
		}
	}
}

/// Aborts the wrapped task when dropped.
#[cfg(not(feature = "wasm-web"))]
struct AbortOnDrop(JoinHandle<()>);

#[cfg(not(feature = "wasm-web"))]
impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

/// Aborts the wrapped task when dropped.
#[cfg(feature = "wasm-web")]
struct AbortOnDrop(AbortHandle);

#[cfg(feature = "wasm-web")]
impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}
