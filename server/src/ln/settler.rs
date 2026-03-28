
use std::time::Duration;

use async_stream::stream;
use futures::Stream;
use tokio::sync::watch;
use tracing::info;

use ark::lightning::{PaymentHash, Preimage};

use crate::database::{Checkpoint, Db};
use crate::system::RuntimeManager;

const DEFAULT_BATCH_SIZE: usize = 100;

pub struct Settlement {
	pub checkpoint: Checkpoint,
	pub hash: PaymentHash,
	pub preimage: Preimage,
}

/// A [`tokio::sync::watch`] channel that only moves forward.
///
/// Callers use [`subscribe`](Self::subscribe) to obtain a standard
/// [`watch::Receiver<Checkpoint>`] and interact with it directly.
#[derive(Clone)]
struct MonotonicWatch {
	tx: watch::Sender<Checkpoint>,
}

impl MonotonicWatch {
	fn new(initial: Checkpoint) -> Self {
		let (tx, _rx) = watch::channel(initial);
		Self { tx }
	}

	/// Update the stored checkpoint if `value` is strictly greater than
	/// the current one.
	fn update(&self, value: Checkpoint) {
		self.tx.send_if_modified(|current| {
			if value > *current {
				*current = value;
				true
			} else {
				false
			}
		});
	}

	fn subscribe(&self) -> watch::Receiver<Checkpoint> {
		self.tx.subscribe()
	}
}

pub struct HtlcSettler {
	db: Db,
	watch: MonotonicWatch,
	batch_size: usize,
}

impl HtlcSettler {
	pub fn start(db: Db, rtmgr: RuntimeManager, poll_interval: Duration) -> Self {
		let watch = MonotonicWatch::new(0);

		let process = Process {
			db: db.clone(),
			watch: watch.clone(),
			poll_interval,
		};
		tokio::spawn(process.run(rtmgr));

		HtlcSettler { db, watch, batch_size: DEFAULT_BATCH_SIZE }
	}

	pub fn batch_size(&mut self, batch_size: usize) {
		self.batch_size = batch_size;
	}

	/// Record a settlement: write preimage to the WAL table, notify watchers.
	/// If this preimage was already recorded, this is a no-op.
	pub async fn settle(&self, preimage: Preimage) -> anyhow::Result<()> {
		if let Some(checkpoint) = self.db.store_htlc_settlement(preimage).await? {
			self.watch.update(checkpoint);
		}
		Ok(())
	}

	/// Check if a payment hash has been settled. Returns the preimage if so.
	pub async fn is_settled(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<Preimage>> {
		self.db.get_htlc_settlement_by_payment_hash(payment_hash).await
	}

	/// Subscribe to settlement notifications starting after `since`.
	///
	/// Returns a stream of [`Settlement`] values, reading from the
	/// database in batches. The stream wakes whenever the checkpoint
	/// advances past the subscriber's cursor (either from an in-process
	/// [`settle`](Self::settle) call or from the background poller
	/// detecting cross-process writes) and re-polls when a batch is
	/// full so that large backlogs are drained without extra waiting.
	pub fn subscribe(
		&self,
		since: Checkpoint,
	) -> impl Stream<Item = Settlement> + use<> {
		let db = self.db.clone();
		let mut rx = self.watch.subscribe();
		let batch_size = self.batch_size;

		stream! {
			let mut cursor = since;
			loop {
				if rx.wait_for(|&cp| cp > cursor).await.is_err() {
					break; // sender dropped
				}

				let batch = match db
					.get_htlc_settlements_since(cursor, batch_size)
					.await
				{
					Ok(b) => b,
					Err(_) => break,
				};

				for s in &batch {
					// Only advance cursor through contiguous checkpoints.
					// Concurrent writers may commit out of order, leaving
					// gaps in the id sequence. Jumping over a gap would
					// permanently skip the rows that fill it later.
					if s.checkpoint > cursor {
						cursor = s.checkpoint;
					}
					yield Settlement {
						checkpoint: s.checkpoint,
						hash: s.hash,
						preimage: s.preimage,
					};
				}
			}
		}
	}
}

/// Background process that periodically checks the database for
/// settlements written by other processes (e.g. watchmand) and
/// advances the watch so subscribers wake up.
struct Process {
	db: Db,
	watch: MonotonicWatch,
	poll_interval: Duration,
}

impl Process {
	async fn run(self, rtmgr: RuntimeManager) {
		let _worker = rtmgr.spawn_critical("HtlcSettler");
		info!("Starting HtlcSettler...");

		let mut interval = tokio::time::interval(self.poll_interval);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

		loop {
			tokio::select! {
				_ = interval.tick() => {
					match self.db.get_htlc_settlement_max_checkpoint().await {
						Ok(cp) => { self.watch.update(cp); }
						Err(e) => {
							tracing::warn!("HtlcSettler poll failed: {:#}", e);
						}
					}
				}
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting HtlcSettler loop...");
					break;
				}
			}
		}

		info!("HtlcSettler terminated gracefully.");
	}
}
