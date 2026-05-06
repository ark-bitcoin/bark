//! Manages outbound Lightning payments. Sends payments via CLN's `xpay` RPC
//! and tracks their status via `listsendpays` streams.
//!
//! ## Payment lifecycle
//!
//! [`ClnXpay::pay`] is fire-and-forget: it spawns a task that calls `xpay` over gRPC.
//! On success, the sendpay stream picks up the result. On RPC error, the spawned task
//! marks the attempt as `Submitted` with the error so the monitor can reconcile later.
//!
//! ## Sendpay stream
//!
//! The main loop `wait`s on CLN for new `created` and `updated` sendpay events.
//! Each event is matched against open payment attempts in the DB and transitions
//! them through `Requested → Submitted → Succeeded/Failed`.
//!
//! ## Payment reconciliation
//!
//! On a periodic interval, queries `listpays` for all open attempts to catch anything
//! the stream missed (e.g. events during downtime). Uses exponential backoff per
//! invoice to avoid hammering CLN.

use std::{fmt, str};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use chrono::{DateTime, Local};
use tokio::sync::{broadcast, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;
use cln_rpc::listpays_pays::ListpaysPaysStatus;

use crate::database;
use crate::database::ln::{ClnNodeId, LightningPaymentAttempt, LightningPaymentStatus};
use crate::ln::settler::HtlcSettler;
use crate::system::RuntimeManager;
use crate::telemetry;

use super::ClnGrpcClient;


/// The buffer we add to the xpay timeout before we check invoice
pub const XPAY_TIMEOUT_BUFFER: Duration = Duration::from_secs(15);

/// Shared client for sending xpay RPCs and reconciling payment status against CLN.
///
/// Wrapped in an `Arc` so both [`ClnXpay::pay`] (fire-and-forget spawned tasks)
/// and [`ClnXpayProcess`] (periodic reconciliation) can use it concurrently.
struct ClnXpayClient {
	db: database::Db,
	rpc: ClnGrpcClient,
	settler: Arc<HtlcSettler>,
	/// Notifies [`ClnManager::get_payment_status`] when a payment reaches a final state.
	payment_update_tx: broadcast::Sender<PaymentHash>,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
}

impl ClnXpayClient {
	fn notifier(&self) -> super::PaymentAttemptNotifier<'_> {
		super::PaymentAttemptNotifier::new(&self.db, &self.mailbox_manager, &self.payment_update_tx)
	}

	pub async fn new(
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		rpc: ClnGrpcClient,
		settler: Arc<HtlcSettler>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
	) -> Arc<Self> {
		Arc::new(Self { db, payment_update_tx, rpc, settler, mailbox_manager })
	}

	/// Calls xpay and then reconciles the attempt status against CLN.
	///
	/// On RPC success the sendpay stream will pick up the result, but we still
	/// reconcile afterwards to handle edge cases (e.g. the stream missing an event).
	/// On RPC error the reconciliation drives the attempt to its final state.
	pub async fn pay(
		&self,
		invoice: Box<Invoice>,
		payment_amount: Amount,
		max_routing_fee: Amount,
		max_cltv_expiry_delta: BlockDelta,
		retry_for: Duration,
	) {
		let mut rpc = self.rpc.clone();
		let payment_hash = invoice.payment_hash();
		match call_xpay(
			&mut rpc, &invoice, payment_amount, max_routing_fee, max_cltv_expiry_delta, retry_for,
		).await {
			Ok(preimage) => {
				// NB we don't do db stuff when it's succesful, because
				// it will happen in the sendpay stream of the monitor process
				trace!("Payment successful, preimage: {} for payment hash {}",
					preimage.as_hex(), payment_hash.as_hex(),
				);
			},
			// Fetch and store the attempt as failed.
			Err(pay_err) => {
				error!("Error calling pay-command: {}", pay_err);
			},
		}

		let attempt_res = self.db
			.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await;

		match attempt_res {
			Ok(Some(attempt)) => {
				if let Err(e) = self.sync_payment_attempt_status(attempt).await {
					error!("Error syncing payment attempt status: {e:#}");
				}
			},
			Ok(None) => {
				error!("Attempt not found for payment hash after calling xpay: {}", payment_hash);
			},
			Err(e) => {
				error!("Error getting open payment attempt by payment hash: {e:#}");
			},
		}
	}

	/// Queries CLN's `listpays` for the given attempt and updates the DB to match.
	///
	/// If CLN has no record of the payment and the attempt is still open, it is
	/// marked `Failed`. If CLN reports a different status than the DB, the DB is
	/// updated (unless the DB status is already final, which is logged as an error).
	/// Sends on `payment_update_tx` when the status changes.
	pub async fn sync_payment_attempt_status(&self, attempt: LightningPaymentAttempt) -> anyhow::Result<()> {
		let payment_hash = attempt.payment_hash;
		debug!("Lightning payment attempt ({}): with payment hash {} is being verified.",
			attempt.id, payment_hash,
		);

		telemetry::add_invoice_verification(attempt.lightning_node_id, attempt.status);

		let req = cln_rpc::ListpaysRequest {
			bolt11: None,
			payment_hash: Some(payment_hash.to_vec()),
			status: None,
			index: None,
			limit: None,
			start: None,
		};
		let listpays_response = self.rpc.clone().list_pays(req).await
			.context("Could not fetch cln payments")?
			.into_inner();
		if listpays_response.pays.is_empty() {
			match attempt.status {
				LightningPaymentStatus::Succeeded => {
					error!("Lightning payment attempt ({}): flagged succeeded \
						when it cannot be found in CLN for payment hash {}",
						attempt.id, payment_hash,
					);
				},
				LightningPaymentStatus::Failed => {
					error!("Lightning payment attempt ({}): flagged failed \
						when it cannot be found in CLN for payment hash {}",
						attempt.id, payment_hash,
					)
				},
				LightningPaymentStatus::Requested
					| LightningPaymentStatus::Submitted =>
				{
					self.notifier().update_lightning_payment_attempt_status(
						&attempt,
						LightningPaymentStatus::Failed,
						None,
						None,
					).await?;

					telemetry::add_lightning_payment(
						attempt.lightning_node_id,
						attempt.amount_msat,
						LightningPaymentStatus::Failed,
					);
				},
			}
		} else {
			let latest = listpays_response.pays.into_iter().max_by_key(|p| {
				p.created_index.expect("should have index")
			}).expect("we have at least one");

			let desired_status = match latest.status() {
				ListpaysPaysStatus::Pending => LightningPaymentStatus::Submitted,
				ListpaysPaysStatus::Complete => {
					if latest.preimage.is_none() {
						error!("Lightning payment attempt ({}): completed but no preimage \
							specified for payment hash {}",
							attempt.id, payment_hash,
						);
						LightningPaymentStatus::Submitted
					} else {
						LightningPaymentStatus::Succeeded
					}
				},
				ListpaysPaysStatus::Failed => LightningPaymentStatus::Failed,
			};

			let error_string = latest.erroronion.as_ref().map(|b| {
				str::from_utf8(b).unwrap_or_else(|e| {
					warn!("Failed to decode erroronion from cln: '{}', {}", b.as_hex(), e);
					"failed to decode erroronion field"
				})
			});

			if attempt.status != desired_status {
				if attempt.status.is_final() {
					error!("Lightning payment attempt ({}): flagged {} when it \
						actually {} for payment hash {}",
						attempt.id, attempt.status, desired_status,
						payment_hash,
					);
				} else {
					let preimage = latest.preimage.map(|b| b.try_into())
						.transpose()
						.context("CLN returned a preimage that is not 32 bytes")?;

					// Store the preimage in the settlement table so the
					// watchman can use it to claim HTLC VTXOs on-chain.
					if let Some(preimage) = preimage {
						self.settler.settle(preimage).await?;
					}

					// NB: for intra-ark payments, settle_invoice may also post
					// the mailbox notification for the same payment hash. The
					// DB insert is idempotent (ON CONFLICT DO NOTHING).
					self.notifier().verify_and_update_payment_attempt(
						&attempt,
						desired_status,
						error_string,
						latest.amount_sent_msat.map(|v| v.msat),
						preimage,
					).await?;
				}
			}
		}

		Ok(())
	}
}

/// Timing knobs for the xpay monitor loop and reconciliation backoff.
#[derive(Debug, Clone)]
pub struct ClnXpayConfig {
	pub invoice_check_interval: Duration,
	pub cln_xpay_timeout: Duration,
	pub check_base_delay: Duration,
	pub max_check_delay: Duration,
}

/// Handle for the xpay monitor process.
///
/// Tracks outbound payment status via CLN's listsendpays streams
/// and periodically verifies open payment attempts.
pub struct ClnXpay {
	jh: Option<JoinHandle<anyhow::Result<()>>>,
	client: Arc<ClnXpayClient>,
}

impl ClnXpay {
	/// Spawns the background reconciliation loop and returns a handle.
	///
	/// Reads the current payment stream indices from the DB so the monitor
	/// knows where to resume after a restart.
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: ClnNodeId,
		rpc: ClnGrpcClient,
		config: ClnXpayConfig,
		settler: Arc<HtlcSettler>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
	) -> anyhow::Result<ClnXpay> {
		let payment_idxs = db.read(async |t| t.get_lightning_payment_indexes(node_id).await).await
			.with_context(|| format!("failed to fetch payment indices for {}", node_id))?
			.unwrap_or_default();

		slog!(XpayStarted,
			node_id: node_id,
			created_index: payment_idxs.created_index,
			updated_index: payment_idxs.updated_index,
		);

		let client = ClnXpayClient::new(db.clone(), payment_update_tx, rpc, settler, mailbox_manager).await;

		let proc = ClnXpayProcess {
			config, db, node_id,
			client: client.clone(),
			attempt_next_check_at: HashMap::new(),
		};

		let jh = tokio::spawn(async move {
			let ret = proc.run(rtmgr, mgr_waker).await;
			if let Err(ref e) = ret {
				slog!(XpayStopped, node_id: node_id, error: format!("{:?}", e));
			}
			ret
		});

		Ok(ClnXpay { jh: Some(jh), client })
	}

	pub fn is_running(&self) -> bool {
		self.jh.as_ref().is_some_and(|jh| !jh.is_finished())
	}

	/// Wait for the process to end.
	pub async fn wait(mut self) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
		match self.jh.take() {
			Some(jh) => Ok(jh.await?),
			None => Ok(Ok(())),
		}
	}

	/// Fire-and-forget: spawn a task that calls xpay and then updates the DB.
	pub fn pay(
		&self,
		invoice: Box<Invoice>,
		payment_amount: Amount,
		max_routing_fee: Amount,
		max_cltv_expiry_delta: BlockDelta,
		retry_for: Duration,
	) {
		let client = self.client.clone();
		tokio::spawn(async move {
			client.pay(
				invoice,
				payment_amount,
				max_routing_fee,
				max_cltv_expiry_delta,
				retry_for,
			).await;
		});
	}
}

impl Drop for ClnXpay {
	fn drop(&mut self) {
		if let Some(jh) = self.jh.take() {
			jh.abort();
		}
	}
}

impl fmt::Debug for ClnXpay {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ClnXpay")
	}
}

/// Background loop that periodically reconciles open payment attempts against CLN.
///
/// Runs on a fixed interval ([`ClnXpayConfig::invoice_check_interval`]) and,
/// for each open attempt old enough to have finished xpay retries, queries
/// `listpays` to drive the attempt to a final state. Uses exponential backoff
/// per invoice to avoid hammering CLN for long-lived pending payments.
struct ClnXpayProcess {
	config: ClnXpayConfig,
	db: database::Db,

	node_id: ClnNodeId,

	client: Arc<ClnXpayClient>,

	/// Per-attempt backoff state: maps attempt id → (check count, earliest next check time).
	/// Entries are pruned once their next-check time lapses.
	attempt_next_check_at: HashMap<i64, (usize, DateTime<Local>)>,
}

impl ClnXpayProcess {
	/// Bumps the backoff counter for `attempt_id` and schedules the next check.
	///
	/// Delay doubles each check starting from `check_base_delay`, capped at
	/// `max_check_delay`.
	fn update_next_attempt_check(&mut self, attempt_id: i64) {
		let (checks, next_check) = self.attempt_next_check_at.entry(attempt_id)
			.or_insert((0, Local::now()));
		*checks += 1;

		// Calculate delay: grows with each check
		// e.g. base 10 seconds, doubling each time, capped to a max delay
		let base_delay_secs = self.config.check_base_delay.as_secs();
		let max_delay_secs = self.config.max_check_delay.as_secs();
		let delay_secs = (base_delay_secs * 2u64.pow(*checks as u32 - 1)).min(max_delay_secs);

		*next_check = Local::now() + Duration::from_secs(delay_secs);

		trace!("Lightning payment attempt ({}): Check {} done, updated next check to {}.",
			attempt_id, checks, next_check,
		);
	}

	/// Iterates over all open payment attempts for this node and reconciles
	/// each one that is old enough and not in backoff. Prunes expired backoff
	/// entries afterwards.
	async fn process_payment_attempts(&mut self) -> anyhow::Result<()> {
		let open_attempts = self.db.read(async |t| t.get_open_lightning_payment_attempts(self.node_id).await).await?;

		for attempt in open_attempts {
			if attempt.is_self_payment {
				trace!("Lightning payment attempt ({}): Skipping since it is a self payment.",
					attempt.id,
				);

				continue;
			}

			// We don't want to go further if we aren't sure CLN
			// didn't finished retrying payment attempts
			let safe_delay_cln_stopped_retries =
				self.config.cln_xpay_timeout + XPAY_TIMEOUT_BUFFER;
			if attempt.created_at > Local::now() - safe_delay_cln_stopped_retries {
				trace!("Lightning payment attempt ({}): Skipping since it was just created.",
					attempt.id,
				);

				continue;
			}

			let next_check = self.attempt_next_check_at.get(&attempt.id);
			if next_check.is_some() && next_check.unwrap().1 > Local::now() {
				trace!("Lightning payment attempt ({}): Skipping since it was checked recently.",
					attempt.id,
				);

				continue;
			}

			let attempt_id = attempt.id;
			if let Err(e) = self.client.sync_payment_attempt_status(attempt).await {
				error!("Error syncing payment attempt status: {e:#}");
			} else {
				self.update_next_attempt_check(attempt_id);
			}

		}

		self.attempt_next_check_at.retain(|_, &mut (_, datetime)| datetime > Local::now());

		telemetry::set_pending_invoice_verifications(
			self.node_id,
			self.attempt_next_check_at.len(),
		);

		Ok(())
	}

	/// Main select loop: runs [`process_payment_attempts`](Self::process_payment_attempts)
	/// on every tick and exits cleanly on shutdown.
	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnXpay({})", self.node_id))
			.with_notify(mgr_waker);

		let mut check_interval = tokio::time::interval(self.config.invoice_check_interval);

		loop {
			tokio::select! {
				_ = check_interval.tick() => {
					self.process_payment_attempts().await?;
				},
				_ = rtmgr.shutdown_signal() => return Ok(()),
			}
		}
	}
}

/// Calls the xpay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
async fn call_xpay(
	rpc: &mut ClnGrpcClient,
	invoice: &Invoice,
	payment_amount: Amount,
	max_routing_fee: Amount,
	max_cltv_expiry_delta: BlockDelta,
	retry_for: Duration,
) -> anyhow::Result<Preimage> {
	let payment_hash = invoice.payment_hash();

	slog!(XpayRpcCalled,
		payment_hash, payment_amount, max_routing_fee,
		invoice: invoice.to_string(),
		max_delay: max_cltv_expiry_delta as u32,
	);

	let pay_result = rpc.xpay(cln_rpc::XpayRequest {
		invstring: invoice.to_string(),
		// cln doesn't allow tipping
		amount_msat: if invoice.amount_msat().is_none() {
			Some(payment_amount.into())
		} else {
			None
		},
		maxdelay: Some(max_cltv_expiry_delta as u32),
		maxfee: Some(max_routing_fee.into()),
		retry_for: Some(retry_for.as_secs() as u32),
		partial_msat: None,
		layers: vec![],
	}).await;

	let result = match pay_result {
		Err(e) => Err(e.into()),
		Ok(resp) => {
			let bytes = resp.into_inner().payment_preimage;
			if bytes.is_empty() {
				Err(anyhow!("missing preimage"))
			} else {
				bytes.try_into().ok().context("invalid preimage not 32 bytes")
			}
		}
	};

	slog!(XpayRpcReturned,
		payment_hash: payment_hash,
		preimage: result.as_ref().ok().copied(),
		error: result.as_ref().err().map(|e| e.to_string()),
	);

	result
}
