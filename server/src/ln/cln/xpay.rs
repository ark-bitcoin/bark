//! Manages outbound Lightning payments. Sends payments via CLN's `xpay` RPC
//! and tracks their status via `listpays`.
//!
//! ## Payment lifecycle
//!
//! [`ClnXpay::pay`] is fire-and-forget: it spawns a task that calls `xpay` over gRPC.
//! When CLN answers, success or error, the attempt moves to `Submitted` and is
//! reconciled right away. When the call breaks in transport, the monitor reconciles
//! the attempt.
//!
//! ## Payment reconciliation
//!
//! On a periodic interval, queries `listpays` for all open attempts. Uses
//! exponential backoff per invoice to avoid hammering CLN.

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
use crate::database::xpay::{self, ClnXpayStatus};
use crate::database::ln::{LightningNodeId, LightningPaymentAttempt, LightningPaymentStatus};
use crate::ln::settler::HtlcSettler;
use crate::system::RuntimeManager;
use crate::telemetry;

use super::ClnGrpcClient;
use super::super::payment_handler::PaymentAttemptHandler;


/// How long an attempt may wait for xpay to answer. xpay always answers, so an
/// attempt still `Requested` after this, with no record in CLN, never reached it.
const XPAY_ANSWER_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared client for sending xpay RPCs and reconciling payment status against CLN.
///
/// Wrapped in an `Arc` so both [`ClnXpay::pay`] (fire-and-forget spawned tasks)
/// and [`ClnXpayProcess`] (periodic reconciliation) can use it concurrently.
pub(crate) struct ClnXpayClient {
	db: database::Db,
	rpc: ClnGrpcClient,
	settler: Arc<HtlcSettler>,
	/// Notifies [`LightningManager::wait_payment_status`] when a payment reaches a final state.
	///
	/// [`LightningManager::wait_payment_status`]: crate::ln::node_manager::LightningManager::wait_payment_status
	payment_update_tx: broadcast::Sender<PaymentHash>,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
}

impl ClnXpayClient {
	fn payment_handler(&self) -> PaymentAttemptHandler<'_> {
		PaymentAttemptHandler::new(&self.db, &self.mailbox_manager, &self.payment_update_tx)
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
	/// On an answer from CLN, success or error, the attempt is reconciled
	/// against `listpays`. On a transport error it is left to the monitor.
	#[tracing::instrument(skip_all, fields(
		payment_hash = %invoice.payment_hash(),
		invoice = %invoice,
		payment_amount = %payment_amount,
		max_routing_fee = %max_routing_fee,
		max_cltv_expiry_delta,
		retry_for = ?retry_for,
	))]
	pub async fn pay(
		&self,
		attempt_id: i64,
		invoice: Box<Invoice>,
		payment_amount: Amount,
		max_routing_fee: Amount,
		max_cltv_expiry_delta: BlockDelta,
		retry_for: Duration,
		label: Option<String>,
	) {
		let mut rpc = self.rpc.clone();
		let payment_hash = invoice.payment_hash();
		// Only place CLN says whether the route was pruned on cost or on delay.
		// A route it never found leaves no `listpays` record either, so
		// dropping this loses the reason entirely.
		let pay_error = match call_xpay(
			&mut rpc, &invoice, payment_amount, max_routing_fee, max_cltv_expiry_delta, retry_for,
			label,
		).await {
			Ok(preimage) => {
				// Record the settlement now: the attempt is finished by the
				// reconciliation below or the monitor, which can both fail,
				// and a revocation is refused only once the preimage is known.
				if preimage.compute_payment_hash() != payment_hash {
					error!("xpay returned a preimage that doesn't match payment hash {}", payment_hash);
				} else if let Err(e) = self.settler.settle(preimage).await {
					error!("Error storing the xpay preimage for payment hash {}: {:#}", payment_hash, e);
				}
				trace!("Payment successful for payment hash {}", payment_hash.as_hex());
				None
			},
			Err(pay_err) if !is_cln_error(&pay_err) => {
				// xpay may still be trying, and syncing now could fail an
				// attempt CLN goes on to pay.
				warn!("xpay call for {} broke, leaving it to the monitor: {:#}",
					payment_hash, pay_err,
				);
				return;
			},
			Err(pay_err) => {
				debug!("Error calling pay-command: {}", pay_err);
				Some(pay_err.to_string())
			},
		};

		// A later attempt for this hash, maybe on another node, is not ours to
		// reconcile with this node's xpay result.
		let attempt_res = self.db
			.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await
			.map(|a| a.filter(|a| a.id == attempt_id));

		let attempt_res = match attempt_res {
			// Store the answer before reconciling, so it survives if
			// `listpays` fails and the monitor has to finish the attempt.
			Ok(Some(attempt)) => self.store_xpay_answer(attempt, pay_error.as_deref()).await,
			res => res,
		};

		match attempt_res {
			Ok(Some(attempt)) => {
				if let Err(e) = self.sync_payment_attempt_status(attempt).await {
					error!("Error syncing payment attempt status: {e:#}");
				}
			},
			Ok(None) => {
				error!("Attempt {} for payment hash {} was closed before xpay returned",
					attempt_id, payment_hash,
				);
			},
			Err(e) => {
				error!("Error getting open payment attempt by payment hash: {e:#}");
			},
		}
	}

	/// Moves `attempt` to `Submitted`, with xpay's error if it answered with
	/// one, and returns it as stored, so later updates carry the new
	/// `updated_at`. When the attempt was changed in the meantime, it is
	/// reloaded and the store retried. Returns `None` once the attempt is no
	/// longer open, leaving a finalized attempt untouched.
	async fn store_xpay_answer(
		&self,
		mut attempt: LightningPaymentAttempt,
		error: Option<&str>,
	) -> anyhow::Result<Option<LightningPaymentAttempt>> {
		loop {
			let updated_at = self.db.write(async |t| t.update_lightning_payment_attempt_status(
				&attempt, LightningPaymentStatus::Submitted, error,
			).await).await?;
			if let Some(updated_at) = updated_at {
				attempt.updated_at = updated_at;
				attempt.status = LightningPaymentStatus::Submitted;
				if let Some(error) = error {
					attempt.error = Some(error.to_owned());
				}
				return Ok(Some(attempt));
			}

			let reloaded = self.db.read(async |t|
				t.get_open_lightning_payment_attempt_by_payment_hash(attempt.payment_hash).await
			).await?;
			match reloaded {
				Some(a) if a.id == attempt.id => attempt = a,
				_ => return Ok(None),
			}
		}
	}

	/// Queries CLN's `listpays` for the given attempt and updates the DB to match.
	///
	/// Only the record of the attempt's own xpay call counts: an earlier call
	/// on the same payment hash says nothing about this one. If CLN has no
	/// record of the call, the attempt is failed once xpay answered, or once it
	/// waited [`XPAY_ANSWER_TIMEOUT`] for an answer. If CLN reports a
	/// different status than the DB, the DB is updated (unless the DB status
	/// is already final, which is logged as an error). Sends on
	/// `payment_update_tx` when the status changes.
	pub async fn sync_payment_attempt_status(
		&self,
		attempt: LightningPaymentAttempt,
	) -> anyhow::Result<()> {
		let payment_hash = attempt.payment_hash;
		let error = attempt.error.as_deref();
		debug!("Lightning payment attempt ({}): with payment hash {} is being verified.",
			attempt.id, payment_hash,
		);

		telemetry::add_payment_sync(attempt.lightning_node_id, attempt.status);

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

		// The attempt's own call is the pending one on its hash, and xpay puts
		// the call's label on every part it sends. Calls from before labels
		// existed match every record.
		let label = self.db
			.read(async |t| xpay::get_xpays_by_payment_hash(&**t, payment_hash).await).await?
			.into_iter()
			.find(|x| x.status == ClnXpayStatus::Pending)
			.and_then(|x| x.label);
		let pays = listpays_response.pays.into_iter()
			.filter(|p| label.is_none() || p.label == label)
			.collect::<Vec<_>>();

		if pays.is_empty() {
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
				// xpay answered without sending a part.
				LightningPaymentStatus::Submitted => {
					self.payment_handler().fail_payment_attempt(&attempt, error).await?;
				},
				LightningPaymentStatus::Requested
					if attempt.created_at + XPAY_ANSWER_TIMEOUT < Local::now() =>
				{
					self.payment_handler().fail_payment_attempt(&attempt, error).await?;
				},
				// xpay may not have sent a part yet.
				LightningPaymentStatus::Requested => {
					debug!("Lightning payment attempt ({}): no record in CLN yet \
						for payment hash {}", attempt.id, payment_hash,
					);
				},
			}
		} else {
			let latest = pays.into_iter().max_by_key(|p| {
				p.created_index.expect("should have index")
			}).expect("we have at least one");

			let updated_status = match latest.status() {
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

			// The onion is binary, so keep it as hex next to the xpay error.
			let onion = latest.erroronion.as_ref().map(|b| format!("erroronion={}", b.as_hex()));
			let error_string = match (error, onion) {
				(Some(e), Some(o)) => Some(format!("{e}; {o}")),
				(e, o) => e.map(String::from).or(o),
			};

			if attempt.status != updated_status {
				if attempt.status.is_final() {
					error!("Lightning payment attempt ({}): flagged {} when it \
						actually {} for payment hash {}",
						attempt.id, attempt.status, updated_status,
						payment_hash,
					);
				} else {
					let preimage = latest.preimage.map(|b| Preimage::from_slice(&b))
						.transpose()
						.context("CLN returned a preimage that is not 32 bytes")?;

					if let Some(preimage) = &preimage {
						if preimage.compute_payment_hash() != attempt.payment_hash {
							bail!("preimage does not match payment hash");
						}
					}

					// NB: for intra-ark payments, settle_invoice may also post
					// the mailbox notification for the same payment hash.
					self.payment_handler().process_payment_attempt(
						&self.settler,
						&attempt,
						updated_status,
						error_string.as_deref(),
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
	pub check_base_delay: Duration,
	pub max_check_delay: Duration,
}

/// Handle for the xpay monitor process.
///
/// Periodically verifies open payment attempts.
pub struct ClnXpay {
	jh: Option<JoinHandle<anyhow::Result<()>>>,
	client: Arc<ClnXpayClient>,
}

impl ClnXpay {
	/// Spawns the background reconciliation loop and returns a handle.
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: LightningNodeId,
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

	/// Cheap clone of the shared command client. Used by [`NodeHandle`] to
	/// issue xpay payments directly without going through the spawn helper.
	pub(crate) fn client(&self) -> Arc<ClnXpayClient> {
		self.client.clone()
	}

	/// Wait for the process to end.
	pub async fn wait(mut self) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
		match self.jh.take() {
			Some(jh) => Ok(jh.await?),
			None => Ok(Ok(())),
		}
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
/// for each open attempt, queries `listpays` to drive the attempt to a final
/// state. Uses exponential backoff
/// per invoice to avoid hammering CLN for long-lived pending payments.
struct ClnXpayProcess {
	config: ClnXpayConfig,
	db: database::Db,

	node_id: LightningNodeId,

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
		let delay_secs = (base_delay_secs.saturating_mul(2u64.saturating_pow(*checks as u32 - 1)))
			.min(max_delay_secs);

		*next_check = Local::now() + Duration::from_secs(delay_secs);

		trace!("Lightning payment attempt ({}): Check {} done, updated next check to {}.",
			attempt_id, checks, next_check,
		);
	}

	/// Iterates over all open payment attempts for this node and reconciles
	/// each one that is not in backoff. Prunes expired backoff
	/// entries afterwards.
	async fn process_payment_attempts(&mut self) -> anyhow::Result<()> {
		let open_attempts = self.db.read(async |t| t.get_open_lightning_payment_attempts(self.node_id).await).await?;

		for attempt in open_attempts {
			if attempt.is_self_payment() {
				trace!("Lightning payment attempt ({}): Skipping since it is a self payment.",
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

		telemetry::set_pending_payment_syncs(
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

/// Whether lightningd itself answered with an error, meaning xpay has stopped
/// trying. cln-grpc words every failed call as `Error calling method ...`, but
/// only an answer from lightningd carries `RpcError { code: Some(..) }`.
fn is_cln_error(err: &anyhow::Error) -> bool {
	err.downcast_ref::<tonic::Status>()
		.is_some_and(|s| s.message().contains("RpcError { code: Some("))
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
	label: Option<String>,
) -> anyhow::Result<Preimage> {
	let payment_hash = invoice.payment_hash();

	slog!(XpayRpcCalled,
		payment_hash, payment_amount, max_routing_fee,
		invoice: invoice.to_string(),
		max_delay: max_cltv_expiry_delta.to_u32(),
	);

	let pay_result = rpc.xpay(cln_rpc::XpayRequest {
		invstring: invoice.to_string(),
		// cln doesn't allow tipping
		amount_msat: if invoice.amount_msat().is_none() {
			Some(payment_amount.into())
		} else {
			None
		},
		maxdelay: Some(max_cltv_expiry_delta.to_u32()),
		maxfee: Some(max_routing_fee.into()),
		retry_for: Some(retry_for.as_secs() as u32),
		partial_msat: None,
		layers: vec![],
		payer_note: None,
		label,
		localinvreqid: None,
		dev_use_shadow: None,
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
		error: result.as_ref().err().map(|e| e.to_string()),
	);

	result
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn is_cln_error_tells_cln_errors_from_transport_errors() {
		let cln = tonic::Status::unknown("Error calling method Xpay: RpcError { \
			code: Some(205), message: \"no route\", data: None }");
		assert!(is_cln_error(&cln.into()));

		let transport = tonic::Status::unavailable("transport error");
		assert!(!is_cln_error(&transport.into()));
		let reset = tonic::Status::unknown("h2 protocol error: stream reset");
		assert!(!is_cln_error(&reset.into()));
		let socket = tonic::Status::unknown("Error calling method Xpay: RpcError { \
			code: None, message: \"no response from lightningd\", data: None }");
		assert!(!is_cln_error(&socket.into()));
		assert!(!is_cln_error(&anyhow!("missing preimage")));
	}
}
