//! Manages incoming HTLCs via CLN's hold invoice plugin.
//!
//! ## HTLC subscription lifecycle
//!
//! Hold invoices defer settlement: HTLCs arrive and are held until we reveal the
//! preimage (settle) or explicitly cancel. Each invoice gets a DB subscription:
//! `Created → Accepted → Settled/Canceled`. On acceptance, the incoming HTLC
//! expiry is validated against the chain tip.
//!
//! ## TrackAll stream
//!
//! When available, a `TrackAll` gRPC stream pushes real-time invoice state changes.
//! On (re)connect, polls all open subscriptions to reconcile missed events.
//! Reconnects with exponential backoff on disconnect.
//!
//! ## Timeout and expiry enforcement
//!
//! Periodically checks all open subscriptions for accepted HTLCs held too long
//! (`receive_htlc_forward_timeout`) and expired invoices. Both result in cancellation.

use std::str::FromStr;
use std::fmt;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::{sha256, Hash};
use chrono::Local;
use futures::Stream;
use lightning_invoice::Bolt11Invoice;
use tokio::sync::{broadcast, Notify};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use ark::lightning::PaymentHash;
use ark::vtxo::policy::{check_block_delta, check_block_height};
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight};
use cln_rpc::plugins::hold::{self, InvoiceState};
use cln_rpc::plugins::hold::hold_client::HoldClient;

use crate::database;
use crate::database::block::BlockTable;
use crate::database::htlc_vtxo;
use crate::database::hold::{self as hold_db, HoldTransition};
use crate::database::ln::{LightningNodeId, LightningHtlcSubscription, LightningHtlcSubscriptionStatus};
use crate::ln::guard::{PaymentGuard, PaymentGuards};
use crate::ln::htlc_recvs_expired;
use crate::ln::node_manager::post_lightning_receive_notification;
use crate::sync::SyncManager;
use crate::system::RuntimeManager;
use crate::telemetry;

use super::super::payment_handler::PaymentAttemptHandler;

#[derive(Debug, Clone)]
pub struct ClnHoldConfig {
	pub invoice_check_interval: Duration,
	pub receive_htlc_forward_timeout: Duration,
	/// Base delay for TrackAll reconnection backoff (e.g., 1 second)
	pub track_all_base_delay: Duration,
	/// Maximum delay for TrackAll reconnection backoff (e.g., 60 seconds)
	pub max_track_all_delay: Duration,
}

/// Ask `hold.list` for exactly the payment hashes we care about and return
/// the subset whose invoice is in Accepted state. Replaces a full-list
/// pagination + client-side filter.
async fn fetch_accepted_payment_hashes(
	hold_client: &mut HoldClient<Channel>,
	payment_hashes: Vec<Vec<u8>>,
) -> anyhow::Result<HashSet<sha256::Hash>> {
	if payment_hashes.is_empty() {
		return Ok(HashSet::new());
	}

	let req = hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHashes(
			hold::list_request::PaymentHashes { payment_hashes },
		)),
	};
	let res = hold_client.list(req).await?.into_inner();

	let mut accepted = HashSet::new();
	for inv in &res.invoices {
		if inv.state != InvoiceState::Accepted as i32 {
			continue;
		}
		match sha256::Hash::from_slice(&inv.payment_hash) {
			Ok(h) => { accepted.insert(h); },
			Err(e) => warn!("hold plugin returned invalid payment_hash \
				(len {}, id {}): {}", inv.payment_hash.len(), inv.id, e),
		}
	}
	Ok(accepted)
}

pub struct ClnHold {
	jh: Option<JoinHandle<anyhow::Result<()>>>,
}

impl ClnHold {
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: LightningNodeId,
		hold_rpc: Option<HoldClient<Channel>>,
		config: ClnHoldConfig,
		sync_manager: Arc<SyncManager>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
		payment_guards: PaymentGuards,
	) -> anyhow::Result<ClnHold> {
		let proc = ClnHoldProcess {
			config, db, payment_update_tx, node_id,
			hold_rpc,
			sync_manager,
			mailbox_manager,
			payment_guards,
		};

		let jh = tokio::spawn(async {
			let ret = proc.run(rtmgr, mgr_waker).await;
			if let Err(ref e) = ret {
				error!("ClnHold exited with error: {:?}", e);
			}
			ret
		});

		Ok(ClnHold { jh: Some(jh) })
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
}

impl Drop for ClnHold {
	fn drop(&mut self) {
		if let Some(jh) = self.jh.take() {
			jh.abort();
		}
	}
}

impl fmt::Debug for ClnHold {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ClnHold")
	}
}

/// Manages the lifecycle of the TrackAll gRPC stream
enum TrackAllStreamState {
	/// hold_rpc is None, TrackAll is disabled
	Disabled,
	/// Waiting before attempting to connect (with backoff)
	Backoff { attempt: u32, retry_at: tokio::time::Instant },
	/// Stream is active and receiving updates for all invoices
	Connected(tonic::codec::Streaming<hold::TrackAllResponse>),
	/// Stream needs to be (re)established
	NeedsConnect,
}

struct ClnHoldProcess {
	config: ClnHoldConfig,
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,

	node_id: LightningNodeId,

	hold_rpc: Option<HoldClient<Channel>>,
	sync_manager: Arc<SyncManager>,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
	payment_guards: PaymentGuards,
}

impl ClnHoldProcess {
	fn payment_handler(&self) -> PaymentAttemptHandler<'_> {
		PaymentAttemptHandler::new(&self.db, &self.mailbox_manager, &self.payment_update_tx)
	}

	/// Takes the payment lock for a subscription.
	///
	/// It is an optimistic lock: it is only taken if the subscription status
	/// hasn't changed since our snapshot. Returns `None` otherwise.
	///
	/// `prepare_lightning_claim` holds the same lock while it moves an
	/// `Accepted` subscription to `HtlcsReady`. Without it, a claim could land
	/// between our hold cancel and our status write: the user would get HTLC
	/// vtxos for incoming HTLCs we already gave back, and we could never settle.
	async fn try_lock_subscription(
		&self,
		htlc_subscription: &LightningHtlcSubscription,
	) -> anyhow::Result<Option<PaymentGuard>> {
		let payment_hash = PaymentHash::from(*htlc_subscription.invoice.payment_hash());
		let guard = self.payment_guards.lock(payment_hash).await;

		let current = self.db.read(async |t|
			t.get_htlc_subscription_by_id(htlc_subscription.id).await
		).await?;
		if current.is_none_or(|s| s.status != htlc_subscription.status) {
			debug!("Lightning htlc subscription ({}) left {} before it could be \
				canceled; leaving it alone.",
				htlc_subscription.id, htlc_subscription.status,
			);
			return Ok(None);
		}

		Ok(Some(guard))
	}

	/// For each subscription, verifies if incoming HTLCs have been accepted.
	/// - If so, it updates the status to accepted.
	/// - Once it can no longer be paid (see [Self::cancel_reason]), it
	/// cancels the subscription on the plugin and updates the status to
	/// canceled.
	async fn process_htlc_subscriptions(&mut self) -> anyhow::Result<()> {
		self.check_htlc_subscription_timeouts().await?;
		self.poll_htlc_state_updates().await?;
		Ok(())
	}

	/// Cancels every open subscription that can no longer be paid.
	/// Called on timer regardless of whether TrackAll is enabled.
	async fn check_htlc_subscription_timeouts(&mut self) -> anyhow::Result<()> {
		let mut hold_client = match &self.hold_rpc {
			Some(client) => client.clone(),
			None => {
				warn!("No hold rpc client, skipping htlc subscription timeout checks");
				return Ok(());
			},
		};

		let htlc_subscriptions = self.db.read(async |t| t.get_open_lightning_htlc_subscriptions(
			self.node_id,
		).await).await?;

		let status_counts = htlc_subscriptions.iter()
			.fold(HashMap::new(), |mut acc, sub| {
				*acc.entry(sub.status).or_insert(0) += 1;
				acc
			});
		telemetry::set_open_invoices(self.node_id, &status_counts);

		let tip = self.sync_manager.chain_tip().height;
		for htlc_subscription in htlc_subscriptions {
			let Some(reason) = self.cancel_reason(&htlc_subscription, tip).await? else {
				continue;
			};
			let Some(_guard) = self.try_lock_subscription(&htlc_subscription).await? else {
				continue;
			};
			self.cancel_invoice_and_htlc_subscription(
				&mut hold_client,
				htlc_subscription.invoice.payment_hash(),
				&htlc_subscription,
				reason,
			).await?;
		}

		Ok(())
	}

	/// Why an open subscription should be canceled now, if it should.
	///
	/// That is when the payee did not finish its HTLC-recv vtxo setup in time,
	/// every granted HTLC-recv vtxo expired, or the invoice expired before
	/// anything was granted. Granted HTLC-recv vtxos keep the receive committed
	/// whatever its invoice says: the payee can claim them on-chain, so
	/// canceling earlier pays the same payment twice.
	async fn cancel_reason(
		&self,
		htlc_subscription: &LightningHtlcSubscription,
		tip: BlockHeight,
	) -> anyhow::Result<Option<&'static str>> {
		match htlc_subscription.status {
			// Held too long in Accepted state. We use our `accepted_at`
			// timestamp rather than the hold plugin's HTLC `created_at` for
			// accuracy.
			LightningHtlcSubscriptionStatus::Accepted => {
				// TODO(dunxen): Simply `.expect` and remove this `unwrap_or` at some stage.
				// The `.unwrap_or` is here for backwards compatibility for existing servers that may
				// have exsisting subscriptions in an `Accepted` state but without an `accepted_at` field
				// after restart.
				let accepted_at = htlc_subscription.accepted_at.unwrap_or(htlc_subscription.updated_at);
				if accepted_at < Local::now() - self.config.receive_htlc_forward_timeout {
					return Ok(Some("htlc vtxo setup timed out"));
				}
			},
			LightningHtlcSubscriptionStatus::HtlcsReady => {
				let (htlc_vtxos, watchman_tip) = self.db.read(async |t| {
					let htlc_vtxos = htlc_vtxo::get_htlc_vtxo_states_by_payment_hash(
						&t, htlc_subscription.payment_hash,
					).await?;
					let watchman_tip = t.get_highest_block(BlockTable::Watchmand).await?.map(|b| b.height);
					Ok((htlc_vtxos, watchman_tip))
				}).await?;
				if htlc_recvs_expired(&htlc_vtxos, tip, watchman_tip) {
					return Ok(Some("htlc-recv vtxos expired"));
				}

				let htlc_recv_expiry = htlc_vtxos.iter()
					.filter(|h| h.direction() == htlc_vtxo::HtlcDirection::Outgoing)
					.map(|h| h.htlc_expiry())
					.max();
				// Only possible if the backfill-htlc-vtxos migration was skipped.
				if htlc_recv_expiry.is_none() {
					debug_assert!(false,
						"HtlcsReady receive {} has no HTLC-recv vtxos", htlc_subscription.id,
					);
					error!("Lightning htlc subscription ({}) is {} without any HTLC-recv vtxo; \
						keeping it committed. Run the backfill-htlc-vtxos data migration.",
						htlc_subscription.id, htlc_subscription.status,
					);
				}

				if htlc_subscription.invoice.is_expired() {
					slog!(LightningReceiveKeptCommitted,
						payment_hash: htlc_subscription.payment_hash,
						htlc_recv_expiry,
						tip,
					);
				}
				return Ok(None);
			},
			_ => {},
		}

		if htlc_subscription.invoice.is_expired() {
			return Ok(Some("invoice expired"));
		}
		Ok(None)
	}

	/// Handles an invoice that has been accepted (HTLCs received).
	/// Fetches HTLC details from hold plugin and validates expiry.
	/// Returns true if subscription was updated, false if skipped/already processed.
	async fn handle_invoice_accepted(
		&mut self,
		htlc_subscription: &LightningHtlcSubscription,
	) -> anyhow::Result<bool> {
		// Only process subscriptions in Created state
		if htlc_subscription.status != LightningHtlcSubscriptionStatus::Created {
			return Ok(false);
		}

		let mut hold_client = match &self.hold_rpc {
			Some(client) => client.clone(),
			None => {
				warn!("No hold rpc client, cannot handle accepted invoice");
				return Ok(false);
			},
		};

		let payment_hash = htlc_subscription.invoice.payment_hash();

		// Fetch HTLC details (TrackAllResponse only provides state, not HTLC details)
		let req = hold::ListRequest {
			constraint: Some(hold::list_request::Constraint::PaymentHash(
				payment_hash.to_byte_array().to_vec(),
			)),
		};
		let res = hold_client.list(req).await?.into_inner();

		let accepted_invoice = match res.invoices.iter().find(|i| i.state == InvoiceState::Accepted as i32) {
			Some(invoice) => invoice,
			None => {
				// Invoice is no longer in Accepted state
				return Ok(false);
			},
		};

		let lowest_incoming_htlc_expiry = match accepted_invoice.htlcs.iter().map(|h| h.cltv_expiry).min() {
			Some(Some(lowest_incoming_htlc_expiry)) => {
				// CLN reports this as a u64; validate it fits a BlockHeight and is
				// within the policy bounds rather than silently truncating.
				match check_block_height(lowest_incoming_htlc_expiry) {
					Ok(height) => height,
					Err(_) => {
						warn!("CLN returned out-of-range HTLC expiry height {} for accepted \
							invoice of subscription {}",
							lowest_incoming_htlc_expiry, htlc_subscription.id,
						);
						return Ok(false);
					},
				}
			},
			None | Some(None) => {
				warn!("CLN returned no HTLC expiry height for accepted invoice of subscription {}",
					htlc_subscription.id,
				);
				return Ok(false);
			},
		};

		let invoice = match Bolt11Invoice::from_str(&accepted_invoice.invoice) {
			Ok(invoice) => {
				debug_assert_eq!(htlc_subscription.invoice, invoice,
					"HTLC subscription invoice != hold plugin response's invoice");
				invoice
			},
			Err(e) => {
				warn!("Failed to parse invoice from cln: '{}', {}", accepted_invoice.invoice, e);
				return Ok(false);
			},
		};

		// Get current tip for expiry validation
		let tip = self.sync_manager.chain_tip().height;

		// NB: We subtract 1 to give some buffer for the lightning payment to be sent.
		let min_final_cltv_expiry_delta = check_block_delta(invoice.min_final_cltv_expiry_delta())
			.context("invoice min_final_cltv_expiry_delta out of range")?;
		let required_min_htlc_expiry = tip
			.checked_add(min_final_cltv_expiry_delta)
			.map(|h| h.saturating_sub(BlockDelta::new(1)))
			.context("required_min_htlc_expiry overflows BlockHeight")?;

		// What the node is holding: the sum that covers the receive.
		let accepted_amount_msat: u64 = accepted_invoice.htlcs.iter()
			.filter(|h| h.state == InvoiceState::Accepted as i32)
			.map(|h| h.msat)
			.sum();

		let (status, expiry) = if lowest_incoming_htlc_expiry >= required_min_htlc_expiry {
			debug!("Lightning htlc subscription ({}) was accepted.", htlc_subscription.id);
			(LightningHtlcSubscriptionStatus::Accepted, Some(lowest_incoming_htlc_expiry))
		} else {
			debug!("Incoming HTLC expiry height ({}) for subscription doesn't fit. required {}, actual {}",
				htlc_subscription.id, required_min_htlc_expiry, lowest_incoming_htlc_expiry
			);
			(LightningHtlcSubscriptionStatus::Canceled, None)
		};

		// The `Created` check at the top of this function ran before the hold
		// RPCs above, so guard the transition on it here too: a subscription
		// canceled or settled in the meantime must not be moved.
		let payment_hash = PaymentHash::from(*htlc_subscription.invoice.payment_hash());
		let node_id = self.node_id;
		let applied = self.db.write(async |t| {
			let applied = t.store_lightning_htlc_subscription_status(
				htlc_subscription.id, status, expiry,
				Some(LightningHtlcSubscriptionStatus::Created),
			).await?;
			// The hold invoice row copies what the plugin reports, in the same
			// transaction: the node is holding these HTLCs. That is so even
			// when the subscription is canceled for an expiry that does not
			// fit: nothing cancels the invoice on the node then, and the HTLCs
			// stay held until the payer times them out, which the plugin
			// reports as unpaid.
			if applied {
				let hold_transition = HoldTransition::Accepted {
					amount_msat: accepted_amount_msat,
					lowest_incoming_htlc_expiry,
				};
				let mirrored = hold_db::transition_open_hold(
					&**t, node_id, payment_hash, hold_transition,
				).await?;
				if mirrored.is_none() {
					debug!("No open cln_hold row for subscription ({}) to move to {}",
						htlc_subscription.id, status,
					);
				}
			}
			Ok(applied)
		}).await?;
		if !applied {
			debug!("Lightning htlc subscription ({}) left Created while being accepted; \
				skipping the {} transition.", htlc_subscription.id, status,
			);
			return Ok(false);
		}

		// Wake check_lightning_receive so the client sees the new status.
		let _ = self.payment_update_tx.send(payment_hash);

		if status == LightningHtlcSubscriptionStatus::Accepted {
			// Post mailbox notification so the client knows to come online and claim
			let payment_hash = PaymentHash::from(*htlc_subscription.invoice.payment_hash());
			post_lightning_receive_notification(
				&self.db, &self.mailbox_manager, payment_hash, htlc_subscription.amount(),
			).await;
		}

		Ok(status == LightningHtlcSubscriptionStatus::Accepted)
	}

	/// Polls hold plugin for invoice state changes.
	/// This is the legacy approach, to be replaced by TrackAll.
	async fn poll_htlc_state_updates(&mut self) -> anyhow::Result<()> {
		let mut hold_client = match &self.hold_rpc {
			Some(client) => client.clone(),
			None => {
				warn!("No hold rpc client, skipping polling for htlc state updates");
				return Ok(());
			},
		};

		let htlc_subscriptions = self.db.read(async |t| t.get_open_lightning_htlc_subscriptions(
			self.node_id,
		).await).await?;

		let created_subs = htlc_subscriptions.into_iter()
			.filter(|s| s.status == LightningHtlcSubscriptionStatus::Created)
			.collect::<Vec<_>>();

		if created_subs.is_empty() {
			return Ok(());
		}

		let payment_hashes = created_subs.iter()
			.map(|s| s.invoice.payment_hash().to_byte_array().to_vec())
			.collect::<Vec<_>>();
		let accepted_hashes = fetch_accepted_payment_hashes(
			&mut hold_client, payment_hashes,
		).await?;

		debug!("poll_htlc_state_updates: {} created subs, {} accepted invoices in plugin",
			created_subs.len(), accepted_hashes.len(),
		);

		for htlc_subscription in created_subs {
			let payment_hash = htlc_subscription.invoice.payment_hash();
			if accepted_hashes.contains(payment_hash) {
				self.handle_invoice_accepted(&htlc_subscription).await?;
			}
		}

		Ok(())
	}

	/// Attempts to establish TrackAll stream.
	/// With an empty payment_hashes list, the stream returns updates for ALL invoices.
	async fn connect_track_all(&mut self) -> anyhow::Result<tonic::codec::Streaming<hold::TrackAllResponse>> {
		let hold_client = self.hold_rpc.as_mut().context("hold_rpc required")?;

		// Empty list means track ALL invoice updates
		let request = hold::TrackAllRequest { payment_hashes: vec![] };
		let stream = hold_client.track_all(request).await?.into_inner();

		Ok(stream)
	}

	/// Calculate exponential backoff delay for TrackAll reconnection.
	fn track_all_backoff(&self, attempt: u32) -> Duration {
		let base = self.config.track_all_base_delay.as_secs();
		let max = self.config.max_track_all_delay.as_secs();
		// Cap exponent at 6 to prevent overflow (2^6 = 64)
		Duration::from_secs((base * 2u64.pow(attempt.min(6))).min(max))
	}

	/// Handle a TrackAll stream event - process invoice acceptance, and mirror
	/// cancellations onto the hold invoice's record.
	async fn handle_track_all_event(&mut self, response: hold::TrackAllResponse) -> anyhow::Result<()> {
		let payment_hash = sha256::Hash::from_slice(&response.payment_hash)?;
		let state = hold::InvoiceState::try_from(response.state).ok();

		match state {
			Some(hold::InvoiceState::Accepted) => {
				if let Some(sub) = self.db
					.read(async |t| t.get_open_htlc_subscription_for_node_by_payment_hash(
						self.node_id,
						&PaymentHash::from(payment_hash),
					).await).await?
				{
					self.handle_invoice_accepted(&sub).await?;
				}
			},
			// Our own cancels record themselves, but the plugin also cancels on
			// its own when held HTLCs near their expiry, and the intra-Ark
			// cancel's write can be lost after its RPC. Whichever write comes
			// first moves the row. The subscription is left to the timeout
			// checks.
			Some(hold::InvoiceState::Cancelled) => {
				let node_id = self.node_id;
				let payment_hash = PaymentHash::from(payment_hash);
				let cancelled = self.db.write(async |t| hold_db::transition_open_hold(
					&**t, node_id, payment_hash, HoldTransition::Cancelled,
				).await).await?;
				if cancelled.is_some() {
					debug!("Hold invoice for {} was cancelled by the plugin", payment_hash);
				}
			},
			_ => {},
		}
		Ok(())
	}

	async fn cancel_invoice_and_htlc_subscription(
		&self,
		hold_client: &mut HoldClient<Channel>,
		payment_hash: &sha256::Hash,
		htlc_subscription: &LightningHtlcSubscription,
		reason: &str,
	) -> anyhow::Result<()> {
		hold_client.cancel(hold::CancelRequest {
			payment_hash: payment_hash.to_byte_array().to_vec(),
		}).await?;

		slog!(LightningReceiveCanceled,
			payment_hash: htlc_subscription.payment_hash,
			reason: reason.to_owned(),
		);

		// The snapshot predates the hold RPCs the callers make, so guard on the
		// status we saw. A subscription settled in the meantime keeps its
		// settlement, and its payment attempt is left alone.
		let node_id = self.node_id;
		let hash = PaymentHash::from(*payment_hash);
		let canceled = self.db.write(async |t| {
			let canceled = t.store_lightning_htlc_subscription_status(
				htlc_subscription.id,
				LightningHtlcSubscriptionStatus::Canceled,
				None,
				Some(htlc_subscription.status),
			).await?;
			// The plugin no longer serves the invoice; its row says so too.
			if canceled {
				let mirrored = hold_db::transition_open_hold(
					&**t, node_id, hash, HoldTransition::Cancelled,
				).await?;
				if mirrored.is_none() {
					debug!("No open cln_hold row to cancel for subscription ({})",
						htlc_subscription.id,
					);
				}
			}
			Ok(canceled)
		}).await?;
		if !canceled {
			debug!("Lightning htlc subscription ({}) left {} before it could be \
				canceled; not failing its payment attempt.",
				htlc_subscription.id, htlc_subscription.status,
			);
			return Ok(());
		}

		// Fail the intra-Ark self-payment initiated against this
		// subscription, if any. An unrelated outgoing payment that merely
		// shares the payment hash is not a self-payment and must be left
		// alone.
		let payment_attempt = self.db.read(async |t|
			t.get_open_lightning_payment_attempt_by_subscription_id(htlc_subscription.id).await
		).await?;
		if let Some(payment_attempt) = payment_attempt {
			debug!("HTLC subscription canceled with ongoing payment attempt, \
				marking as failed: {}", payment_attempt.id,
			);
			self.payment_handler().fail_payment_attempt(&payment_attempt, Some(reason)).await?;
		} else {
			telemetry::add_lightning_payment(
				htlc_subscription.lightning_node_id,
				htlc_subscription.amount().to_msat(),
				telemetry::LightningPaymentMetricStatus::Canceled,
				telemetry::LightningDirection::Receive,
				false,
				htlc_subscription.user_agent.as_deref(),
				None,
				None,
			);
		}

		Ok(())
	}

	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnHold({})", self.node_id))
			.with_notify(mgr_waker);

		let mut invoice_interval = tokio::time::interval(self.config.invoice_check_interval);

		// Initialize TrackAll state based on whether hold_rpc is available
		let mut track_all_state = if self.hold_rpc.is_some() {
			TrackAllStreamState::NeedsConnect
		} else {
			TrackAllStreamState::Disabled
		};
		// NB we can't change the state while we have a mutable borrow on the state
		// so we use this variable to trigger reconnects in the event loop
		// it holds the attempt number we should set on failure
		let mut track_all_reconnect_attempt = None;

		// we have two nested loops so that we can keep the various streams
		// alive while we receive messages over all channels
		'requests: loop {
			// Attempt TrackAll connection if needed
			match track_all_state {
				TrackAllStreamState::NeedsConnect => {
					track_all_reconnect_attempt = Some(1);
				},
				TrackAllStreamState::Backoff { attempt, retry_at }
					if tokio::time::Instant::now() > retry_at =>
				{
					track_all_reconnect_attempt = Some(attempt + 1);
				},
				_ => {},
			}
			if let Some(next_attempt) = track_all_reconnect_attempt {
				track_all_reconnect_attempt = None;
				match self.connect_track_all().await {
					Ok(stream) => {
						info!("TrackAll stream connected");
						// One-time reconciliation to catch any events missed during disconnect
						if let Err(e) = self.poll_htlc_state_updates().await {
							warn!("TrackAll post-connect reconciliation failed: {:#}", e);
						}
						track_all_state = TrackAllStreamState::Connected(stream);
					},
					Err(e) => {
						warn!("TrackAll connect failed: {:#}", e);
						let attempt = next_attempt;
						let backoff_delay = self.track_all_backoff(attempt);
						let retry_at = tokio::time::Instant::now() + backoff_delay;
						track_all_state = TrackAllStreamState::Backoff { attempt, retry_at };
					},
				}
			}

			// whether our invoice_interval should handle subscriptions or only timeouts.
			// Backoff polls too: otherwise Created -> Accepted detection waits for
			// reconnect, delaying up to `max_track_all_delay`.
			let interval_handle_subscriptions = match track_all_state {
				TrackAllStreamState::Connected(_) => false,
				TrackAllStreamState::Backoff { .. } => true,
				TrackAllStreamState::Disabled | TrackAllStreamState::NeedsConnect => true,
			};

			// to simplify the select event loop below, we first extract the two possible
			// futures for the track_all system.
			// note that we place never-ending `pending` stubs if we don't need them
			let (mut track_all_stream, mut track_all_backoff): (
				Pin<Box<dyn Stream<Item = Result<_, _>> + Send>>,
				Pin<Box<dyn Future<Output = ()> + Send>>,
			) = match track_all_state {
				TrackAllStreamState::Connected(ref mut stream) => {
					(Box::pin(stream), Box::pin(futures::future::pending()))
				},
				TrackAllStreamState::Backoff { retry_at, .. } => {
					let sleep = tokio::time::sleep_until(retry_at);
					(Box::pin(tokio_stream::pending()), Box::pin(sleep))
				},
				_ => (Box::pin(tokio_stream::pending()), Box::pin(futures::future::pending())),
			};

			loop {
				tokio::select! {
					_ = rtmgr.shutdown_signal() => return Ok(()),
					event = track_all_stream.next() => {
						match event {
							Some(Ok(resp)) => {
								if let Err(e) = self.handle_track_all_event(resp).await {
									warn!("TrackAll event error: {:#}", e);
								}
							}
							Some(Err(e)) => {
								warn!("TrackAll stream error: {:#}", e);
								track_all_reconnect_attempt = Some(0);
								continue 'requests;
							}
							None => {
								info!("TrackAll stream ended");
								track_all_reconnect_attempt = Some(0);
								continue 'requests;
							}
						}
					},
					_ = &mut track_all_backoff => {
						info!("TrackAll backoff expired, reconnecting");
						continue 'requests;
					},
					_ = invoice_interval.tick() => {
						// Log rather than propagate: killing the worker would break
						// the TrackAll reconnect loop we depend on to recover.
						let res = if interval_handle_subscriptions {
							self.process_htlc_subscriptions().await
						} else {
							self.check_htlc_subscription_timeouts().await
						};
						if let Err(e) = res {
							warn!("htlc subscription processing failed: {:#}", e);
						}
					},
				}
			}
		}
	}
}
