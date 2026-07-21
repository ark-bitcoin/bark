//! Manages lightning node connections and proxies requests to per-backend monitors.
//!
//! ## Node lifecycle
//!
//! Each configured node is tracked by a per-backend node-info struct with the
//! same state machine: `Offline ↔ Online ↔ Error`, where `Invalid` and
//! `Disabled` are terminal states. The manager periodically reconnects
//! offline/errored nodes and monitors online nodes for crashed sub-monitors.
//! When multiple nodes are online, the highest-priority node is selected for
//! operations.
//!
//! ## Architecture
//!
//! [`LightningManager`] is the public handle held by the rest of the server.
//! `LightningManagerProcess` runs as a tokio task and is a pure supervisor:
//! it reconnects offline nodes, watches monitor liveness, and republishes a
//! snapshot of `NodeHandle`s for the currently-online nodes into a shared
//! `parking_lot::RwLock` whenever node state changes.
//!
//! Data-path operations (pay, generate/settle/cancel invoice, fetch bolt12)
//! run directly on the caller's task: they pick a node via one of the
//! manager's getters (`active_node`, `hold_active_node`, `node_by_id`) and
//! issue RPCs on the cloned handle. A small `Ctrl` mpsc channel survives only
//! for `activate`/`disable`, where the supervisor owns the state transition.
//!
//! ## Routing
//!
//! `generate_invoice`/`settle_invoice`/`cancel_invoice` route to the backend's
//! receive monitor (e.g. `ClnHold` for CLN). `pay` routes to the backend's pay
//! monitor (e.g. `ClnXpay`). `fetch_bolt12` calls the backend's gRPC directly.
//! Intra-Ark payments short-circuit both paths: the manager updates the DB and
//! broadcasts the result without making a backend round-trip.

use std::fmt;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight};
use cln_rpc::plugins::hold as hold_plugin;
use lightning_invoice::Bolt11Invoice;
use futures::Stream;
use tokio::sync::{broadcast, Notify, mpsc};
use tokio_stream::StreamExt;
use tonic::transport::Uri;
use tracing::{debug, error, info, trace, warn};
use ark::VtxoId;
use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, PaymentHash, PaymentStatus, Preimage};
use ark::mailbox::MailboxIdentifier;

use crate::Server;
use crate::error::ContextExt;
use crate::ln::cln::{ClnNodeInfo, ClnNodeOnlineState, NodeHandle};
use crate::ln::cln::hold::ClnHoldConfig;
use crate::ln::cln::xpay::ClnXpayConfig;
use crate::ln::settler::HtlcSettler;
use crate::sync::SyncManager;
use crate::system::RuntimeManager;
use crate::config::Config;
use crate::database;
use crate::database::ln::{
	LightningNodeId, LightningHtlcSubscription, LightningHtlcSubscriptionStatus, LightningPaymentStatus,
};
use crate::telemetry;

use super::payment_handler::PaymentAttemptHandler;

/// Handle for the cln manager process.
pub struct LightningManager {
	db: database::Db,
	settler: Arc<HtlcSettler>,
	invoice_poll_interval: Duration,
	invoice_expiry: Duration,
	htlc_expiry_delta: BlockDelta,
	cln_xpay_timeout: Duration,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,

	/// This channel is to manage individual CLN integrations.
	ctrl_tx: mpsc::UnboundedSender<Ctrl>,

	/// Snapshot of command handles for the currently-online nodes, republished
	/// by the manager process on every maintenance pass. The node getters read
	/// from here to route data-path operations without a channel round-trip.
	node_handles: Arc<parking_lot::RwLock<Vec<NodeHandle>>>,

	/// We also keep a handle of the update channel to update from
	/// payment request that fail before the hit the sendpay stream.
	//TODO(stevenroose) consider changing this to hold some update info
	payment_update_tx: broadcast::Sender<PaymentHash>,
	// If all receivers are dropped the channel will close and the payment might fail
	// The only purpose of this field is to ensure we will always keep at least one receiver alive
	payment_update_rx: broadcast::Receiver<PaymentHash>,
}

impl LightningManager {
	fn payment_handler(&self) -> PaymentAttemptHandler<'_> {
		PaymentAttemptHandler::new(&self.db, &self.mailbox_manager, &self.payment_update_tx)
	}

	/// Start the [LightningManager].
	pub async fn start(
		rtmgr: RuntimeManager,
		config: &Config,
		db: database::Db,
		sync_manager: Arc<SyncManager>,
		mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
		settler: Arc<HtlcSettler>,
	) -> anyhow::Result<LightningManager> {
		let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
		let (payment_update_tx, payment_update_rx) = broadcast::channel(256);
		let node_handles = Arc::new(parking_lot::RwLock::new(Vec::new()));

		let hold_config = ClnHoldConfig {
			invoice_check_interval: config.invoice_check_interval,
			receive_htlc_forward_timeout: config.receive_htlc_forward_timeout,
			track_all_base_delay: config.track_all_base_delay,
			max_track_all_delay: config.max_track_all_delay,
		};
		let xpay_config = ClnXpayConfig {
			invoice_check_interval: config.invoice_check_interval,
			cln_xpay_timeout: config.cln_xpay_timeout,
			check_base_delay: config.invoice_check_base_delay,
			max_check_delay: config.max_invoice_check_delay,
		};
		let proc = LightningManagerProcess {
			db: db.clone(),
			rtmgr,
			waker: Arc::new(Notify::new()),

			ctrl_rx,
			node_handles: node_handles.clone(),
			hold_config,
			xpay_config,
			sync_manager,
			mailbox_manager: mailbox_manager.clone(),
			settler: settler.clone(),

			payment_update_tx: payment_update_tx.clone(),

			network: config.network,
			nodes: config.cln_array.iter().map(|conf| (conf.uri.clone(), ClnNodeInfo {
				uri: conf.uri.clone(),
				config: conf.clone(),
				state: NodeState::Offline,
			})).collect(),
			node_by_id: HashMap::with_capacity(config.cln_array.len()),
		};
		info!("Starting LightningManager thread... nb_nodes={}", proc.nodes.len());
		tokio::spawn(proc.run(config.cln_reconnect_interval));

		Ok(LightningManager {
			db,
			settler,
			mailbox_manager,
			ctrl_tx,
			node_handles,
			payment_update_tx,
			payment_update_rx,
			invoice_poll_interval: config.invoice_poll_interval,
			invoice_expiry: config.invoice_expiry,
			htlc_expiry_delta: config.htlc_expiry_delta,
			cln_xpay_timeout: config.cln_xpay_timeout,
		})
	}

	/// Subscribe to payment status changes.
	pub fn subscribe_payment_updates(&self) -> broadcast::Receiver<PaymentHash> {
		self.payment_update_rx.resubscribe()
	}

	/// Signal that a payment's status has changed.
	pub fn notify_payment_update(&self, payment_hash: PaymentHash) {
		let _ = self.payment_update_tx.send(payment_hash);
	}

	/// Send a control message to the process
	fn send_ctrl(&self, ctrl: Ctrl) {
		self.ctrl_tx.send(ctrl).expect("called LightningManager after shutting down");
	}

	/// The highest-priority online node, if any.
	///
	/// Reads the snapshot published by the manager process; the returned handle
	/// talks to the node directly, without a control-channel round-trip.
	fn active_node(&self) -> Option<NodeHandle> {
		self.node_handles.read().iter().min_by_key(|h| h.priority).cloned()
	}

	/// The highest-priority online node that supports hold invoices, if any.
	fn hold_active_node(&self) -> Option<NodeHandle> {
		self.node_handles.read().iter()
			.filter(|h| h.hold_rpc.is_some())
			.min_by_key(|h| h.priority)
			.cloned()
	}

	/// Whether a hold-capable lightning node is currently registered as online.
	pub fn has_hold_active_node(&self) -> bool {
		self.hold_active_node().is_some()
	}

	/// The currently-online node with the given id, if any.
	fn node_by_id(&self, id: LightningNodeId) -> Option<NodeHandle> {
		self.node_handles.read().iter().find(|h| h.id == id).cloned()
	}

	/// Pays a bolt-11 invoice
	///
	/// This method is also more clever than calling the grpc-method.
	/// We might be able to recover from a short connection-break or time-outs
	/// from Core Lightning.
	#[tracing::instrument(skip_all, fields(
		payment_hash = %invoice.payment_hash(),
		invoice = %invoice,
		payment_amount = %payment_amount,
		max_routing_fee = %max_routing_fee,
		htlc_send_expiry_height,
	))]
	pub async fn pay_invoice(
		&self,
		invoice: &Invoice,
		payment_amount: Amount,
		max_routing_fee: Amount,
		htlc_send_expiry_height: BlockHeight,
		sender_mailbox_id: Option<MailboxIdentifier>,
		htlc_vtxo_ids: Vec<VtxoId>,
		user_fee: Amount,
	) -> anyhow::Result<()> {
		invoice.check_signature().context("invalid invoice signature")?;

		debug!("Sending payment to CLN for invoice: {}", invoice);

		if let Err(e) = self.start_payment(
			Box::new(invoice.clone()),
			payment_amount,
			max_routing_fee,
			htlc_send_expiry_height,
			sender_mailbox_id.as_ref(),
			&htlc_vtxo_ids,
			user_fee,
		).await {
			error!("Error sending bolt11 payment for invoice: {:#}", e);
		} else {
			debug!("Bolt11 invoice sent for payment");
		}

		Ok(())
	}

	/// Kick off a bolt-11 payment on the highest-priority online node.
	///
	/// If a hold-invoice subscription already exists for this payment hash,
	/// this is an intra-Ark payment and we settle off-CLN instead of issuing
	/// an outbound xpay. Otherwise we spawn the xpay fire-and-forget; the
	/// xpay monitor picks the result up via the sendpays stream.
	#[tracing::instrument(skip_all, fields(
		payment_hash = %invoice.payment_hash(),
		invoice = %invoice,
		amount = %amount,
		max_routing_fee = %max_routing_fee,
		htlc_send_expiry_height,
	))]
	async fn start_payment(
		&self,
		invoice: Box<Invoice>,
		amount: Amount,
		max_routing_fee: Amount,
		htlc_send_expiry_height: BlockHeight,
		sender_mailbox_id: Option<&MailboxIdentifier>,
		htlc_vtxo_ids: &[VtxoId],
		user_fee: Amount,
	) -> anyhow::Result<()> {
		let payment_hash = invoice.payment_hash();
		let node = self.active_node().context("no active cln node")?;
		let tip = node.rpc.clone().getinfo(cln_rpc::GetinfoRequest {}).await
			.context("failed to get info from rpc")?
			.into_inner().blockheight;

		debug!("Selected cln node {} for bolt11 payment with payment hash {} and amount {}. \
			Current block height is {}", node.id, payment_hash, amount, tip,
		);

		self.db.write(async |t|
			t.store_lightning_payment_start(node.id, &invoice, amount, sender_mailbox_id, htlc_vtxo_ids).await
		).await?;

		// If there is an existing subscription, it's an intra-Ark lightning
		// payment so we can directly mark it as accepted, then skip cln payment.
		let sub = self.db.read(async |t| t.get_htlc_subscription_by_payment_hash(payment_hash).await).await?;
		if let Some(sub) = sub {
			trace!("Updating subscription status for intra-Ark lightning payment with payment hash {payment_hash}");
			let res = self.set_created_subscription_to_accepted(sub, htlc_send_expiry_height).await;
			if let Err(e) = res {
				trace!("Failed to update subscription status: {e:#}");
				let payment_attempt = self.db
					.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await?
					.expect("we inserted a payment attempt");

				self.payment_handler().fail_payment_attempt(&payment_attempt, Some(&e.to_string())).await?;
				return Err(e);
			}

			return Ok(());
		}

		// NB: we don't want a lightning payment to take more time than the
		// htlc-send expiry leaves us with.
		let max_cltv_expiry_delta = htlc_send_expiry_height
			.checked_sub(tip + self.htlc_expiry_delta as BlockHeight)
			.context("HTLC expiry height is too soon to perform a lightning payment")?;

		// Fire-and-forget: ClnXpayClient::pay issues the gRPC and reconciles
		// the DB on completion, same as the old ClnXpay::pay wrapper. If the
		// gRPC times out the payment may still succeed; the xpay monitor's
		// sendpay stream is the source of truth.
		trace!("Bolt11 invoice payment of {:?} sent to CLN: {}", amount, invoice);
		let xpay_client = node.xpay.clone();
		let retry_for = self.cln_xpay_timeout;
		tokio::spawn(async move {
			xpay_client.pay(
				invoice,
				amount,
				max_routing_fee,
				max_cltv_expiry_delta as BlockDelta,
				retry_for,
			).await;
		});
		slog!(LightningPaymentInitiated, payment_hash, amount, fee: user_fee,
			min_expiry: htlc_send_expiry_height,
		);

		Ok(())
	}

	/// Promote a Created hold-invoice subscription to Accepted for an
	/// intra-Ark payment, cancel the locked hold HTLCs on the receiving
	/// node, and notify the receiver to come online.
	async fn set_created_subscription_to_accepted(
		&self,
		subscription: LightningHtlcSubscription,
		htlc_send_expiry_height: BlockHeight,
	) -> anyhow::Result<()> {
		match subscription.status {
			LightningHtlcSubscriptionStatus::Created => {
				self.db.write(async |t| t.store_lightning_htlc_subscription_status(
					subscription.id,
					LightningHtlcSubscriptionStatus::Accepted,
					Some(htlc_send_expiry_height),
				).await).await?;

				let payment_hash = PaymentHash::from(&subscription.invoice);
				// Wake check_lightning_receive so the client sees Accepted.
				let _ = self.payment_update_tx.send(payment_hash);

				// Post mailbox notification so the client knows to come online and claim
				post_lightning_receive_notification(
					&self.db, &self.mailbox_manager, payment_hash,
				).await;

				// Cancel the hold invoice on the receiving node: the intra-Ark
				// payment settles off-CLN, so we don't want the HTLCs locked.
				// NB: we only issue the RPC here, not the full cancel_invoice
				// flow - we just set the subscription to Accepted, not Canceled.
				let mut hold_client = self.node_by_id(subscription.lightning_node_id)
					.context("invoice cannot be canceled: node is now offline")?
					.hold_rpc.context("node doesn't support hold anymore")?;
				hold_client.cancel(hold_plugin::CancelRequest {
					payment_hash: payment_hash.to_vec(),
				}).await?;
			},
			LightningHtlcSubscriptionStatus::Accepted |
			LightningHtlcSubscriptionStatus::HtlcsReady |
			LightningHtlcSubscriptionStatus::Settled |
			LightningHtlcSubscriptionStatus::Canceled => {
				bail!("invoice is not in a valid state to pay: {}. expected: {}",
					subscription.status,
					LightningHtlcSubscriptionStatus::Created,
				);
			}
		};

		Ok(())
	}

	/// Gets the payment status for a given payment hash
	pub async fn get_payment_status(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<PaymentStatus> {
		trace!("Getting payment status for payment hash: {}. wait: {}",
			payment_hash, wait);

		let mut update_rx = self.payment_update_rx.resubscribe();
		let mut poll_interval = tokio::time::interval(self.invoice_poll_interval);

		loop {
			tokio::select! {
				_ = poll_interval.tick() => trace!("check bolt11 timeout reached, polling"),
				// Trigger received on channel
				rcv = update_rx.recv() => match rcv {
					Ok(hash) => {
						if hash != payment_hash {
							continue;
						}
					},
					Err(broadcast::error::RecvError::Lagged(_)) => continue,
					Err(broadcast::error::RecvError::Closed) => {
						bail!("payment update channel closed, probably shutting down");
					},
				},
			}

			let attempt = self.db.read(async |t|
				t.get_latest_payment_attempt_by_payment_hash(payment_hash).await
			).await?.not_found([payment_hash], "payment attempt not found")?;

			// Check payment status
			trace!("Payment attempt status for payment {}: {}",
				payment_hash, attempt.status,
			);

			if attempt.status == LightningPaymentStatus::Succeeded {
				let preimage = self.settler.is_settled(payment_hash).await?
					.context("missing preimage on payment success")?;
				debug!(payment_hash = %payment_hash, preimage = %preimage, "CheckLightningPayment responding with success");
				return Ok(PaymentStatus::Success(preimage));
			}

			if attempt.status == LightningPaymentStatus::Failed {
				debug!(payment_hash = %payment_hash, "CheckLightningPayment responding with failed");
				return Ok(PaymentStatus::Failed);
			}

			if !wait {
				trace!(payment_hash = %payment_hash, "CheckLightningPayment responding with pending");
				return Ok(PaymentStatus::Pending);
			}
			// Continue loop, wait for next trigger or timeout
		}
	}

	/// Generate (or, when a prior subscription exists, reuse) a bolt-11 invoice
	/// on the highest-priority hold-capable node.
	pub async fn generate_invoice(
		&self,
		payment_hash: PaymentHash,
		amount: Amount,
		cltv_delta: BlockDelta,
		description: Option<String>,
		receiver_mailbox_id: Option<MailboxIdentifier>,
	) -> anyhow::Result<Bolt11Invoice> {
		let node = self.hold_active_node().context("no active hold-compatible cln node")?;
		let mut hold_client = node.hold_rpc.clone().expect("hold-active node has hold_rpc");

		// Reuse the invoice from any prior subscription (e.g. from a previous
		// canceled attempt) so the payer can settle to the same payment hash.
		let existing_subs = self.db.read(async |t|
			t.get_htlc_subscriptions_by_payment_hash(payment_hash).await
		).await?;
		if let Some(existing) = existing_subs.first() {
			trace!("Found existing subscription, creating new one with same invoice");

			hold_client.inject(hold_plugin::InjectRequest {
				invoice: existing.invoice.to_string(),
				min_cltv_expiry: None,
			}).await?;

			self.db.write(async |t|
				t.store_lightning_htlc_subscription(node.id, payment_hash, &existing.invoice).await
			).await?;
			return Ok(existing.invoice.clone())
		}

		let res = hold_client.invoice(hold_plugin::InvoiceRequest {
			payment_hash: payment_hash.to_vec(),
			amount_msat: amount.to_msat(),
			min_final_cltv_expiry: Some(cltv_delta as u64),
			expiry: Some(self.invoice_expiry.as_secs()),
			routing_hints: vec![],
			description: description.map(hold_plugin::invoice_request::Description::Memo),
		}).await?.into_inner();

		let invoice = Bolt11Invoice::from_str(&res.bolt11)?;
		self.db.write(async |t|
			t.store_generated_lightning_receive(
				node.id, &invoice, amount.to_msat(), receiver_mailbox_id.as_ref(),
			).await
		).await?;

		Ok(invoice)
	}

	/// Settle a hold invoice in CLN or, for intra-ark payments, mark the
	/// invoice as succeeded directly.
	///
	/// The caller must ensure the preimage has already been recorded in
	/// the [`HtlcSettler`] before calling this.
	async fn settle_invoice(
		&self,
		subscription_id: i64,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let payment_hash = preimage.compute_payment_hash();

		// If an open payment attempt exists for the payment hash, it is an
		// intra-Ark lightning payment so we can mark it as succeeded,
		// then skip hold invoice settlement.
		let attempt = self.db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await).await?;
		if let Some(attempt) = attempt {
			// NB: the xpay reconciliation loop may also post the mailbox notification
			// for the same payment hash. The DB insert is idempotent (ON CONFLICT DO NOTHING).
			self.payment_handler().process_payment_attempt(
				&self.settler, &attempt,
				LightningPaymentStatus::Succeeded,
				None,
				None,
				Some(preimage),
			).await?;
		} else {
			// Settle the hold invoice on the node that created the
			// subscription - that's where the HTLCs are locked. The user has
			// already revealed the preimage, so if that node is now offline
			// we cannot recover and the caller will surface the error.
			let htlc_subscription = self.db
				.read(async |t| t.get_htlc_subscription_by_id(subscription_id).await).await?
				.expect("can only settle known invoice");
			let mut hold_client = self.node_by_id(htlc_subscription.lightning_node_id)
				.context("invoice cannot be settled: node is now offline")?
				.hold_rpc.context("node doesn't support hold anymore")?;
			hold_client.settle(hold_plugin::SettleRequest {
				payment_preimage: preimage.to_vec(),
			}).await?;
		}

		// Update the subscription status to settled and notify waiters.
		// This covers both intra-ark (no CLN hook fires) and regular
		// hold-invoice paths.
		self.db.write(async |t| t.store_lightning_htlc_subscription_status(
			subscription_id,
			LightningHtlcSubscriptionStatus::Settled,
			None
		).await).await?;
		let _ = self.payment_update_tx.send(payment_hash);

		Ok(())

	}

	pub async fn cancel_invoice(
		&self,
		subscription: LightningHtlcSubscription,
	) -> anyhow::Result<()> {
		let id = subscription.id;
		let payment_hash = PaymentHash::from(*subscription.invoice.payment_hash());

		// Cancel on the node that created the subscription.
		let mut hold_client = self.node_by_id(subscription.lightning_node_id)
			.context("invoice cannot be canceled: node is now offline")?
			.hold_rpc.context("node doesn't support hold anymore")?;
		hold_client.cancel(hold_plugin::CancelRequest {
			payment_hash: payment_hash.to_vec(),
		}).await?;

		self.db.write(async |t| t.store_lightning_htlc_subscription_status(
			id,
			LightningHtlcSubscriptionStatus::Canceled,
			None,
		).await).await?;
		self.notify_payment_update(payment_hash);

		Ok(())
	}

	/// Fetches and parse an invoice from a bolt-12 offer
	pub async fn fetch_bolt12_invoice(
		&self,
		offer: Offer,
		amount: Amount,
	) -> anyhow::Result<Bolt12Invoice> {
		let node = self.active_node().context("no active cln node")?;

		let resp = node.rpc.clone().fetch_invoice(cln_rpc::FetchinvoiceRequest {
			offer: offer.to_string(),
			amount_msat: Some(cln_rpc::Amount { msat: amount.to_msat() }),
			quantity: None,
			recurrence_counter: None,
			recurrence_start: None,
			recurrence_label: None,
			timeout: None,
			payer_note: None,
			payer_metadata: None,
			bip353: None,
		}).await?.into_inner();

		Bolt12Invoice::from_str(&resp.invoice)
			.map_err(|e| anyhow!("Invalid bolt12 invoice: {:?}", e))
	}

	pub fn activate(&self, uri: Uri) {
		self.send_ctrl(Ctrl::ActivateNode(uri));
	}

	pub fn disable(&self, uri: Uri) {
		self.send_ctrl(Ctrl::DisableNode(uri));
	}

	/// Spawn a background task that settles hold invoices on the active
	/// backend when new preimages appear on the settler's stream.
	///
	/// Design notes:
	///
	/// - Idempotent: skips subscriptions not in HtlcsReady state. Multiple
	///   paths write to the settler (cooperative claim_lightning_receive,
	///   on-chain preimage extraction via the frontier). The settler is the
	///   single source of truth for preimages; this subscriber is the sole
	///   path that settles hold invoices on the backend.
	///
	/// - Retry on failure: a settlement that fails is retried on the same
	///   item every 5 seconds until it succeeds, so one stuck preimage does
	///   not advance past unsettled work but never abandons it either.
	///
	/// - Backoff: 5s sleep between retries avoids busy-looping when the
	///   backend or database is persistently unavailable. The preimage is
	///   safe on the settler stream regardless.
	pub fn spawn_hold_settler(
		&self,
		srv: Arc<Server>,
		settlement_stream: impl Stream<Item = super::settler::Settlement> + Send + 'static,
	) {
		tokio::spawn(run_hold_settler(srv, settlement_stream));
	}
}

async fn run_hold_settler(
	srv: Arc<Server>,
	settlement_stream: impl Stream<Item = super::settler::Settlement>,
) {
	let _worker = srv.rtmgr.spawn_critical("HoldSettler");
	tokio::pin!(settlement_stream);

	loop {
		let item = tokio::select! {
			item = settlement_stream.next() => item,
			_ = srv.rtmgr.shutdown_signal() => return,
		};

		let Some(settlement) = item else { break };
		let (payment_hash, preimage) = (settlement.hash, settlement.preimage);

		while !try_settle_hold_invoice(&srv, payment_hash, preimage).await {
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_secs(5)) => {},
				_ = srv.rtmgr.shutdown_signal() => return,
			}
		}
	}
	error!("Hold settler exited: hold invoices will no longer be settled automatically");
}

/// Try to settle a single hold invoice. Returns true if the entry was
/// handled (or can be skipped), false if it should be retried.
///
/// The caller must ensure the preimage has already been recorded in
/// the [`HtlcSettler`].
async fn try_settle_hold_invoice(
	srv: &Server,
	payment_hash: PaymentHash,
	preimage: Preimage,
) -> bool {
	let sub = match srv.db.read(async |t| t.get_htlc_subscription_by_payment_hash(payment_hash).await).await {
		Ok(Some(sub)) => sub,
		Ok(None) => return true, // no subscription, nothing to settle
		Err(e) => {
			warn!("Failed to look up HTLC subscription for {}, will retry: {:#}", payment_hash, e);
			return false;
		}
	};

	if !matches!(sub.status, LightningHtlcSubscriptionStatus::HtlcsReady) {
		// Safe to skip: a preimage in the WAL implies HTLCs were already
		// locked (HtlcsReady was reached before the preimage was learned),
		// so the only other states here are Settled or the cooperative
		// path already handled it.
		return true;
	}

	if let Err(e) = srv.cln.settle_invoice(sub.id, preimage).await {
		warn!("Hold invoice settlement failed for {}, will retry: {:#}", payment_hash, e);
		return false;
	}

	true
}

/// Post a lightning receive notification to the mailbox if the invoice has a
/// mailbox_id associated with it. This notifies the client that a payment
/// has arrived and they should come online to claim it.
pub(crate) async fn post_lightning_receive_notification(
	db: &database::Db,
	mailbox_manager: &crate::mailbox_manager::MailboxManager,
	payment_hash: PaymentHash,
) {
	let res = db.write(async |t| {
		if let Some(id) = t.get_lightning_receiver_mailbox_id(payment_hash).await
			.context("failed to look up mailbox ID")?
		{
			// `None` means a notification for this payment hash already exists;
			// the re-post is silently ignored.
			let cp = t.store_lightning_receive_notification(id, &payment_hash.to_string()).await?;
			Ok(cp.map(|cp| (id, cp)))
		} else {
			Ok(None)
		}
	}).await;
	match res {
		Ok(Some((id, cp))) => mailbox_manager.notify(id, cp),
		Ok(None) => {},
		Err(e) => warn!("Error posting lightning receive notification for {}: {:#}", payment_hash, e),
	}
}

#[derive(Debug)]
pub enum NodeState {
	Offline,
	Online(ClnNodeOnlineState),
	Error {
		msg: String,
	},
	Invalid {
		msg: String,
	},
	Disabled,
}

const OFFLINE: &'static str = "offline";
const ONLINE: &'static str = "online";
const ERROR: &'static str = "error";
const INVALID: &'static str = "invalid";
const DISABLED: &'static str = "disabled";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeStateKind {
	/// see [NodeState::Offline]
	Offline,
	/// see [NodeState::Online]
	Online,
	/// see [NodeState::Error]
	Error,
	/// see [NodeState::Invalid]
	Invalid,
	/// see [NodeState::Disabled]
	Disabled,
}

impl NodeStateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			NodeStateKind::Offline => OFFLINE,
			NodeStateKind::Online => ONLINE,
			NodeStateKind::Error => ERROR,
			NodeStateKind::Invalid => INVALID,
			NodeStateKind::Disabled => DISABLED,
		}
	}
	pub fn get_all() -> &'static [NodeStateKind] {
		&[
			NodeStateKind::Offline,
			NodeStateKind::Online,
			NodeStateKind::Error,
			NodeStateKind::Invalid,
			NodeStateKind::Disabled,
		]
	}
}

impl NodeState {
	pub fn kind(&self) -> NodeStateKind {
		match &self {
			Self::Offline => NodeStateKind::Offline,
			Self::Online(_) => NodeStateKind::Online,
			Self::Error { .. } => NodeStateKind::Error,
			Self::Invalid { .. } => NodeStateKind::Invalid,
			Self::Disabled => NodeStateKind::Disabled,
		}
	}
	pub(crate) fn error(msg: impl fmt::Display) -> Self {
		NodeState::Error { msg: msg.to_string() }
	}
	pub(crate) fn invalid(msg: impl fmt::Display) -> Self {
		NodeState::Invalid { msg: msg.to_string() }
	}
}

impl fmt::Display for NodeState {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    match self {
			NodeState::Offline => f.write_str("offline"),
			NodeState::Online(i) => write!(f, "online: {}", i.id),
			NodeState::Error { msg } => write!(f, "error: {}", msg),
			NodeState::Invalid { msg } => write!(f, "invalid: {}", msg),
			NodeState::Disabled => f.write_str("disabled"),
		}
	}
}

#[derive(Debug)]
enum Ctrl {
	ActivateNode(Uri),
	DisableNode(Uri),
}

struct LightningManagerProcess {
	db: database::Db,
	rtmgr: RuntimeManager,
	waker: Arc<Notify>,

	ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,

	payment_update_tx: broadcast::Sender<PaymentHash>,

	/// Shared with [`LightningManager`]; rebuilt by [`Self::publish`] whenever
	/// node state changes so the manager's getters see fresh handles.
	node_handles: Arc<parking_lot::RwLock<Vec<NodeHandle>>>,

	network: bitcoin::Network,
	nodes: HashMap<Uri, ClnNodeInfo>,
	node_by_id: HashMap<LightningNodeId, Uri>,
	hold_config: ClnHoldConfig,
	xpay_config: ClnXpayConfig,
	sync_manager: Arc<SyncManager>,
	mailbox_manager: Arc<crate::mailbox_manager::MailboxManager>,
	settler: Arc<HtlcSettler>,
}

impl LightningManagerProcess {
	/// Rebuild the shared snapshot of command handles for the currently-online
	/// nodes. Called after every maintenance pass and state change so the
	/// manager's getters route to nodes that were online as of the last pass.
	fn publish(&self) {
		let handles = self.nodes.values().filter_map(|node| {
			let NodeState::Online(ref state) = node.state else { return None };
			Some(state.handle(node.config.priority))
		}).collect();
		*self.node_handles.write() = handles;
	}

	async fn check_nodes(&mut self) {
		for (uri, node) in self.nodes.iter_mut() {
			match node.state {
				NodeState::Online(ref mut rt) => {
					// check if the monitor is still running
					if !rt.monitor.as_ref().expect("online").is_running() {
						match rt.monitor.take().unwrap().wait().await {
							Ok(Err(e)) => {
								let new_state = NodeState::error(format!("{:?}", e));
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state)
							},
							Ok(Ok(())) => {
								error!("ClnHold for {uri} unexpectedly exited without error");
								let new_state = NodeState::Offline;
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state);
							},
							Err(e) => {
								if e.is_panic() {
									error!("ClnHold for {uri} thread paniced!");
								}
								let new_state = NodeState::error(e);
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state);
							},
						}
					// check if xpay is still running
					} else if !rt.xpay.as_ref().expect("online").is_running() {
						match rt.xpay.take().unwrap().wait().await {
							Ok(Err(e)) => {
								let new_state = NodeState::error(format!("{:?}", e));
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state)
							},
							Ok(Ok(())) => {
								error!("ClnXpay for {uri} unexpectedly exited without error");
								let new_state = NodeState::Offline;
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state);
							},
							Err(e) => {
								let msg = e.to_string();
								if let Ok(p) = e.try_into_panic() {
									error!("ClnXpay for {uri} thread paniced!: {:?}", p);
								}
								let new_state = NodeState::error(msg);
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state);
							},
						}
					}
				},
				NodeState::Offline | NodeState::Error { .. } => {
					trace!("Trying to connect to offline node at {}", uri);
					match node.try_connect(
						&self.db,
						self.network,
						&self.hold_config,
						&self.xpay_config,
						&self.payment_update_tx,
						&self.rtmgr,
						&self.waker,
						&self.sync_manager,
						&self.mailbox_manager,
						&self.settler,
					).await {
						Ok(id) => {
							info!("Successfully connected to CLN node at {}", uri);
							self.node_by_id.insert(id, node.uri.clone());
						},
						Err(e) => {
							trace!("Failed to connect to CLN node at {}: {:#}", uri, e);
							if let Ok(state) = e.downcast::<NodeState>() {
								telemetry::set_lightning_node_state(
									uri.clone(), None, None, state.kind(),
								);
								node.set_state(state);
							}
						}
					}
				},
				NodeState::Invalid { .. } | NodeState::Disabled => {}, // do nothing anymore
			}
		}

		// Republish the snapshot so the manager's getters see the latest set
		// of online nodes.
		self.publish();
	}

	async fn disable_node(&mut self, uri: &Uri) {
		let Some(node) = self.nodes.get_mut(uri) else {
			error!("Cannot disable node since URI {uri} cannot be found.");
			return;
		};

		let disable = match &node.state {
			NodeState::Online(_) => {
				info!("ClnNode {uri} was Online and is now disabled.");
				true
			}
			NodeState::Error { .. } => {
				info!("ClnNode {uri} was in Error and is now disabled.");
				true
			}
			NodeState::Offline => {
				info!("ClnNode {uri} was Offline and is now disabled.");
				true
			}
			NodeState::Disabled => {
				info!("ClnNode {uri} is already disabled.");
				false
			}
			NodeState::Invalid { .. } => {
				info!("ClnNode {uri} is invalid.");
				false
			}
		};

		if disable {
			let new_state = NodeState::Disabled;
			telemetry::set_lightning_node_state(
				uri.clone(), None, None, new_state.kind(),
			);
			node.set_state(new_state);
			// Drop the node from the snapshot so getters stop routing to it.
			self.publish();
		}
	}

	async fn enable_node(&mut self, uri: &Uri) {
		let Some(node) = self.nodes.get_mut(uri) else {
			error!("Cannot enable node since URI {uri} cannot be found.");
			return;
		};

		let enable = match &node.state {
			NodeState::Online(_) => {
				info!("ClnNode with {uri} is already Online (not disabled).");
				false
			},
			NodeState::Error { .. } => {
				info!("ClnNode with {uri} is in state Error (not disabled).");
				false
			},
			NodeState::Offline => {
				info!("ClnNode with {uri} is in state Offline (not disabled).");
				false
			},
			NodeState::Disabled => {
				info!("ClnNode with {uri} was disabled and is now enabled.");
				true
			},
			NodeState::Invalid { .. } => {
				info!("ClnNode with {uri} is invalid.");
				false
			},
		};

		if enable {
			// NB: mark Offline (not Disabled) so check_nodes reconnects the
			// node, and nudge the supervisor so it happens on the next loop
			// iteration rather than waiting for the reconnect interval.
			let new_state = NodeState::Offline;
			telemetry::set_lightning_node_state(
				uri.clone(), None, None, new_state.kind(),
			);
			node.set_state(new_state);
			self.waker.notify_one();
		}
	}

	async fn run(mut self, reconnect_interval: Duration) {
		let _worker = self.rtmgr.spawn_critical("LightningManager");

		let mut interval = tokio::time::interval(reconnect_interval);

		loop {
			tokio::select!{
				_ = self.rtmgr.shutdown_signal() => {
					info!("Run CLN integration received shutdown signal. Exiting.");
					break;
				},

				_ = self.waker.notified() => {
					trace!("LightningManagerProcess woken up by child");
					self.check_nodes().await;
				},
				_ = interval.tick() => {
					trace!("LightningManagerProcess checking nodes on interval");
					self.check_nodes().await;
				},

				msg = self.ctrl_rx.recv() => if let Some(msg) = msg {
					 match msg {
						Ctrl::ActivateNode(uri) => {
							self.enable_node(&uri).await;
						},
						Ctrl::DisableNode(uri) => {
							self.disable_node(&uri).await;
						},
					}
				} else {
					warn!("control channel closed, shutting down LightningManager");
					break;
				},
			};
		}
	}
}
