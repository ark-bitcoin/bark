
use std::str::FromStr;
use std::{cmp, fmt ,str};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin_ext::BlockHeight;
use chrono::{DateTime, Local};
use cln_rpc::plugins::hold::{self, InvoiceState};
use cln_rpc::ClnGrpcClient;
use futures::Stream;
use lightning_invoice::Bolt11Invoice;
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tracing::{debug, error, info, trace, warn};
use ark::lightning::PaymentHash;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::listsendpays_request::ListsendpaysIndex;
use cln_rpc::node_client::NodeClient;
use cln_rpc::plugins::hold::hold_client::HoldClient;
use crate::database;
use crate::database::ln::{ClnNodeId, LightningHtlcSubscription, LightningHtlcSubscriptionStatus, LightningPaymentStatus};
use crate::system::RuntimeManager;
use crate::telemetry;

#[derive(Debug, Clone)]
pub struct ClnNodeMonitorConfig {
	pub invoice_check_interval: Duration,
	pub invoice_recheck_delay: Duration,
	pub invoice_expiry: Duration,
	pub receive_htlc_forward_timeout: Duration,
	pub check_base_delay: Duration,
	pub check_max_delay: Duration,
	/// Base delay for TrackAll reconnection backoff (e.g., 1 second)
	pub track_all_base_delay: Duration,
	/// Maximum delay for TrackAll reconnection backoff (e.g., 60 seconds)
	pub track_all_max_delay: Duration,
}

pub struct ClnNodeMonitor {
	ctrl_tx: mpsc::Sender<Ctrl>,
	jh: JoinHandle<anyhow::Result<()>>,
}

impl ClnNodeMonitor {
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: ClnNodeId,
		node_rpc: ClnGrpcClient,
		hold_rpc: Option<HoldClient<Channel>>,
		config: ClnNodeMonitorConfig,
	) -> anyhow::Result<ClnNodeMonitor> {
		let payment_idxs = db.get_lightning_payment_indexes(node_id).await
			.with_context(|| format!("failed to fetch payment indices for {}", node_id))?
			.unwrap_or_default();

		info!("Start managing payments for node with id {} with created_index={}, updated_index={}",
			node_id, payment_idxs.created_index, payment_idxs.updated_index,
		);

		let (ctrl_tx, ctrl_rx) = mpsc::channel(4);
		let proc = ClnNodeMonitorProcess {
			config, db, payment_update_tx, ctrl_rx, node_id,
			rpc: node_rpc,
			hold_rpc,
			created_index: match payment_idxs.created_index {
				0 => None,
				i => Some(i),
			},
			updated_index: match payment_idxs.updated_index {
				0 => None,
				i => Some(i),
			},
			invoice_next_check_at: HashMap::new(),
		};

		let jh = tokio::spawn(async {
			let ret = proc.run(rtmgr, mgr_waker).await;
			if let Err(ref e) = ret {
				error!("ClnNodeMonitor exited with error: {:?}", e);
			}
			ret
		});

		Ok(ClnNodeMonitor { ctrl_tx, jh })
	}

	pub fn is_running(&self) -> bool {
		!self.jh.is_finished()
	}

	/// Wait for the process to end.
	///
	/// Note that if [ClnNodeMonitor::stop] is not called,
	/// it won't stop until an error occurs.
	pub async fn wait(self) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
		Ok(self.jh.await?)
	}

	/// Stop the monitor process and wait for it to end.
	#[allow(unused)]
	pub async fn stop(self) -> anyhow::Result<()> {
		self.ctrl_tx.send(Ctrl::Stop).await?;
		self.wait().await?
	}
}

impl fmt::Debug for ClnNodeMonitor {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    f.write_str("ClnNodeMonitor")
	}
}

enum Ctrl {
	Stop,
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

struct ClnNodeMonitorProcess {
	config: ClnNodeMonitorConfig,
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,
	ctrl_rx: mpsc::Receiver<Ctrl>,

	node_id: ClnNodeId,

	rpc: NodeClient<Channel>,
	hold_rpc: Option<HoldClient<Channel>>,

	/// last seen sendpay created index, or 0 for none seen
	created_index: Option<u64>,
	/// last seen sendpay updated index, or 0 for none seen
	updated_index: Option<u64>,

	/// Map from invoice id to number of attempts and time of last update.
	invoice_next_check_at: HashMap<i64, (usize, DateTime<Local>)>,
}

impl ClnNodeMonitorProcess {
	async fn process_sendpay(&mut self, kind: ListsendpaysIndex)-> anyhow::Result<()> {
		let start_index = match kind {
			ListsendpaysIndex::Created => self.created_index.map(|i| i + 1).unwrap_or(0),
			ListsendpaysIndex::Updated => self.updated_index.map(|i| i + 1).unwrap_or(0),
		};

		trace!("Querying lightning payment ({}) with start index {} for node {}",
			kind.as_str_name(), start_index, self.node_id,
		);
		let updates = self.rpc.list_pays(cln_rpc::ListpaysRequest {
			bolt11: None,
			payment_hash: None,
			status: None,
			index: Some(kind as i32),
			start: Some(start_index),
			limit: None
		}).await?.into_inner();

		let mut max_index = start_index;
		for update in updates.pays {
			let updated_index = update.updated_index();
			max_index = cmp::max(max_index, updated_index);

			let payment_hash = PaymentHash::try_from(update.payment_hash.clone())
				.expect("payment hash must be 32 bytes");

			let attempt = match self.db.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await? {
				Some(r) => r,
				None => continue, // NB this is unrelated traffic on cln node
			};

			match update.status() {
				ListpaysPaysStatus::Pending => {
					if attempt.status == LightningPaymentStatus::Requested {
						debug!("Lightning payment's first update received from CLN since \
							requesting for payment hash {}.", payment_hash,
						);

						let status = LightningPaymentStatus::Submitted;
						let ok = self.db.verify_and_update_invoice(
							&payment_hash, &attempt, status, None, None, None,
						).await?;
						if ok {
							self.payment_update_tx.send(payment_hash)?;
						}
					}
				}
				ListpaysPaysStatus::Failed => {
					debug!("Lightning payment failed for payment hash {}.", payment_hash);

					let error_string = update.erroronion.as_ref().map(|b| {
						str::from_utf8(b).unwrap_or_else(|e| {
							warn!("Failed to decode erroronion from cln: '{}', {}", b.as_hex(), e);
							"failed to decode erroronion field"
						})
					});

					let status = LightningPaymentStatus::Failed;
					let ok = self.db.verify_and_update_invoice(
						&payment_hash, &attempt, status, error_string,  None, None,
					).await?;
					if ok {
						self.payment_update_tx.send(payment_hash)?;
					}
				}
				ListpaysPaysStatus::Complete => {
					debug!("Lightning payment succeeded for payment hash {}.", payment_hash);

					let final_msat = update.amount_sent_msat
						.context("should have amount send on complete pay")?.msat;
					let preimage = update.preimage
						.context("should have preimage send on complete pay")?
						.try_into().ok().context("invalid preimage not 32 bytes")?;

					let status = LightningPaymentStatus::Succeeded;
					let ok = self.db.verify_and_update_invoice(
						&payment_hash, &attempt, status, None, Some(final_msat), Some(preimage),
					).await?;
					if ok {
						self.payment_update_tx.send(payment_hash)?;
					}
				}
			}
		}

		if max_index > start_index {
			trace!("Processing lightning payment done ({}) new start index {} for node {}",
				kind.as_str_name(), max_index, self.node_id,
			);
			self.db.store_lightning_payment_index(self.node_id, kind, max_index).await?;
		}
		match kind {
			ListsendpaysIndex::Created => self.created_index = Some(max_index),
			ListsendpaysIndex::Updated => self.updated_index = Some(max_index),
		}

		Ok(())
	}

	fn update_next_invoice_check(&mut self, invoice_id: i64) {
		let (attempts, next_check) = self.invoice_next_check_at.entry(invoice_id)
			.or_insert((0, Local::now()));
		*attempts += 1;

		// Calculate delay: grows with each attempt
		// e.g. base 10 seconds, doubling each time, capped to a max delay
		let base_delay_secs = self.config.check_base_delay.as_secs();
		let max_delay_secs = self.config.check_max_delay.as_secs();
		let delay_secs = (base_delay_secs * 2u64.pow(*attempts as u32 - 1)).min(max_delay_secs);

		*next_check = Local::now() + Duration::from_secs(delay_secs);

		trace!("Lightning invoice ({}): Check {} done, updated next check to {}.",
			invoice_id, attempts, next_check,
		);
	}

	async fn process_payment_attempts(&mut self) -> anyhow::Result<()> {
		let open_attempts = self.db.get_open_lightning_payment_attempts(self.node_id).await?;

		for attempt in open_attempts {
			if attempt.is_self_payment {
				trace!("Lightning invoice ({}): Skipping since it is a self payment.",
					attempt.lightning_invoice_id,
				);

				continue;
			}

			if attempt.created_at > Local::now() - self.config.invoice_recheck_delay {
				trace!("Lightning invoice ({}): Skipping since it was just created.",
					attempt.lightning_invoice_id,
				);

				continue;
			}

			let next_check = self.invoice_next_check_at.get(&attempt.lightning_invoice_id);
			if next_check.is_some() && next_check.unwrap().1 > Local::now() {
				trace!("Lightning invoice ({}): Skipping since it was checked recently.",
					attempt.lightning_invoice_id,
				);

				continue;
			}

			let invoice = self.db.get_lightning_invoice_by_id(attempt.lightning_invoice_id).await?;
			debug!("Lightning invoice ({}): with payment hash {} is being verified.",
				invoice.id, invoice.payment_hash,
			);

			let mut updated = false;

			telemetry::add_invoice_verification(attempt.lightning_node_id, attempt.status);

			let req = cln_rpc::ListpaysRequest {
				bolt11: None,
				payment_hash: Some(invoice.payment_hash.to_vec()),
				status: None,
				index: None,
				limit: None,
				start: None,
			};
			let listpays_response = self.rpc.list_pays(req).await
				.context("Could not fetch cln payments")?
				.into_inner();
			if listpays_response.pays.is_empty() {
				match attempt.status {
					LightningPaymentStatus::Succeeded => {
						error!("Lightning invoice ({}): Payment attempt flagged succeeded \
							when it cannot be found in CLN for payment hash {}",
							invoice.id, invoice.payment_hash,
						);
					},
					LightningPaymentStatus::Failed => {
						error!("Lightning invoice ({}): Payment attempt flagged failed \
							when it cannot be found in CLN for payment hash {}",
							invoice.id, invoice.payment_hash,
						)
					},
					LightningPaymentStatus::Requested
						| LightningPaymentStatus::Submitted =>
					{
						self.db.update_lightning_payment_attempt_status(
							&attempt,
							LightningPaymentStatus::Failed,
							None,
						).await?;

						telemetry::add_lightning_payment(
							attempt.lightning_node_id,
							attempt.amount_msat,
							LightningPaymentStatus::Failed,
						);

						updated = true;
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
							error!("Lightning invoice ({}): Payment completed but no preimage \
								specified for payment hash {}",
								invoice.id, invoice.payment_hash,
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
						error!("Lightning invoice ({}): payment attempt flagged {} when it \
							actually {} for payment hash {}",
							invoice.id, attempt.status, desired_status,
							invoice.payment_hash,
						);
					} else {
						let preimage = latest.preimage.map(|b| b.try_into().expect("invalid preimage not 32 bytes"));

						updated = self.db.verify_and_update_invoice(
							&invoice.payment_hash,
							&attempt,
							desired_status,
							error_string,
							None,
							preimage,
						).await?;
					}
				}
			}

			if updated {
				trace!("Lightning invoice ({}): status updated for payment hash {}.",
					invoice.id, invoice.payment_hash,
				);

				self.payment_update_tx.send(invoice.payment_hash)?;
			}

			self.update_next_invoice_check(invoice.id);
		}

		self.invoice_next_check_at.retain(|_, &mut (_, datetime)| datetime > Local::now());

		telemetry::set_pending_invoice_verifications(
			self.node_id,
			self.invoice_next_check_at.len(),
		);

		Ok(())
	}

	/// For each subscription, verifies if incoming HTLCs have been accepted.
	/// - If so, it updates the status to accepted.
	/// - After a delay, it cancels the subscription on the plugin and updates
	/// the status to canceled.
	async fn process_htlc_subscriptions(&mut self) -> anyhow::Result<()> {
		self.check_htlc_subscription_timeouts().await?;
		self.poll_htlc_state_updates().await?;
		Ok(())
	}

	/// Checks all open subscriptions for timeouts and expired invoices.
	/// Called on timer regardless of whether TrackAll is enabled.
	async fn check_htlc_subscription_timeouts(&mut self) -> anyhow::Result<()> {
		let mut hold_client = match &self.hold_rpc {
			Some(client) => client.clone(),
			None => {
				warn!("No hold rpc client, skipping htlc subscription timeout checks");
				return Ok(());
			},
		};

		let htlc_subscriptions = self.db.get_open_lightning_htlc_subscriptions(
			self.node_id,
		).await?;

		for htlc_subscription in htlc_subscriptions {
			let payment_hash = htlc_subscription.invoice.payment_hash();

			// Check for HTLC timeout: subscription held too long in Accepted state.
			// We use our `accepted_at` timestamp rather than the hold plugin's HTLC
			// `created_at` for accuracy.
			if htlc_subscription.status == LightningHtlcSubscriptionStatus::Accepted {
				// TODO(dunxen): Simply `.expect` and remove this `unwrap_or` at some stage.
				// The `.unwrap_or` is here for backwards compatibility for existing servers that may
				// have exsisting subscriptions in an `Accepted` state but without an `accepted_at` field
				// after restart.
				let accepted_at = htlc_subscription.accepted_at.unwrap_or(htlc_subscription.updated_at);
				if accepted_at < Local::now() - self.config.receive_htlc_forward_timeout {
					// Check if the hold invoice is still active (not an intra-ark payment)
					let req = hold::ListRequest {
						constraint: Some(hold::list_request::Constraint::PaymentHash(
							payment_hash.to_byte_array().to_vec(),
						)),
					};
					let res = hold_client.list(req).await?.into_inner();
					let has_accepted_invoice = res.invoices.iter().any(|i| i.state == InvoiceState::Accepted as i32);

					if has_accepted_invoice {
						self.cancel_invoice_and_htlc_subscription(
							&mut hold_client,
							payment_hash,
							&htlc_subscription,
							"htlc vtxo setup timed out",
						).await?;
					} else {
						// For intra-ark payments, the hold invoice is canceled after we set
						// the subscription to Accepted, so there won't be an accepted invoice
						// in the hold plugin.
						self.cancel_htlc_subscription(&htlc_subscription, "htlc vtxo setup timed out").await?;
					}
					continue;
				}
			}

			// Cancel invoice & subscription if invoice expired
			if htlc_subscription.invoice.is_expired() {
				self.cancel_invoice_and_htlc_subscription(
					&mut hold_client,
					payment_hash,
					&htlc_subscription,
					"invoice expired",
				).await?;
			}
		}

		Ok(())
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
			Some(Some(lowest_incoming_htlc_expiry)) => lowest_incoming_htlc_expiry as BlockHeight,
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
		let tip = self.rpc.getinfo(cln_rpc::GetinfoRequest {}).await?
			.into_inner().blockheight;

		// NB: We subtract 1 to give some buffer for the lightning payment to be sent.
		let required_min_htlc_expiry = tip + invoice.min_final_cltv_expiry_delta() as BlockHeight - 1;

		if lowest_incoming_htlc_expiry >= required_min_htlc_expiry {
			debug!("Lightning htlc subscription ({}) was accepted.", htlc_subscription.id);

			self.db.store_lightning_htlc_subscription_status(
				htlc_subscription.id,
				LightningHtlcSubscriptionStatus::Accepted,
				Some(lowest_incoming_htlc_expiry),
			).await?;

			Ok(true)
		} else {
			debug!("Incoming HTLC expiry height ({}) for subscription doesn't fit. required {}, actual {}",
				htlc_subscription.id, required_min_htlc_expiry, lowest_incoming_htlc_expiry
			);

			self.db.store_lightning_htlc_subscription_status(
				htlc_subscription.id,
				LightningHtlcSubscriptionStatus::Canceled,
				None,
			).await?;

			Ok(false)
		}
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

		let htlc_subscriptions = self.db.get_open_lightning_htlc_subscriptions(
			self.node_id,
		).await?;

		let status_counts = htlc_subscriptions.iter()
			.fold(HashMap::new(), |mut acc, sub| {
				*acc.entry(sub.status).or_insert(0) += 1;
				acc
			});
		telemetry::set_open_invoices(self.node_id, &status_counts);

		for htlc_subscription in htlc_subscriptions {
			// Only poll for subscriptions that haven't been accepted yet
			if htlc_subscription.status != LightningHtlcSubscriptionStatus::Created {
				continue;
			}

			let payment_hash = htlc_subscription.invoice.payment_hash();

			debug!("Lightning htlc subscription ({}) is being verified.",
				htlc_subscription.id,
			);

			let req = hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(
					payment_hash.to_byte_array().to_vec(),
				)),
			};
			let res = hold_client.list(req).await?.into_inner();

			let is_accepted = res.invoices.iter().any(|i| i.state == InvoiceState::Accepted as i32);

			if is_accepted {
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
		let max = self.config.track_all_max_delay.as_secs();
		// Cap exponent at 6 to prevent overflow (2^6 = 64)
		Duration::from_secs((base * 2u64.pow(attempt.min(6))).min(max))
	}

	/// Handle a TrackAll stream event - process invoice acceptance.
	async fn handle_track_all_event(&mut self, response: hold::TrackAllResponse) -> anyhow::Result<()> {
		let payment_hash = sha256::Hash::from_slice(&response.payment_hash)?;
		let state = hold::InvoiceState::try_from(response.state).ok();

		if state == Some(hold::InvoiceState::Accepted) {
			if let Some(sub) = self.db
				.get_open_htlc_subscription_for_node_by_payment_hash(
					self.node_id,
					&PaymentHash::from(payment_hash),
				).await?
			{
				self.handle_invoice_accepted(&sub).await?;
			}
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

		self.cancel_htlc_subscription(htlc_subscription, reason).await?;

		Ok(())
	}

	/// Cancel a subscription without canceling the hold invoice.
	///
	/// This is used for intra-ark payments where the hold invoice was already
	/// canceled when the subscription was set to Accepted.
	async fn cancel_htlc_subscription(
		&self,
		htlc_subscription: &LightningHtlcSubscription,
		reason: &str,
	) -> anyhow::Result<()> {
		debug!("Lightning htlc subscription ({}) canceled: {}.",
			htlc_subscription.id, reason,
		);

		self.db.store_lightning_htlc_subscription_status(
			htlc_subscription.id,
			LightningHtlcSubscriptionStatus::Canceled,
			None,
		).await?;

		let payment_hash = PaymentHash::from(&htlc_subscription.invoice);
		let payment_attempt = self.db
			.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await?;
		if let Some(payment_attempt) = payment_attempt {
			debug!("HTLC subscription canceled with ongoing payment attempt, \
				marking as failed: {}", payment_attempt.id,
			);
			self.db.update_lightning_payment_attempt_status(
				&payment_attempt,
				LightningPaymentStatus::Failed,
				Some(reason),
			).await?;

			// NB: For intra-ark lightning payments, we need to notify the subscriber
			// that the payment has failed, otherwise it will wait until next timeout
			// to get the confirmation, since no notification will ever come from CLN hook.
			if let Err(e) = self.payment_update_tx.send(payment_hash) {
				debug!("Failed to send payment update notification: {}", e);
			}
		}

		Ok(())
	}

	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnNodeMonitor({})", self.node_id))
			.with_notify(mgr_waker);

		let mut invoice_interval = tokio::time::interval(self.config.invoice_check_interval);
		let (mut rpc1, mut rpc2) = (self.rpc.clone(), self.rpc.clone()); // circumvent &mut

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
			let created_request = rpc1.wait(cln_rpc::WaitRequest {
				subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
				indexname: cln_rpc::wait_request::WaitIndexname::Created as i32,
				nextvalue: self.created_index.map(|i| i + 1).unwrap_or(0),
			});
			tokio::pin!(created_request);
			let updated_request = rpc2.wait(cln_rpc::WaitRequest {
				subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
				indexname: cln_rpc::wait_request::WaitIndexname::Updated as i32,
				nextvalue: self.updated_index.map(|i| i + 1).unwrap_or(0),
			});
			tokio::pin!(updated_request);

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

			// whether our invoice_interval should handle subscriptions or only timeouts
			let interval_handle_subscriptions = match track_all_state {
				TrackAllStreamState::Connected(_) => false,
				TrackAllStreamState::Backoff { .. } => false,
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
					ctrl = self.ctrl_rx.recv() => match ctrl {
						None | Some(Ctrl::Stop) => return Ok(()),
					},
					_ = &mut created_request => {
						self.process_sendpay(ListsendpaysIndex::Created).await
							.context("error processing created events")?;
						continue 'requests;
					},
					_ = &mut updated_request => {
						self.process_sendpay(ListsendpaysIndex::Updated).await
							.context("error processing updated events")?;
						continue 'requests;
					},
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
						self.process_payment_attempts().await?;
						if interval_handle_subscriptions {
							self.process_htlc_subscriptions().await?;
						} else {
							self.check_htlc_subscription_timeouts().await?;
						}
					},
				}
			}
		}
	}
}
