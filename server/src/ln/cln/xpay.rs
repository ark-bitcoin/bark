
use std::{cmp, fmt, str};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use bitcoin_ext::{AmountExt, BlockDelta};
use chrono::{DateTime, Local};
use tokio::sync::{broadcast, Notify};
use tokio::task::JoinHandle;
use tonic::transport::Channel;
use tracing::{debug, error, info, trace, warn};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::listsendpays_request::ListsendpaysIndex;
use cln_rpc::node_client::NodeClient;

use crate::database;
use crate::database::ln::{ClnNodeId, LightningPaymentStatus};
use crate::system::RuntimeManager;
use crate::telemetry;
use super::ClnGrpcClient;

#[derive(Debug, Clone)]
pub struct ClnXpayConfig {
	pub invoice_check_interval: Duration,
	pub invoice_recheck_delay: Duration,
	pub check_base_delay: Duration,
	pub max_check_delay: Duration,
}

/// Handle for the xpay monitor process.
///
/// Tracks outbound payment status via CLN's listsendpays streams
/// and periodically verifies open payment attempts.
pub struct ClnXpay {
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,
	rpc: ClnGrpcClient,
	jh: JoinHandle<anyhow::Result<()>>,
}

impl ClnXpay {
	pub async fn start(
		rtmgr: RuntimeManager,
		mgr_waker: Arc<Notify>,
		db: database::Db,
		payment_update_tx: broadcast::Sender<PaymentHash>,
		node_id: ClnNodeId,
		rpc: ClnGrpcClient,
		config: ClnXpayConfig,
	) -> anyhow::Result<ClnXpay> {
		let payment_idxs = db.get_lightning_payment_indexes(node_id).await
			.with_context(|| format!("failed to fetch payment indices for {}", node_id))?
			.unwrap_or_default();

		info!("Start managing xpay for node with id {} with created_index={}, updated_index={}",
			node_id, payment_idxs.created_index, payment_idxs.updated_index,
		);

		let proc = ClnXpayProcess {
			config,
			db: db.clone(),
			payment_update_tx: payment_update_tx.clone(),
			node_id,
			rpc: rpc.clone(),
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
				error!("ClnXpay exited with error: {:?}", e);
			}
			ret
		});

		Ok(ClnXpay { db, payment_update_tx, rpc, jh })
	}

	pub fn is_running(&self) -> bool {
		!self.jh.is_finished()
	}

	/// Wait for the process to end.
	pub async fn wait(self) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
		Ok(self.jh.await?)
	}

	/// Fire-and-forget: spawn a task that calls xpay and updates the DB.
	pub fn pay(
		&self,
		invoice: Box<Invoice>,
		user_amount: Option<Amount>,
		max_cltv_expiry_delta: BlockDelta,
	) {
		tokio::spawn(handle_pay_invoice(
			self.db.clone(),
			self.payment_update_tx.clone(),
			self.rpc.clone(),
			invoice,
			user_amount,
			max_cltv_expiry_delta,
		));
	}
}

impl fmt::Debug for ClnXpay {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ClnXpay")
	}
}

struct ClnXpayProcess {
	config: ClnXpayConfig,
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,

	node_id: ClnNodeId,
	rpc: NodeClient<Channel>,

	/// last seen sendpay created index, or 0 for none seen
	created_index: Option<u64>,
	/// last seen sendpay updated index, or 0 for none seen
	updated_index: Option<u64>,

	/// Map from invoice id to number of attempts and time of last update.
	invoice_next_check_at: HashMap<i64, (usize, DateTime<Local>)>,
}

impl ClnXpayProcess {
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

			let attempt = match self.db.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await? {
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
							payment_hash, &attempt, status, None, None, None,
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
						payment_hash, &attempt, status, error_string,  None, None,
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
						payment_hash, &attempt, status, None, Some(final_msat), Some(preimage),
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
		let max_delay_secs = self.config.max_check_delay.as_secs();
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
							invoice.payment_hash,
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

	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnXpay({})", self.node_id))
			.with_notify(mgr_waker);

		let mut check_interval = tokio::time::interval(self.config.invoice_check_interval);
		let (mut rpc1, mut rpc2) = (self.rpc.clone(), self.rpc.clone());

		loop {
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

			tokio::select! {
				_ = rtmgr.shutdown_signal() => return Ok(()),
				_ = &mut created_request => {
					self.process_sendpay(ListsendpaysIndex::Created).await
						.context("error processing created events")?;
				},
				_ = &mut updated_request => {
					self.process_sendpay(ListsendpaysIndex::Updated).await
						.context("error processing updated events")?;
				},
				_ = check_interval.tick() => {
					self.process_payment_attempts().await?;
				},
			}
		}
	}
}

/// Handles calling the pay cln endpoint and processing the response.
async fn handle_pay_invoice(
	db: database::Db,
	payment_update_tx: broadcast::Sender<PaymentHash>,
	mut rpc: ClnGrpcClient,
	invoice: Box<Invoice>,
	amount: Option<Amount>,
	max_cltv_expiry_delta: BlockDelta,
) {
	let payment_hash = invoice.payment_hash();
	match call_xpay(&mut rpc, &invoice, amount, max_cltv_expiry_delta).await {
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
			match db.get_open_lightning_payment_attempt_by_payment_hash(payment_hash).await {
				Ok(Some(attempt)) => match db.verify_and_update_invoice(
					payment_hash,
					&attempt,
					LightningPaymentStatus::Submitted,
					Some(&format!("pay rpc call error: {}", pay_err)),
					None,
					None,
				).await {
					Ok(_) => {},
					Err(e) => error!("Error updating invoice after pay error: {e:#}"),
				}
				Ok(None) => error!("Failed to find attempt for invoice just started \
					payment_hash={payment_hash}"),
				Err(e) => error!("Error querying attempt for invoice just started \
					payment_hash={payment_hash}: {e:#}"),
			}
			let _ = payment_update_tx.send(payment_hash);
		},
	}
}

/// Calls the xpay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
async fn call_xpay(
	rpc: &mut ClnGrpcClient,
	invoice: &Invoice,
	user_amount: Option<Amount>,
	max_cltv_expiry_delta: BlockDelta,
) -> anyhow::Result<Preimage> {
	match (user_amount, invoice.amount_msat()) {
		(Some(user), Some(inv)) => {
			let inv = Amount::from_msat_ceil(inv);
			if user != inv {
				bail!("invoice amount {inv} and given amount {user} don't match");
			}
		},
		(None, None) => {
			bail!("Amount not encoded in invoice nor provided by user. Please provide amount");
		},
		_ => {},
	}

	// Call the xpay command
	let pay_response = rpc.xpay(cln_rpc::XpayRequest {
		invstring: invoice.to_string(),
		amount_msat: {
			if invoice.amount_msat().is_none() {
				Some(user_amount.unwrap().into())
			} else {
				None
			}
		},
		maxdelay: Some(max_cltv_expiry_delta as u32),
		maxfee: None,
		retry_for: None,
		partial_msat: None,
		layers: vec![],
	}).await?.into_inner();

	if pay_response.payment_preimage.len() > 0 {
		Ok(pay_response.payment_preimage.try_into().ok().context("invalid preimage not 32 bytes")?)
	} else {
		bail!("xpay returned invalid preimage: {}", pay_response.payment_preimage.as_hex());
	}
}
