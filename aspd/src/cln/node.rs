
use std::{cmp, fmt ,str};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use chrono::{DateTime, Utc};
use cln_rpc::ClnGrpcClient;
use log::{debug, error, info, trace, warn};
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinHandle;
use tonic::transport::Channel;

use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::listsendpays_request::ListsendpaysIndex;
use cln_rpc::node_client::NodeClient;

use crate::database::{self, ClnNodeId};
use crate::database::model::LightningPaymentStatus;
use crate::system::RuntimeManager;
use crate::telemetry::TelemetryMetrics;

#[derive(Debug, Clone)]
pub struct ClnNodeMonitorConfig {
	pub invoice_check_interval: Duration,
	pub invoice_recheck_delay: Duration,
	pub check_base_delay: Duration,
	pub check_max_delay: Duration,
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
		payment_update_tx: broadcast::Sender<sha256::Hash>,
		node_id: ClnNodeId,
		node_rpc: ClnGrpcClient,
		config: ClnNodeMonitorConfig,
		telemetry_metrics: TelemetryMetrics,
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
			created_index: match payment_idxs.created_index {
				0 => None,
				i => Some(i),
			},
			updated_index: match payment_idxs.updated_index {
				0 => None,
				i => Some(i),
			},
			invoice_next_check_at: HashMap::new(),
			telemetry_metrics,
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
	/// Note that if [stop] is not called, it won't stop until an error occurs.
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

struct ClnNodeMonitorProcess {
	config: ClnNodeMonitorConfig,
	db: database::Db,
	payment_update_tx: broadcast::Sender<sha256::Hash>,
	ctrl_rx: mpsc::Receiver<Ctrl>,

	node_id: ClnNodeId,
	rpc: NodeClient<Channel>,

	/// last seen sendpay created index, or 0 for none seen
	created_index: Option<u64>,
	/// last seen sendpay updated index, or 0 for none seen
	updated_index: Option<u64>,

	/// Map from invoice id to number of attempts and time of last update.
	invoice_next_check_at: HashMap<i64, (usize, DateTime<Utc>)>,
	telemetry_metrics: TelemetryMetrics,
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

			let payment_hash = sha256::Hash::from_slice(&update.payment_hash)
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
							self.telemetry_metrics.clone(),
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
						self.telemetry_metrics.clone(),
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
						&payment_hash, &attempt, status, None, Some(final_msat), Some(&preimage),
						self.telemetry_metrics.clone(),
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
			.or_insert((0, Utc::now()));
		*attempts += 1;

		// Calculate delay: grows with each attempt
		// e.g. base 10 seconds, doubling each time, capped to a max delay
		let base_delay_secs = self.config.check_base_delay.as_secs();
		let max_delay_secs = self.config.check_max_delay.as_secs();
		let delay_secs = (base_delay_secs * 2u64.pow(*attempts as u32 - 1)).min(max_delay_secs);

		*next_check = Utc::now() + Duration::from_secs(delay_secs);

		trace!("Lightning invoice ({}): Check {} done, updated next check to {}.",
			invoice_id, attempts, next_check,
		);
	}

	async fn process_invoices(&mut self) -> anyhow::Result<()> {
		let open_attempts = self.db.get_open_lightning_payment_attempts(
			self.node_id,
		).await?;

		for attempt in open_attempts.into_iter() {
			if attempt.created_at > Utc::now() - self.config.invoice_recheck_delay {
				trace!("Lightning invoice ({}): Skipping since it was just created.",
					attempt.lightning_invoice_id,
				);

				continue;
			}

			let next_check = self.invoice_next_check_at.get(&attempt.lightning_invoice_id);
			if next_check.is_some() && next_check.unwrap().1 > Utc::now() {
				trace!("Lightning invoice ({}): Skipping since it was checked recently.",
					attempt.lightning_invoice_id,
				);

				continue;
			}

			let invoice = self.db.get_lightning_invoice_by_id(attempt.lightning_invoice_id).await?;
			debug!("Lightning invoice ({}): with payment hash {} is being verified.",
				invoice.lightning_invoice_id, invoice.payment_hash,
			);

			let mut updated = false;

			self.telemetry_metrics.add_invoice_verification(attempt.lightning_node_id, attempt.status);

			let req = cln_rpc::ListpaysRequest {
				bolt11: None,
				payment_hash: Some(invoice.payment_hash[..].to_vec()),
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
							invoice.lightning_invoice_id, invoice.payment_hash,
						);
					},
					LightningPaymentStatus::Failed => {
						error!("Lightning invoice ({}): Payment attempt flagged failed \
							when it cannot be found in CLN for payment hash {}",
							invoice.lightning_invoice_id, invoice.payment_hash,
						)
					},
					LightningPaymentStatus::Requested
						| LightningPaymentStatus::Submitted =>
					{
						self.db.store_lightning_payment_attempt_status(
							attempt.lightning_payment_attempt_id,
							LightningPaymentStatus::Failed,
							None,
							attempt.updated_at,
						).await?;

						self.telemetry_metrics.add_lightning_payment(
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
								invoice.lightning_invoice_id, invoice.payment_hash,
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
							invoice.lightning_invoice_id, attempt.status, desired_status,
							invoice.payment_hash,
						);
					} else {
						let preimage = latest.preimage.map(|b| b.try_into().expect("invalid preimage not 32 bytes"));
						self.db.verify_and_update_invoice(
							&invoice.payment_hash,
							&attempt,
							desired_status,
							error_string,
							None,
							preimage.as_ref(),
							self.telemetry_metrics.clone(),
						).await?;

						updated = true;
					}
				}
			}

			if updated {
				trace!("Lightning invoice ({}): status updated for payment hash {}.",
					invoice.lightning_invoice_id, invoice.payment_hash,
				);

				self.payment_update_tx.send(invoice.payment_hash)?;
			}

			self.update_next_invoice_check(invoice.lightning_invoice_id);
		}

		self.invoice_next_check_at.retain(|_, &mut (_, datetime)| datetime > Utc::now());

		self.telemetry_metrics.set_pending_invoice_verifications(
			self.node_id,
			self.invoice_next_check_at.len(),
		);

		Ok(())
	}

	async fn run(mut self, rtmgr: RuntimeManager, mgr_waker: Arc<Notify>) -> anyhow::Result<()> {
		let _worker = rtmgr.spawn(format!("ClnNodeMonitor({})", self.node_id))
			.with_notify(mgr_waker);

		let mut invoice_interval = tokio::time::interval(self.config.invoice_check_interval);
		let (mut rpc1, mut rpc2) = (self.rpc.clone(), self.rpc.clone()); // circumvent &mut

		// we have two nested loops so that we can keep the gRPC requests
		// alive while we receive messages over other channels
		'requests: loop {
			let created_request = rpc1.wait(cln_rpc::WaitRequest {
				subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
				indexname: cln_rpc::wait_request::WaitIndexname::Created as i32,
				nextvalue: self.created_index.map(|i| i + 1).unwrap_or(0),
			});
			let updated_request = rpc2.wait(cln_rpc::WaitRequest {
				subsystem: cln_rpc::wait_request::WaitSubsystem::Sendpays as i32,
				indexname: cln_rpc::wait_request::WaitIndexname::Updated as i32,
				nextvalue: self.updated_index.map(|i| i + 1).unwrap_or(0),
			});

			tokio::pin!(created_request);
			tokio::pin!(updated_request);
			loop {
				tokio::select!{
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
					_ = invoice_interval.tick() => self.process_invoices().await?,
				};
			}
		}
	}
}
