
//!
//! Lightning logic based on our CLN node.
//!
//! ## A high-level summary of the payment flow.
//!
//! * User makes a payment over grpc, aspd calls [ClnManager::pay_bolt11].
//! * The payment request is sent over the payment channel to the processor.
//! * The calling thread will then subscribe to the payment update channel,
//!   - and wait for a msg with its payment hash, or
//!   - periodically poll the db for any progress.
//!
//! Meanwhile the [ClnManagerProcess] receives the payment request on the channel.
//! * It calls [ClnManagerProcess::start_payment], which will
//! * store the payment request in the db
//! * pick the highest priority online CLN node from our list
//! * calls [handle_pay_bolt11] which calls the cln node's RPC `pay` endpoint.
//!   - on any progress it sends a message on the payment update channel
//!     - on error it stores the error data in the database
//!       (this is necessary because on some errors, we don't get a listsendpay update)
//!     - on success it does nothing extra, the listsendpay thread will eventually
//!       receive an update too and correctly log in the db
//!
//! ## The CLN listsendpay stream
//!
//! For each running cln node, we have a [ClnNodeMonitor] that will be subscribed
//! to all updates regarding payments on the node. On each message we do the neccesary
//! logging to the database and send a message on the payment update channel.
//!
//!
//!
//!
//!
//!
//!

pub(crate) mod node;

use std::fmt;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hashes::sha256;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::AmountExt;
use lightning_invoice::Bolt11Invoice;
use log::{debug, error, info, trace, warn};
use tokio::sync::{broadcast, Notify, mpsc};
use tokio::sync::broadcast::Receiver;
use tonic::transport::{Channel, Uri};

use ark::lightning::SignedBolt11Payment;
use cln_rpc::node_client::NodeClient;

use crate::error::AnyhowErrorExt;
use crate::system::RuntimeManager;
use crate::cln::node::ClnNodeMonitor;
use crate::config::{self, Config};
use crate::database::{self, ClnNodeId};
use crate::database::model::{LightningPaymentAttempt, LightningPaymentStatus};
use crate::telemetry::TelemetryMetrics;
use self::node::ClnNodeMonitorConfig;


type ClnGrpcClient = NodeClient<Channel>;

/// Handle for the cln manager process.
pub struct ClnManager {
	db: database::Db,
	invoice_poll_interval: Duration,

	/// This channel sends payment requests to the process.
	payment_tx: mpsc::UnboundedSender<(Bolt11Invoice, Option<Amount>)>,

	/// We also keep a handle of the update channel to update from
	/// payment request that fail before the hit the sendpay stream.
	//TODO(stevenroose) consider changing this to hold some update info
	payment_update_tx: broadcast::Sender<sha256::Hash>,
}

impl ClnManager {
	/// Start the [ClnManager].
	pub async fn start(
		rtmgr: RuntimeManager,
		config: &Config,
		db: database::Db,
		telemetry_metrics: TelemetryMetrics,
	) -> anyhow::Result<ClnManager> {
		let (payment_tx, payment_rx) = mpsc::unbounded_channel();
		let (payment_update_tx, _rx) = broadcast::channel(256);

		let node_monitor_config = ClnNodeMonitorConfig {
			invoice_check_interval: config.invoice_check_interval,
			invoice_recheck_delay: config.invoice_recheck_delay,
			check_base_delay: config.invoice_check_base_delay,
			check_max_delay: config.invoice_check_max_delay,
		};
		let proc = ClnManagerProcess {
			rtmgr,
			payment_rx,
			node_monitor_config,
			db: db.clone(),
			payment_update_tx: payment_update_tx.clone(),
			waker: Arc::new(Notify::new()),
			network: config.network,
			nodes: config.cln_array.iter().map(|conf| (conf.uri.clone(), ClnNodeInfo {
				uri: conf.uri.clone(),
				config: conf.clone(),
				state: ClnNodeState::Offline,
			})).collect(),
			node_by_id: HashMap::with_capacity(config.cln_array.len()),
			telemetry_metrics: telemetry_metrics.clone(),
		};
		info!("Starting ClnManager thread... nb_nodes={}", proc.nodes.len());
		tokio::spawn(proc.run(config.cln_reconnect_interval));

		Ok(ClnManager {
			db,
			payment_tx,
			payment_update_tx,
			invoice_poll_interval: config.invoice_poll_interval,
		})
	}

	/// Pays a bolt-11 invoice and returns the pre-image
	///
	/// This method is also more clever than calling the grpc-method.
	/// We might be able to recover from a short connection-break or time-outs
	/// from Core Lightning.
	pub async fn pay_bolt11(
		&self,
		payment: &SignedBolt11Payment,
		wait: bool,
	) -> anyhow::Result<[u8; 32]> {
		let invoice = &payment.payment.invoice;
		if invoice.check_signature().is_err() {
			bail!("Invalid signature in Bolt-11 invoice");
		}

		let user_amount = if invoice.amount_milli_satoshis().is_none() {
			Some(payment.payment.payment_amount)
		} else {
			None
		};

		let update_rx = self.payment_update_tx.subscribe();
		self.payment_tx.send((invoice.clone(), user_amount)).context("payment channel broken")?;

		debug!("Bolt11 invoice sent for payment, waiting for maintenance task CLN updates...");
		let payment_hash = *invoice.payment_hash();

		self.check_bolt11_internal(update_rx, &payment_hash, wait, false).await
	}

	/// Checks a bolt-11 invoice and returns the pre-image
	pub async fn check_bolt11(
		&self,
		payment_hash: &sha256::Hash,
		wait: bool,
	) -> anyhow::Result<[u8; 32]> {
		let update_rx = self.payment_update_tx.subscribe();

		self.check_bolt11_internal(update_rx, payment_hash, wait, true).await
	}

	pub async fn check_bolt11_internal(
		&self,
		mut update_rx: Receiver<sha256::Hash>,
		payment_hash: &sha256::Hash,
		wait: bool,
		instant_check: bool,
	) -> anyhow::Result<[u8; 32]> {
		let mut poll_interval = tokio::time::interval(self.invoice_poll_interval);
		poll_interval.reset();
		loop {
			tokio::select! {
				_ = async {}, if instant_check => {
					trace!("instant_check triggered, polling");
					continue;
				},
				_ = poll_interval.tick() => trace!("check bolt11 timeout reached, polling"),
				// Trigger received on channel
				rcv = update_rx.recv() => match rcv {
					Ok(hash) => {
						if hash != *payment_hash {
							continue;
						}
					},
					Err(broadcast::error::RecvError::Lagged(_)) => continue,
					Err(broadcast::error::RecvError::Closed) => {
						bail!("payment update channel closed, probably shutting down");
					},
				},
			}

			let invoice = self.db.get_lightning_invoice_by_payment_hash(&payment_hash).await?;

			if let Some(status) = invoice.last_attempt_status {
				// In both cases, check payment status
				trace!("Bolt11 invoice status for payment {}: {}",
					invoice.invoice.payment_hash(), status,
				);

				if status == LightningPaymentStatus::Succeeded {
					let preimage = invoice.preimage
						.context("missing preimage on bolt11 success")?;
					debug!("Done, preimage: {} for invoice {}", preimage.as_hex(), invoice.invoice);
					return Ok(preimage);
				}

				if status == LightningPaymentStatus::Failed {
					return Err(anyhow::Error::msg("payment failed")
						.context(LightningPaymentStatus::Failed));
				}
			} else {
				warn!("Bolt11 invoice status for payment {}: no attempt on invoice",
					invoice.invoice.payment_hash(),
				);
			}

			if !wait {
				let err = anyhow!("payment pending");
				return Err(if let Some(status) = invoice.last_attempt_status {
					err.context(status)
				} else {
					err
				})
			}
			// Continue loop, wait for next trigger or timeout
		}
	}
}

#[derive(Debug)]
pub struct ClnNodeOnlineState {
	id: ClnNodeId,
	public_key: PublicKey,
	rpc: ClnGrpcClient,
	// option so we can take() when marking as down
	monitor: Option<ClnNodeMonitor>,
}

#[derive(Debug)]
pub enum ClnNodeState {
	Offline,
	Online(ClnNodeOnlineState),
	Error {
		msg: String,
	},
	Invalid {
		msg: String,
	},
}

const OFFLINE: &'static str = "offline";
const ONLINE: &'static str = "online";
const ERROR: &'static str = "error";
const INVALID: &'static str = "invalid";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClnNodeStateKind {
	/// see [`Offline`]
	Offline,
	/// see [`Online`]
	Online,
	/// see [`Error`]
	Error,
	/// see [`Invalid`]
	Invalid,
}

impl ClnNodeStateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			ClnNodeStateKind::Offline => OFFLINE,
			ClnNodeStateKind::Online => ONLINE,
			ClnNodeStateKind::Error => ERROR,
			ClnNodeStateKind::Invalid => INVALID,
		}
	}
	pub fn get_all() -> Vec<ClnNodeStateKind> {
		vec![
			ClnNodeStateKind::Offline,
			ClnNodeStateKind::Online,
			ClnNodeStateKind::Error,
			ClnNodeStateKind::Invalid,
		]
	}
}

impl ClnNodeState {
	pub fn kind(&self) -> ClnNodeStateKind {
		match &self {
			Self::Offline => ClnNodeStateKind::Offline,
			Self::Online(_) => ClnNodeStateKind::Online,
			Self::Error { .. } => ClnNodeStateKind::Error,
			Self::Invalid { .. } => ClnNodeStateKind::Invalid,
		}
	}
	fn error(msg: impl fmt::Display) -> Self {
		ClnNodeState::Error { msg: msg.to_string() }
	}
	fn invalid(msg: impl fmt::Display) -> Self {
		ClnNodeState::Invalid { msg: msg.to_string() }
	}
}

impl fmt::Display for ClnNodeState {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    match self {
			ClnNodeState::Offline => f.write_str("offline"),
			ClnNodeState::Online(i) => write!(f, "online: {}", i.id),
			ClnNodeState::Error { msg } => write!(f, "error: {}", msg),
			ClnNodeState::Invalid { msg } => write!(f, "invalid: {}", msg),
		}
	}
}

#[derive(Debug)]
pub struct ClnNodeInfo {
	uri: Uri,
	config: config::Lightningd,
	state: ClnNodeState,
}

impl ClnNodeInfo {
	fn online(&self) -> Option<&ClnNodeOnlineState> {
		match self.state {
			ClnNodeState::Online(ref s) => Some(s),
			_ => None,
		}
	}

	/// Set new status and print a log for the record.
	fn set_state(&mut self, new_state: ClnNodeState) {
		let uri = &self.uri;
		if let ClnNodeState::Invalid { ref msg } = new_state {
			error!("Marking CLN node with URI {uri} as invalid: {msg}");
		} else if let ClnNodeState::Offline = new_state {
			warn!("Marking CLN node with URI {uri} as offline");
		} else {
			debug!("Setting status of CLN node with URI {uri}: {new_state}");
		}
		self.state = new_state;
	}

	async fn try_connect(
		&mut self,
		db: &database::Db,
		expected_network: bitcoin::Network,
		monitor_config: &ClnNodeMonitorConfig,
		payment_update_tx: &broadcast::Sender<sha256::Hash>,
		rtmgr: &RuntimeManager,
		waker: &Arc<Notify>,
		telemetry_metrics: &TelemetryMetrics,
	) -> anyhow::Result<ClnNodeId> {
		let mut rpc = self.config.build_grpc_client().await.context("failed to connect rpc")?;

		let info = rpc.getinfo(cln_rpc::GetinfoRequest {}).await
			.context("failed to get info from rpc")?
			.into_inner();

		let network = bitcoin::Network::from_str(info.network.as_str())
			.context(ClnNodeState::invalid("network invalid"))?;

		if network != expected_network {
			let msg = format!("network is {network} instead of {expected_network}");
			return Err(anyhow::Error::msg(msg.clone()).context(ClnNodeState::invalid(msg)));
		}

		let public_key = PublicKey::from_slice(&info.id.to_vec())
			.context(ClnNodeState::invalid("malformed pubkey"))?;

		let (id, _) = db.register_lightning_node(&public_key).await?;

		info!("Succesfully connected to cln node with uri {}", self.uri);
		let monitor = ClnNodeMonitor::start(
			rtmgr.clone(),
			waker.clone(),
			db.clone(),
			payment_update_tx.clone(),
			id,
			rpc.clone(),
			monitor_config.clone(),
			telemetry_metrics.clone(),
		).await.context("failed to start ClnNodeMonitor")?;

		let online = ClnNodeOnlineState { id, public_key, rpc, monitor: Some(monitor) };
		let new_state = ClnNodeState::Online(online);
		telemetry_metrics.set_lightning_node_state(
			self.uri.clone(), Some(id), Some(public_key), new_state.kind(),
		);
		self.set_state(new_state);

		Ok(id)
	}
}

struct ClnManagerProcess {
	db: database::Db,
	rtmgr: RuntimeManager,
	payment_rx: mpsc::UnboundedReceiver<(Bolt11Invoice, Option<Amount>)>,
	payment_update_tx: broadcast::Sender<sha256::Hash>,
	waker: Arc<Notify>,

	network: bitcoin::Network,
	nodes: HashMap<Uri, ClnNodeInfo>,
	node_by_id: HashMap<ClnNodeId, Uri>,
	node_monitor_config: ClnNodeMonitorConfig,

	telemetry_metrics: TelemetryMetrics,
}

impl ClnManagerProcess {
	/// Get the active node, i.e. the node with the highest priority.
	///
	/// We use this node to start payments.
	fn get_active_node(&self) -> Option<&ClnNodeInfo> {
		let nodes_by_prio = self.nodes.iter().filter_map(|(_, node)| {
			if let ClnNodeState::Online(_) = node.state {
				Some((node.config.priority, node))
			} else {
				None
			}
		});

		nodes_by_prio.min_by_key(|&(prio, _)| prio).map(|(_, node)| node)
	}

	async fn check_nodes(&mut self) {
		for (uri, node) in self.nodes.iter_mut() {
			match node.state {
				ClnNodeState::Online(ref mut rt) => {
					// we check if the monitor is still running
					if !rt.monitor.as_ref().expect("online").is_running() {
						match rt.monitor.take().unwrap().wait().await {
							Ok(Err(e)) => {
								let new_state = ClnNodeState::error(format!("{:?}", e));
								self.telemetry_metrics.set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.public_key), new_state.kind(),
								);
								node.set_state(new_state)
							},
							Ok(Ok(())) => {
								error!("ClnNodeMonitor for {uri} unexpectedly exited without error");
								let new_state = ClnNodeState::Offline;
								self.telemetry_metrics.set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.public_key), new_state.kind(),
								);
								node.set_state(new_state);
							},
							Err(e) => {
								if e.is_panic() {
									// unfortunately we don't have much more info we can show here
									error!("ClnNodeMonitor for {uri} thread paniced!");
								}
								let new_state = ClnNodeState::error(e);
								self.telemetry_metrics.set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.public_key), new_state.kind(),
								);
								node.set_state(new_state);
							},
						}
					}
				},
				ClnNodeState::Offline | ClnNodeState::Error { .. } => {
					trace!("Trying to connect to offline node at {}", uri);
					match node.try_connect(
						&self.db,
						self.network,
						&self.node_monitor_config,
						&self.payment_update_tx,
						&self.rtmgr,
						&self.waker,
						&self.telemetry_metrics,
					).await {
						Ok(id) => {
							info!("Successfully connected to CLN node at {}", uri);
							self.node_by_id.insert(id, node.uri.clone());
						},
						Err(e) => {
							trace!("Failed to connect to CLN node at {}: {}", uri, e.full_msg());
							if let Ok(state) = e.downcast::<ClnNodeState>() {
								self.telemetry_metrics.set_lightning_node_state(
									uri.clone(), None, None, state.kind(),
								);
								node.set_state(state);
							}
						}
					}
				},
				ClnNodeState::Invalid { .. } => {}, // do nothing anymore
			}
		}
	}

	async fn start_payment(
		&self,
		invoice: Bolt11Invoice,
		user_amount: Option<Amount>,
	) -> anyhow::Result<()> {
		let node = self.get_active_node().context("no active cln node")?
			.online().context("active node not online")?;

		debug!("Selected cln node {} for bolt11 payment with payment hash {} and amount {:#?}",
			node.id, invoice.payment_hash(), user_amount,
		);

		let amount_msat = match invoice.amount_milli_satoshis() {
			Some(msat) => msat,
			None => user_amount.context("user amount required for invoice without amount")?.to_msat(),
		};
		self.db.store_lightning_payment_start(node.id, &invoice, amount_msat).await?;

		// Call pay over GRPC
		// If it returns a pre-image we know the call succeeded,
		//  however we ignore the response because it should get processed by the maintenance task.
		// This method might fail even if the payment will succeed
		// (grpc-connection problems or time-outs).
		// We keep the error-around but will verify if the payment actually failed.
		trace!("Bolt11 invoice payment of {:?} sent to CLN: {}", user_amount, invoice);
		tokio::spawn(handle_pay_bolt11(
			self.db.clone(),
			self.payment_update_tx.clone(),
			node.rpc.clone(),
			invoice,
			user_amount,
			self.telemetry_metrics.clone(),
		));

		Ok(())
	}

	async fn run(mut self, reconnect_interval: Duration) {
		let _worker = self.rtmgr.spawn_critical("ClnManager");

		let mut interval = tokio::time::interval(reconnect_interval);

		loop {
			tokio::select!{
				_ = self.rtmgr.shutdown_signal() => {
					info!("Run CLN integration received shutdown signal. Exiting.");
					break;
				},

				_ = self.waker.notified() => {
					trace!("ClnManagerProcess woken up by child");
					self.check_nodes().await;
				},
				_ = interval.tick() => {
					trace!("ClnManagerProcess checking nodes on interval");
					self.check_nodes().await;
				},

				msg = self.payment_rx.recv() => if let Some((invoice, amount)) = msg {
					trace!("Payment received: payment_hash={:?}", invoice.payment_hash());
					if let Err(e) = self.start_payment(invoice, amount).await {
						error!("Error sending bolt11 payment for invoice: {}", e);
					}
				} else {
					warn!("payment channel closed, shutting down ClnManager");
					break;
				},
			};
		}
	}
}

/// Handles calling the pay cln endpoint and processing the response.
async fn handle_pay_bolt11(
	db: database::Db,
	payment_update_tx: broadcast::Sender<sha256::Hash>,
	mut rpc: ClnGrpcClient,
	invoice: Bolt11Invoice,
	amount: Option<Amount>,
	telemetry_metrics: TelemetryMetrics,
) {
	let payment_hash = *invoice.payment_hash();
	match call_pay_bolt11(&mut rpc, &invoice, amount).await {
		Ok(preimage) => {
			// NB we don't do db stuff when it's succesful, because
			// it will happen in the sendpay stream of the monitor process
			trace!("Payment successful, preimage: {} for payment hash {}",
				preimage.as_hex(), payment_hash,
			);
		},
		// Fetch and store the attempt as failed.
		Err(pay_err) => {
			match db.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await {
				Ok(Some(attempt)) => match db.verify_and_update_invoice(
					&payment_hash,
					Some(&format!("pay rpc call error: {}", pay_err)),
					&attempt,
					LightningPaymentStatus::Submitted,
					None,
					None,
					telemetry_metrics,
				).await {
					Ok(_) => {},
					Err(e) => error!("Error updating invoice after pay error: {e}"),
				}
				Ok(None) => error!("Failed to find attempt for invoice just started \
					payment_hash={payment_hash}"),
				Err(e) => error!("Error querying attempt for invoice just started \
					payment_hash={payment_hash}: {e}"),
			}
			let _ = payment_update_tx.send(payment_hash);
		},
	}
}

/// Calls the pay-command over gRPC.
/// If the payment completes successfully it will return the pre-image
/// Otherwise, an error will be returned
async fn call_pay_bolt11(
	rpc: &mut ClnGrpcClient,
	invoice: &Bolt11Invoice,
	user_amount: Option<Amount>,
) -> anyhow::Result<[u8; 32]> {
	match (user_amount, invoice.amount_milli_satoshis()) {
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

	// Call the pay command
	let pay_response = rpc.pay(cln_rpc::PayRequest {
		bolt11: invoice.to_string(),
		label: None,
		maxfee: None,
		maxfeepercent: None,
		retry_for: None,
		maxdelay: None,
		amount_msat: {
			if invoice.amount_milli_satoshis().is_none() {
				Some(user_amount.unwrap().into())
			} else {
				None
			}
		},
		description: None,
		exemptfee: None,
		riskfactor: None,
		exclude: vec![],
		localinvreqid: None,
		partial_msat: None,
	}).await?.into_inner();

	if pay_response.payment_preimage.len() > 0 {
		Ok(pay_response.payment_preimage.try_into().ok().context("invalid preimage not 32 bytes")?)
	} else {
		bail!("pay returned with status {}", pay_response.status().as_str_name())
	}
}

impl database::Db {
	async fn verify_and_update_invoice(
		&self,
		payment_hash: &sha256::Hash,
		payment_error: Option<&str>,
		attempt: &LightningPaymentAttempt,
		status: LightningPaymentStatus,
		final_amount_msat: Option<u64>,
		preimage: Option<&[u8; 32]>,
		telemetry_metrics: TelemetryMetrics,
	) -> anyhow::Result<bool> {
		let li = self.get_lightning_invoice_by_payment_hash(payment_hash).await?;
		let is_last_attempt_finalized = li.last_attempt_status
			.map(|a| a.is_final()).unwrap_or(false);

		if li.preimage.is_some() || is_last_attempt_finalized {
			debug!("Lightning invoice update for {payment_hash}: Skipped update because the \
				payment is already in a final state.");
			return Ok(false);
		}

		if li.lightning_invoice_id != attempt.lightning_invoice_id {
			error!("Lightning invoice update for {payment_hash}: Skipped update because of \
				incorrect payment hash matching.");
			return Ok(false);
		}

		self.store_lightning_payment_attempt_status(
			attempt.lightning_payment_attempt_id, status, payment_error, attempt.updated_at,
		).await?;

		self.store_lightning_invoice_status(
			li.lightning_invoice_id, final_amount_msat, preimage, li.updated_at,
		).await?;

		let amount_msat = final_amount_msat.unwrap_or(attempt.amount_msat);

		telemetry_metrics.add_lightning_payment(
			attempt.lightning_node_id,
			amount_msat,
			status,
		);

		Ok(true)
	}
}
