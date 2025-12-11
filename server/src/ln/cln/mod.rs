//!
//! Lightning logic based on our CLN node.
//!
//! ## A high-level summary of the payment flow.
//!
//! * User makes a payment over grpc, server calls [ClnManager::pay_invoice].
//! * The payment request is sent over the payment channel to the processor.
//! * The calling thread will then subscribe to the payment update channel,
//!   - and wait for a msg with its payment hash, or
//!   - periodically poll the db for any progress.
//!
//! Meanwhile the [ClnManagerProcess] receives the payment request on the channel.
//! * It calls [ClnManagerProcess::start_payment], which will
//! * store the payment request in the db
//! * pick the highest priority online CLN node from our list
//! * calls [handle_pay_invoice] which calls the cln node's RPC `pay` endpoint.
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
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight};
use cln_rpc::plugins::hold::{self, hold_client::HoldClient};
use lightning_invoice::Bolt11Invoice;
use log::{debug, error, info, trace, warn};
use tokio::sync::{broadcast, Notify, mpsc, oneshot};
use tonic::transport::{Channel, Uri};

use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, PaymentHash, PaymentStatus, Preimage};
use cln_rpc::node_client::NodeClient;

use crate::error::ContextExt;
use crate::system::RuntimeManager;
use crate::config::{self, Config};
use crate::database;
use crate::database::ln::{
	ClnNodeId, LightningHtlcSubscription, LightningHtlcSubscriptionStatus, LightningPaymentAttempt,
	LightningPaymentStatus,
};
use self::node::{ClnNodeMonitor, ClnNodeMonitorConfig};
use crate::telemetry;

type ClnGrpcClient = NodeClient<Channel>;

/// Handle for the cln manager process.
pub struct ClnManager {
	db: database::Db,
	invoice_poll_interval: Duration,

	/// This channel is to manage individual CLN integrations.
	ctrl_tx: mpsc::UnboundedSender<Ctrl>,

	/// We also keep a handle of the update channel to update from
	/// payment request that fail before the hit the sendpay stream.
	//TODO(stevenroose) consider changing this to hold some update info
	payment_update_tx: broadcast::Sender<PaymentHash>,
	// If all receivers are dropped the channel will close and the payment might fail
	// The only purpose of this field is to ensure we will always keep at least one receiver alive
	payment_update_rx: broadcast::Receiver<PaymentHash>,
}

impl ClnManager {
	/// Start the [ClnManager].
	pub async fn start(
		rtmgr: RuntimeManager,
		config: &Config,
		db: database::Db,
	) -> anyhow::Result<ClnManager> {
		let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
		let (payment_update_tx, payment_update_rx) = broadcast::channel(256);

		let node_monitor_config = ClnNodeMonitorConfig {
			invoice_check_interval: config.invoice_check_interval,
			invoice_recheck_delay: config.invoice_recheck_delay,
			invoice_expiry: config.invoice_expiry,
			receive_htlc_forward_timeout: config.receive_htlc_forward_timeout,
			check_base_delay: config.invoice_check_base_delay,
			check_max_delay: config.invoice_check_max_delay,
		};
		let proc = ClnManagerProcess {
			db: db.clone(),
			rtmgr,
			waker: Arc::new(Notify::new()),

			ctrl_rx,
			node_monitor_config,

			payment_update_tx: payment_update_tx.clone(),

			network: config.network,
			nodes: config.cln_array.iter().map(|conf| (conf.uri.clone(), ClnNodeInfo {
				uri: conf.uri.clone(),
				config: conf.clone(),
				state: ClnNodeState::Offline,
			})).collect(),
			node_by_id: HashMap::with_capacity(config.cln_array.len()),

			htlc_expiry_delta: config.htlc_expiry_delta,
		};
		info!("Starting ClnManager thread... nb_nodes={}", proc.nodes.len());
		tokio::spawn(proc.run(config.cln_reconnect_interval));

		Ok(ClnManager {
			db,
			ctrl_tx,
			payment_update_tx,
			payment_update_rx,
			invoice_poll_interval: config.invoice_poll_interval,
		})
	}

	/// Send a control message to the process
	fn send_ctrl(&self, ctrl: Ctrl) {
		self.ctrl_tx.send(ctrl).expect("called ClnManager after shutting down");
	}

	/// Pays a bolt-11 invoice and returns the pre-image
	///
	/// This method is also more clever than calling the grpc-method.
	/// We might be able to recover from a short connection-break or time-outs
	/// from Core Lightning.
	pub async fn pay_invoice(
		&self,
		invoice: &Invoice,
		htlc_amount: Amount,
		htlc_send_expiry_height: BlockHeight,
	) -> anyhow::Result<()> {
		invoice.check_signature().context("invalid invoice signature")?;

		let user_amount = if invoice.amount_msat().is_none() {
			Some(htlc_amount)
		} else {
			None
		};

		let (result_tx, result_rx) = oneshot::channel();
		self.send_ctrl(Ctrl::PaymentRequest {
			result_tx,
			invoice: Box::new(invoice.clone()),
			user_amount,
			htlc_expiry_height: htlc_send_expiry_height,
		});

		if let Err(e) = result_rx.await.context("channel closed")? {
			error!("Error sending bolt11 payment for invoice: {:#}", e);
		} else {
			debug!("Bolt11 invoice sent for payment, waiting for maintenance task CLN updates...");
		}

		Ok(())
	}

	/// Gets the payment status for a given payment hash
	pub async fn get_payment_status(
		&self,
		payment_hash: &PaymentHash,
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

			let invoice = self.db.get_lightning_invoice_by_payment_hash(&payment_hash).await?
				.not_found([payment_hash], "invoice not found")?;

			if let Some(status) = invoice.last_attempt_status {
				// In both cases, check payment status
				trace!("Bolt11 invoice status for payment {}: {}",
					invoice.invoice.payment_hash(), status,
				);

				if status == LightningPaymentStatus::Succeeded {
					let preimage = invoice.preimage
						.context("missing preimage on bolt11 success")?;
					debug!("Done, preimage: {} for invoice {}", preimage.as_hex(), invoice.invoice);
					return Ok(PaymentStatus::Success(preimage));
				}

				if status == LightningPaymentStatus::Failed {
					return Ok(PaymentStatus::Failed);
				}
			} else {
				warn!("Bolt11 invoice status for payment {}: no attempt on invoice",
					invoice.invoice.payment_hash(),
				);
			}

			if !wait {
				return Ok(PaymentStatus::Pending);
			}
			// Continue loop, wait for next trigger or timeout
		}
	}

	pub async fn generate_invoice(
		&self,
		payment_hash: PaymentHash,
		amount: Amount,
		cltv_delta: BlockDelta,
	) -> anyhow::Result<Bolt11Invoice> {
		let (invoice_tx, invoice_rx) = oneshot::channel();
		self.send_ctrl(Ctrl::GenerateInvoice { payment_hash, amount, cltv_delta, invoice_tx });
		invoice_rx.await.context("an error occurred requesting a BOLT-11 invoice")
	}

	pub async fn settle_invoice(
		&self,
		subscription_id: i64,
		preimage: Preimage,
	) -> anyhow::Result<()> {
		let payment_hash = preimage.compute_payment_hash();

		// If an open payment attempt exists for the payment hash, it is an
		// intra-Ark lightning payment so we can mark it as succeeded with
		// preimage, then skip hold invoice settlement
		let attempt = self.db.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await?;
		if let Some(attempt) = attempt {
			let status = LightningPaymentStatus::Succeeded;
			self.db.verify_and_update_invoice(
				&payment_hash, &attempt, status, None, None, Some(preimage),
			).await?;

			// NB: in case of intra-ark lightning payments, we need to notify the subscriber
			// that the payment has been succeeded, otherwise it will wait until next timeout
			// to get the confirmation, since no notification will ever come from CLN hook
			self.payment_update_tx.send(payment_hash)
				.context("payment update channel broken")?;
		} else {
			let (result_tx, result_rx) = oneshot::channel();
			self.send_ctrl(Ctrl::SettleInvoice { subscription_id, preimage, result_tx });
			result_rx.await.context("an error occurred settling invoice")??;
		}

		// Update the subscription status to settled
		self.db.store_lightning_htlc_subscription_status(
			subscription_id,
			LightningHtlcSubscriptionStatus::Settled,
			None
		).await?;

		Ok(())

	}

	/// Fetches and parse an invoice from a bolt-12 offer
	pub async fn fetch_bolt12_invoice(
		&self,
		offer: Offer,
		amount: Amount,
	) -> anyhow::Result<Bolt12Invoice> {
		let (invoice_tx, invoice_rx) = oneshot::channel();
		self.send_ctrl(Ctrl::RequestBolt12 { offer: Box::new(offer), amount, invoice_tx });
		invoice_rx.await.context("an error occurred requesting BOLT-12 invoice")
	}

	pub fn activate(&self, uri: Uri) {
		self.send_ctrl(Ctrl::ActivateCln(uri));
	}

	pub fn disable(&self, uri: Uri) {
		self.send_ctrl(Ctrl::DisableCln(uri));
	}
}

#[derive(Debug)]
pub struct ClnNodeOnlineState {
	id: ClnNodeId,
	pubkey: PublicKey,
	rpc: ClnGrpcClient,
	hodl_rpc: Option<HoldClient<Channel>>,
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
	Disabled,
}

const OFFLINE: &'static str = "offline";
const ONLINE: &'static str = "online";
const ERROR: &'static str = "error";
const INVALID: &'static str = "invalid";
const DISABLED: &'static str = "disabled";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClnNodeStateKind {
	/// see [ClnNodeState::Offline]
	Offline,
	/// see [ClnNodeState::Online]
	Online,
	/// see [ClnNodeState::Error]
	Error,
	/// see [ClnNodeState::Invalid]
	Invalid,
	/// see [ClnNodeState::Disabled]
	Disabled,
}

impl ClnNodeStateKind {
	pub fn as_str(&self) -> &'static str {
		match self {
			ClnNodeStateKind::Offline => OFFLINE,
			ClnNodeStateKind::Online => ONLINE,
			ClnNodeStateKind::Error => ERROR,
			ClnNodeStateKind::Invalid => INVALID,
			ClnNodeStateKind::Disabled => DISABLED,
		}
	}
	pub fn get_all() -> &'static [ClnNodeStateKind] {
		&[
			ClnNodeStateKind::Offline,
			ClnNodeStateKind::Online,
			ClnNodeStateKind::Error,
			ClnNodeStateKind::Invalid,
			ClnNodeStateKind::Disabled,
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
			Self::Disabled => ClnNodeStateKind::Disabled,
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
			ClnNodeState::Disabled => f.write_str("disabled"),
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
		payment_update_tx: &broadcast::Sender<PaymentHash>,
		rtmgr: &RuntimeManager,
		waker: &Arc<Notify>,
	) -> anyhow::Result<ClnNodeId> {
		let mut rpc = self.config.build_grpc_client().await.context("failed to connect rpc")?;
		let hodl_rpc = self.config.build_hodl_client().await.context("failed to connect hodl rpc")?;

		let info = rpc.getinfo(cln_rpc::GetinfoRequest {}).await
			.context("failed to get info from rpc")?
			.into_inner();

		let network = bitcoin::Network::from_str(info.network.as_str())
			.context(ClnNodeState::invalid("network invalid"))?;

		if network != expected_network {
			let msg = format!("network is {network} instead of {expected_network}");
			return Err(anyhow::Error::msg(msg.clone()).context(ClnNodeState::invalid(msg)));
		}

		let pubkey = PublicKey::from_slice(&info.id.to_vec())
			.context(ClnNodeState::invalid("malformed pubkey"))?;

		let (id, _) = db.register_lightning_node(&pubkey).await?;

		info!("Succesfully connected to cln node with uri {}", self.uri);
		let monitor = ClnNodeMonitor::start(
			rtmgr.clone(),
			waker.clone(),
			db.clone(),
			payment_update_tx.clone(),
			id,
			rpc.clone(),
			hodl_rpc.clone(),
			monitor_config.clone(),
		).await.context("failed to start ClnNodeMonitor")?;

		let online = ClnNodeOnlineState { id, pubkey, rpc, hodl_rpc, monitor: Some(monitor) };
		let new_state = ClnNodeState::Online(online);
		telemetry::set_lightning_node_state(
			self.uri.clone(), Some(id), Some(pubkey), new_state.kind(),
		);
		self.set_state(new_state);

		Ok(id)
	}
}

#[derive(Debug)]
enum Ctrl {
	ActivateCln(Uri),
	DisableCln(Uri),
	PaymentRequest {
		invoice: Box<Invoice>,
		user_amount: Option<Amount>,
		htlc_expiry_height: BlockHeight,
		result_tx: oneshot::Sender<anyhow::Result<()>>,
	},
	GenerateInvoice {
		payment_hash: PaymentHash,
		amount: Amount,
		cltv_delta: BlockDelta,
		invoice_tx: oneshot::Sender<Bolt11Invoice>,
	},
	SettleInvoice {
		subscription_id: i64,
		preimage: Preimage,
		result_tx: oneshot::Sender<anyhow::Result<()>>,
	},
	RequestBolt12 {
		offer: Box<Offer>,
		amount: Amount,
		invoice_tx: oneshot::Sender<Bolt12Invoice>,
	},
}

struct ClnManagerProcess {
	db: database::Db,
	rtmgr: RuntimeManager,
	waker: Arc<Notify>,

	ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,

	payment_update_tx: broadcast::Sender<PaymentHash>,

	network: bitcoin::Network,
	nodes: HashMap<Uri, ClnNodeInfo>,
	node_by_id: HashMap<ClnNodeId, Uri>,
	node_monitor_config: ClnNodeMonitorConfig,

	htlc_expiry_delta: BlockDelta,
}

impl ClnManagerProcess {
	fn online_nodes(&self) -> impl Iterator<Item = (u8, &ClnNodeOnlineState)> {
		self.nodes.iter().filter_map(|(_, node)| {
			if let ClnNodeState::Online(ref state) = node.state {
				Some((node.config.priority, state))
			} else {
				None
			}
		})
	}

	/// Get the active node, i.e. the node with the highest priority.
	///
	/// We use this node to start payments.
	fn get_active_node(&self) -> Option<&ClnNodeOnlineState> {
		self.online_nodes().min_by_key(|&(prio, _)| prio).map(|(_, node)| node)
	}

	fn get_hodl_active_node(&self) -> Option<&ClnNodeOnlineState> {
		self.online_nodes()
			.filter(|(_, node)| node.hodl_rpc.is_some())
			.min_by_key(|&(prio, _)| prio).map(|(_, node)| node)
	}

	fn get_node_by_id(&self, id: ClnNodeId) -> Option<&ClnNodeOnlineState> {
		self.online_nodes()
			.find(|(_, node)| node.id == id)
			.map(|(_, node)| node)
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
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state)
							},
							Ok(Ok(())) => {
								error!("ClnNodeMonitor for {uri} unexpectedly exited without error");
								let new_state = ClnNodeState::Offline;
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
								);
								node.set_state(new_state);
							},
							Err(e) => {
								if e.is_panic() {
									// unfortunately we don't have much more info we can show here
									error!("ClnNodeMonitor for {uri} thread paniced!");
								}
								let new_state = ClnNodeState::error(e);
								telemetry::set_lightning_node_state(
									uri.clone(), Some(rt.id), Some(rt.pubkey), new_state.kind(),
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
					).await {
						Ok(id) => {
							info!("Successfully connected to CLN node at {}", uri);
							self.node_by_id.insert(id, node.uri.clone());
						},
						Err(e) => {
							trace!("Failed to connect to CLN node at {}: {:#}", uri, e);
							if let Ok(state) = e.downcast::<ClnNodeState>() {
								telemetry::set_lightning_node_state(
									uri.clone(), None, None, state.kind(),
								);
								node.set_state(state);
							}
						}
					}
				},
				ClnNodeState::Invalid { .. } | ClnNodeState::Disabled => {}, // do nothing anymore
			}
		}
	}

	async fn disable_node(&mut self, uri: &Uri) {
		let Some(node) = self.nodes.get_mut(uri) else {
			error!("Cannot disable node since URI {uri} cannot be found.");
			return;
		};

		let disable = match &node.state {
			ClnNodeState::Online(_) => {
				info!("ClnNode {uri} was Online and is now disabled.");
				true
			}
			ClnNodeState::Error { .. } => {
				info!("ClnNode {uri} was in Error and is now disabled.");
				true
			}
			ClnNodeState::Offline => {
				info!("ClnNode {uri} was Offline and is now disabled.");
				true
			}
			ClnNodeState::Disabled => {
				info!("ClnNode {uri} is already disabled.");
				false
			}
			ClnNodeState::Invalid { .. } => {
				info!("ClnNode {uri} is invalid.");
				false
			}
		};

		if disable {
			let new_state = ClnNodeState::Disabled;
			telemetry::set_lightning_node_state(
				uri.clone(), None, None, new_state.kind(),
			);
			node.set_state(new_state)
		}
	}

	async fn enable_node(&mut self, uri: &Uri) {
		let Some(node) = self.nodes.get_mut(uri) else {
			error!("Cannot enable node since URI {uri} cannot be found.");
			return;
		};

		let enable = match &node.state {
			ClnNodeState::Online(_) => {
				info!("ClnNode with {uri} is already Online (not disabled).");
				false
			},
			ClnNodeState::Error { .. } => {
				info!("ClnNode with {uri} is in state Error (not disabled).");
				false
			},
			ClnNodeState::Offline => {
				info!("ClnNode with {uri} is in state Offline (not disabled).");
				false
			},
			ClnNodeState::Disabled => {
				info!("ClnNode with {uri} was disabled and is now enabled.");
				true
			},
			ClnNodeState::Invalid { .. } => {
				info!("ClnNode with {uri} is invalid.");
				false
			},
		};

		if enable {
			let new_state = ClnNodeState::Disabled;
			telemetry::set_lightning_node_state(
				uri.clone(), None, None, new_state.kind(),
			);
			node.set_state(new_state);
		}
	}

	async fn set_created_subscription_to_accepted(
		&self,
		subscription: LightningHtlcSubscription,
		htlc_send_expiry_height: BlockHeight,
	) -> anyhow::Result<()> {
		match subscription.status {
			LightningHtlcSubscriptionStatus::Created => {
				self.db.store_lightning_htlc_subscription_status(
					subscription.id,
					LightningHtlcSubscriptionStatus::Accepted,
					Some(htlc_send_expiry_height),
				).await?;

				self.cancel_invoice(subscription.clone()).await?;
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

	async fn start_payment(
		&self,
		invoice: Box<Invoice>,
		user_amount: Option<Amount>,
		htlc_send_expiry_height: BlockHeight,
	) -> anyhow::Result<()> {
		let payment_hash = invoice.payment_hash();
		let node = self.get_active_node().context("no active cln node")?;
		let tip = node.rpc.clone().getinfo(cln_rpc::GetinfoRequest {}).await
			.context("failed to get info from rpc")?
			.into_inner().blockheight;

		let amount_msat = match invoice.amount_msat() {
			Some(msat) => msat,
			None => user_amount.context("user amount required for invoice without amount")?.to_msat(),
		};

		debug!("Selected cln node {} for bolt11 payment with payment hash {} and amount {}. Current block height is {}",
			node.id, payment_hash, Amount::from_msat_floor(amount_msat), tip,
		);

		self.db.store_lightning_payment_start(node.id, &invoice, amount_msat).await?;

		// If there is an existing subscription, it's an intra-Ark lightning
		// payment so we can directly mark it as accepted, then skip cln payment
		let sub = self.db
			.get_htlc_subscription_by_payment_hash(payment_hash).await?;
		if let Some(sub) = sub {
			trace!("Updating subscription status for intra-Ark lightning payment with payment hash {payment_hash}");
			let res = self.set_created_subscription_to_accepted(sub, htlc_send_expiry_height).await;
			if let Err(e) = res {
				trace!("Failed to update subscription status: {e}");
				let payment_attempt = self.db
					.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await?
					.expect("we inserted a payment attempt");

				self.db.update_lightning_payment_attempt_status(
					&payment_attempt,
					LightningPaymentStatus::Failed,
					Some(&e.to_string()),
				).await?;

				return Err(e);
			}

			return Ok(());
		}

		// NB: we don't want lightning payment to take more time than the htlc-send expiry
		let max_cltv_expiry_delta = htlc_send_expiry_height
			.checked_sub(tip + self.htlc_expiry_delta as BlockHeight)
			.context("HTLC expiry height is too soon to perform a lightning payment")?;

		// Call pay over GRPC
		// If it returns a pre-image we know the call succeeded,
		//  however we ignore the response because it should get processed by the maintenance task.
		// This method might fail even if the payment will succeed
		// (grpc-connection problems or time-outs).
		// We keep the error-around but will verify if the payment actually failed.
		trace!("Bolt11 invoice payment of {:?} sent to CLN: {}", user_amount, invoice);
		tokio::spawn(handle_pay_invoice(
			self.db.clone(),
			self.payment_update_tx.clone(),
			node.rpc.clone(),
			invoice,
			user_amount,
			max_cltv_expiry_delta as BlockDelta,
		));

		Ok(())
	}

	/// Generates an invoice for the payment hash if none is found in the
	/// database.
	/// - If there is an existing invoice in the database, creates a new
	///   subscription for it and returns the invoice
	/// - Otherwise, creates a new invoice in the hodl plugin, stores it in
	///   the database and returns it
	///
	/// Caller is responsible for checking if there is an existing opened
	/// subscription in the db and act accordingly.
	async fn generate_invoice(&self, payment_hash: PaymentHash, amount: Amount, cltv_delta: BlockDelta) -> anyhow::Result<Bolt11Invoice> {
		let node = self.get_hodl_active_node().context("no active hodl-compatible cln node")?;
		let mut hold_client = node.hodl_rpc.clone().expect("active node not hodl enabled");

		if let Ok(Some(existing)) = self.db.get_lightning_invoice_by_payment_hash(&payment_hash).await {
			trace!("Found invoice but no subscription, creating new one");

			hold_client.inject(hold::InjectRequest {
				invoice: existing.invoice.to_string(),
				min_cltv_expiry: None,
			}).await?;

			self.db.store_lightning_htlc_subscription(node.id, existing.id).await?;
			return Ok(existing.invoice.into_bolt11().expect("invoice is not bolt11"))
		}

		let res = hold_client.invoice(hold::InvoiceRequest {
			payment_hash: payment_hash.to_vec(),
			amount_msat: amount.to_msat(),
			min_final_cltv_expiry: Some(cltv_delta as u64),
			expiry: Some(self.node_monitor_config.invoice_expiry.as_secs()),
			routing_hints: vec![],
			description: None,
		}).await?.into_inner();

		let invoice = Bolt11Invoice::from_str(&res.bolt11)?;
		let _ = self.db.store_generated_lightning_invoice(node.id, &invoice, amount.to_msat()).await?;

		Ok(invoice)
	}

	async fn settle_invoice(&self, subscription_id: i64, preimage: Preimage) -> anyhow::Result<()> {
		let htlc_subscription = self.db
			.get_htlc_subscription_by_id(subscription_id).await?
			.expect("can only settle known invoice");

		// NB: we need to use the node that created the subscription because it is where the HTLCs were sent
		// TODO: this unlikely to happen but at this point, the user already revealed the preimage, so we need
		// to find a way to settle the invoice else he will go onchain and we won't be able to claim Lightning fees,
		// so we'll lose the board amount
		let mut hold_client = self.online_nodes()
			.find(|(_, node)| node.id == htlc_subscription.lightning_node_id)
			.map(|(_, node)| node)
			.context("invoice cannot be settled: node is now offline")?
			.hodl_rpc.clone().context("node doesn't support hodl anymore")?;

		hold_client.settle(hold::SettleRequest {
			payment_preimage: preimage.to_vec(),
		}).await?;

		Ok(())
	}

	/// Cancels an invoice by sending a cancel request to the hodl plugin.
	async fn cancel_invoice(&self, subscription: LightningHtlcSubscription) -> anyhow::Result<()> {
		// NB: we need to use the node that created the subscription
		let mut hold_client = self.get_node_by_id(subscription.lightning_node_id)
			.context("invoice cannot be canceled: node is now offline")?
			.hodl_rpc.clone().context("node doesn't support hodl anymore")?;

		let payment_hash = PaymentHash::from(*subscription.invoice.payment_hash());
		hold_client.cancel(hold::CancelRequest {
			payment_hash: payment_hash.to_vec(),
		}).await?;

		Ok(())
	}

	async fn fetch_bolt12_invoice(
		&self,
		offer: &Offer,
		amount: Amount,
	) -> anyhow::Result<Bolt12Invoice> {
		let node = self.get_active_node().context("no active cln node")?;

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

		Ok(Bolt12Invoice::from_str(&resp.invoice)
			.map_err(|e| anyhow!("Invalid bolt12 invoice: {:?}", e))?)
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

				msg = self.ctrl_rx.recv() => if let Some(msg) = msg {
					 match msg {
						Ctrl::ActivateCln(uri) => {
							self.enable_node(&uri).await;
						},
						Ctrl::DisableCln(uri) => {
							self.disable_node(&uri).await;
						},
						Ctrl::PaymentRequest { invoice, user_amount, htlc_expiry_height, result_tx } => {
							trace!("Payment request received: payment_hash={}",
								invoice.payment_hash(),
							);

							let res = self.start_payment(
								invoice,
								user_amount,
								htlc_expiry_height,
							).await;

							let _ = result_tx.send(res);
						},
						Ctrl::GenerateInvoice { payment_hash, amount, cltv_delta, invoice_tx } => {
							trace!("Invoice generation received: payment_hash={:?}", payment_hash);
							match self.generate_invoice(payment_hash, amount, cltv_delta).await {
								Ok(invoice) => {
									trace!("Invoice generation successful: payment_hash={}",
										payment_hash,
									);
									let _ = invoice_tx.send(invoice);
								},
								Err(e) => error!("Error generating invoice: {:#}", e),
							}
						},
						Ctrl::SettleInvoice { subscription_id, preimage, result_tx } => {
							match self.settle_invoice(subscription_id, preimage).await {
								Ok(()) => {
									trace!("Invoice settled successfully: payment_hash={}",
										preimage.compute_payment_hash(),
									);
									let _ = result_tx.send(Ok(()));
								},
								Err(e) => {
									debug!("Error settling invoice: {:#}", e);
									let _ = result_tx.send(Err(e));
								},
							}
						},
						Ctrl::RequestBolt12 { offer, amount, invoice_tx } => {
							trace!("Fetch bolt12 invoice received: offer={:?}", offer);
							match self.fetch_bolt12_invoice(&offer, amount).await {
								Ok(invoice) => {
									let _ = invoice_tx.send(invoice);
								},
								Err(e) => error!("Error fetching bolt12 invoice: {:#}", e),
							}
						},
					}
				} else {
					warn!("control channel closed, shutting down ClnManager");
					break;
				},
			};
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
			match db.get_open_lightning_payment_attempt_by_payment_hash(&payment_hash).await {
				Ok(Some(attempt)) => match db.verify_and_update_invoice(
					&payment_hash,
					&attempt,
					LightningPaymentStatus::Submitted,
					Some(&format!("pay rpc call error: {}", pay_err)),
					None,
					None,
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

impl database::Db {
	async fn verify_and_update_invoice(
		&self,
		payment_hash: &PaymentHash,
		attempt: &LightningPaymentAttempt,
		status: LightningPaymentStatus,
		payment_error: Option<&str>,
		final_amount_msat: Option<u64>,
		preimage: Option<Preimage>,
	) -> anyhow::Result<bool> {
		let li = self.get_lightning_invoice_by_payment_hash(payment_hash).await?
			.not_found([payment_hash], "invoice not found")?;
		let is_last_attempt_finalized = li.last_attempt_status
			.map(|a| a.is_final()).unwrap_or(false);

		if li.preimage.is_some() || is_last_attempt_finalized {
			debug!("Lightning invoice update for {payment_hash}: Skipped update because the \
				payment is already in a final state.");
			return Ok(false);
		}

		if li.id != attempt.lightning_invoice_id {
			error!("Lightning invoice update for {payment_hash}: Skipped update because of \
				incorrect payment hash matching.");
			return Ok(false);
		}

		self.update_lightning_payment_attempt_status(attempt, status, payment_error).await?;

		let updated_at = self.update_lightning_invoice(li, final_amount_msat, preimage).await?;

		let amount_msat = final_amount_msat.unwrap_or(attempt.amount_msat);

		telemetry::add_lightning_payment(
			attempt.lightning_node_id,
			amount_msat,
			status,
		);

		Ok(updated_at.is_some())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn guard_ctrl_size() {
		// NB our invoice types are huge (thanks LDK), so we box them
		// to reduce the size of our control message
		assert_eq!(std::mem::size_of::<Invoice>(), 1392);
		assert_eq!(std::mem::size_of::<Bolt11Invoice>(), 168);
		assert_eq!(std::mem::size_of::<Bolt12Invoice>(), 1392);
		assert_eq!(std::mem::size_of::<Ctrl>(), 96, "Ctrl type size changed");
	}
}
