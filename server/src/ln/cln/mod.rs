//! Manages CLN node connections and proxies requests to `ClnHold` and `ClnXpay`.
//!
//! ## Node lifecycle
//!
//! Each configured CLN node is tracked as a `ClnNodeInfo` with a state machine:
//! `Offline ↔ Online ↔ Error`, where `Invalid` and `Disabled` are terminal states.
//! The manager periodically reconnects offline/errored nodes and monitors online nodes
//! for crashed sub-monitors (`ClnHold`, `ClnXpay`). When multiple nodes are online,
//! the highest-priority node is selected for operations.
//!
//! ## Actor pattern
//!
//! [`LightningManager`] is the public handle held by the rest of the server. It sends [`Ctrl`]
//! messages over an mpsc channel to [`LightningManagerProcess`], which runs as a tokio task.
//! Responses come back via oneshot channels embedded in the control messages.
//!
//! ## Routing
//!
//! `generate_invoice`/`settle_invoice`/`cancel_invoice` route to `ClnHold`.
//! `pay` routes to `ClnXpay`. `fetch_bolt12` calls CLN gRPC directly.
//! Intra-Ark payments short-circuit both paths: the manager updates the DB and
//! broadcasts the result without making a CLN round-trip.

pub(crate) mod hold;
mod notifier;
pub(crate) mod xpay;

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use cln_rpc::plugins::hold::hold_client::HoldClient;
use tokio::sync::{broadcast, Notify};
use tonic::transport::{Channel, Uri};
use tracing::{debug, error, info, warn};
use ark::lightning::PaymentHash;
use cln_rpc::node_client::NodeClient;

use crate::ln::node_manager::NodeState;
use crate::ln::settler::HtlcSettler;
use crate::sync::SyncManager;
use crate::system::RuntimeManager;
use crate::config;
use crate::database;
use crate::database::ln::LightningNodeId;
use crate::telemetry;

use self::hold::{ClnHold, ClnHoldConfig};
pub(crate) use self::notifier::PaymentAttemptNotifier;
use self::xpay::{ClnXpay, ClnXpayConfig};

type ClnGrpcClient = NodeClient<Channel>;

/// Cheap, cloneable command handle to a running node.
///
/// Returned by the manager's node getters so callers can issue RPCs to the
/// node directly instead of routing a command through the manager task. The
/// manager republishes these handles whenever node state changes, so a handle
/// reflects a node that was online as of the last maintenance pass.
#[derive(Clone, Debug)]
pub(crate) struct NodeHandle {
	pub(crate) priority: u8,
	rpc: ClnGrpcClient,
}

impl NodeHandle {
	/// A fresh clone of the node's gRPC client.
	pub(crate) fn rpc(&self) -> ClnGrpcClient {
		self.rpc.clone()
	}
}

#[derive(Debug)]
pub struct ClnNodeOnlineState {
	pub(crate) id: LightningNodeId,
	pub(crate) pubkey: PublicKey,
	pub(crate) rpc: ClnGrpcClient,
	pub(crate) hold_rpc: Option<HoldClient<Channel>>,
	// option so we can take() when marking as down
	pub(crate) monitor: Option<ClnHold>,
	pub(crate) xpay: Option<ClnXpay>,
}

impl ClnNodeOnlineState {
	/// Build a cloneable command handle for this node at the given priority.
	pub(crate) fn handle(&self, priority: u8) -> NodeHandle {
		NodeHandle {
			priority,
			rpc: self.rpc.clone(),
		}
	}
}

#[derive(Debug)]
pub struct ClnNodeInfo {
	pub(crate) uri: Uri,
	pub(crate) config: config::Lightningd,
	pub(crate) state: NodeState,
}

impl ClnNodeInfo {
	/// Set new status and print a log for the record.
	pub(crate) fn set_state(&mut self, new_state: NodeState) {
		let uri = &self.uri;
		if let NodeState::Invalid { ref msg } = new_state {
			error!("Marking CLN node with URI {uri} as invalid: {msg}");
		} else if let NodeState::Offline = new_state {
			warn!("Marking CLN node with URI {uri} as offline");
		} else {
			debug!("Setting status of CLN node with URI {uri}: {new_state}");
		}
		self.state = new_state;
	}

	pub(crate) async fn try_connect(
		&mut self,
		db: &database::Db,
		expected_network: bitcoin::Network,
		monitor_config: &ClnHoldConfig,
		xpay_config: &ClnXpayConfig,
		payment_update_tx: &broadcast::Sender<PaymentHash>,
		rtmgr: &RuntimeManager,
		waker: &Arc<Notify>,
		sync_manager: &Arc<SyncManager>,
		mailbox_manager: &Arc<crate::mailbox_manager::MailboxManager>,
		settler: &Arc<HtlcSettler>,
	) -> anyhow::Result<LightningNodeId> {
		let mut rpc = self.config.build_grpc_client().await.context("failed to connect rpc")?;
		let hold_rpc = self.config.build_hold_client().await.context("failed to connect hold rpc")?;

		let info = rpc.getinfo(cln_rpc::GetinfoRequest {}).await
			.context("failed to get info from rpc")?
			.into_inner();

		let network = bitcoin::Network::from_str(info.network.as_str())
			.context(NodeState::invalid("network invalid"))?;

		if network != expected_network {
			let msg = format!("network is {network} instead of {expected_network}");
			return Err(anyhow::Error::msg(msg.clone()).context(NodeState::invalid(msg)));
		}

		let pubkey = PublicKey::from_slice(&info.id.to_vec())
			.context(NodeState::invalid("malformed pubkey"))?;

		let (id, _) = db.write(async |t| t.register_lightning_node(&pubkey).await).await?;

		info!("Succesfully connected to cln node with uri {}", self.uri);
		let monitor = ClnHold::start(
			rtmgr.clone(),
			waker.clone(),
			db.clone(),
			payment_update_tx.clone(),
			id,
			hold_rpc.clone(),
			monitor_config.clone(),
			sync_manager.clone(),
			mailbox_manager.clone(),
		).await.context("failed to start ClnHold")?;

		let xpay = ClnXpay::start(
			rtmgr.clone(),
			waker.clone(),
			db.clone(),
			payment_update_tx.clone(),
			id,
			rpc.clone(),
			xpay_config.clone(),
			settler.clone(),
			mailbox_manager.clone(),
		).await.context("failed to start ClnXpay")?;

		let online = ClnNodeOnlineState {
			id, pubkey, rpc, hold_rpc,
			monitor: Some(monitor),
			xpay: Some(xpay),
		};
		let new_state = NodeState::Online(online);
		telemetry::set_lightning_node_state(
			self.uri.clone(), Some(id), Some(pubkey), new_state.kind(),
		);
		self.set_state(new_state);

		Ok(id)
	}
}
