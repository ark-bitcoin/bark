//! CLN-specific node types: `ClnNodeInfo`, `ClnNodeOnlineState`, and the
//! cloneable [`NodeHandle`] returned by the manager's node getters.
//!
//! Each configured CLN node is tracked as a `ClnNodeInfo` with a state machine:
//! `Offline ↔ Online ↔ Error`, where `Invalid` and `Disabled` are terminal states.
//! The supervisor (see [`crate::ln::node_manager`]) reconnects offline/errored
//! nodes and watches `ClnHold`/`ClnXpay` for crashes. When multiple nodes are
//! online, the highest-priority node is selected for operations.
//!
//! `NodeHandle` carries the cheap RPC clients (gRPC, hold-plugin, xpay client)
//! and is what data-path operations on `LightningManager` use to talk to a
//! node directly. `ClnNodeOnlineState::handle` builds one from the live
//! online-state fields; the supervisor republishes them into the manager's
//! shared snapshot.

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
use self::xpay::{ClnXpay, ClnXpayClient, ClnXpayConfig};

type ClnGrpcClient = NodeClient<Channel>;

/// Cheap, cloneable command handle to a running node.
///
/// Returned by the manager's node getters so callers can issue RPCs to the
/// node directly instead of routing a command through the manager task. The
/// manager republishes these handles whenever node state changes, so a handle
/// reflects a node that was online as of the last maintenance pass.
#[derive(Clone)]
pub(crate) struct NodeHandle {
	pub(crate) id: LightningNodeId,
	pub(crate) priority: u8,
	pub(crate) rpc: ClnGrpcClient,
	pub(crate) hold_rpc: Option<HoldClient<Channel>>,
	pub(crate) xpay: Arc<ClnXpayClient>,
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
	///
	/// Online state always carries a live xpay monitor (check_nodes drops the
	/// node from Online if its monitor crashes before publish runs), so it is
	/// safe to expect it here.
	pub(crate) fn handle(&self, priority: u8) -> NodeHandle {
		NodeHandle {
			id: self.id,
			priority,
			rpc: self.rpc.clone(),
			hold_rpc: self.hold_rpc.clone(),
			xpay: self.xpay.as_ref().expect("online node has live xpay monitor").client(),
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
