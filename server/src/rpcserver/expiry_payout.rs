//! The public RPC of a server in expiry payout mode: the protocol version
//! gate, and the owner mailbox that the VTXO status reports.

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use tonic::service::interceptor::InterceptedService;

use ark::VtxoId;
use server_rpc::{self as rpc, RequestExt};

use crate::Server;
use crate::rpcserver::ToStatusResult;

/// Refuse a request that carries a protocol version below
/// [rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT], with the error that
/// any client that is too old for the server gets. Such a client does not
/// send the owner mailbox of its VTXOs.
///
/// A request without a version passes: the handshake carries none, and every
/// handler that depends on the version requires it.
fn require_expiry_payout_version(req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
	if req.try_pver()?.is_some_and(|pver| pver < rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT) {
		return badarg!("Your client version is too old, you need to update \
			in order to use expiry payouts.").to_status();
	}
	Ok(req)
}

/// The owner mailbox of VTXOs, as the VTXO status RPCs report it. Empty
/// when the server is not in payout mode.
#[derive(Default)]
pub(crate) struct VtxoPayouts {
	owners: BTreeMap<VtxoId, PublicKey>,
}

impl VtxoPayouts {
	pub(crate) fn owner_mailbox(&self, id: &VtxoId) -> Vec<u8> {
		self.owners.get(id).map(|owner| owner.serialize().to_vec()).unwrap_or_default()
	}
}

impl Server {
	pub(crate) async fn vtxo_payouts(&self, ids: &[VtxoId]) -> Result<VtxoPayouts, tonic::Status> {
		if !self.config.expiry_payouts {
			return Ok(VtxoPayouts::default());
		}
		self.db.read(async |t| {
			let owners = t.vtxo_owner_mailboxes(ids).await?;
			Ok(VtxoPayouts { owners })
		}).await.to_status()
	}
}

/// The public services of a server in payout mode: the Ark and mailbox
/// services behind [require_expiry_payout_version], and the health service.
pub(crate) fn routes(srv: &Arc<Server>) -> tonic::service::Routes {
	let (_, health_server) = tonic_health::server::health_reporter();
	tonic::service::Routes::default()
		.add_service(InterceptedService::new(
			rpc::server::ArkServiceServer::from_arc(srv.clone()), require_expiry_payout_version,
		))
		.add_service(InterceptedService::new(
			rpc::server::MailboxServiceServer::from_arc(srv.clone()), require_expiry_payout_version,
		))
		.add_service(health_server)
}

#[cfg(test)]
mod test {
	use super::*;

	fn with_pver(pver: Option<u64>) -> tonic::Request<()> {
		let mut req = tonic::Request::new(());
		if let Some(pver) = pver {
			req.set_pver(pver);
		}
		req
	}

	#[test]
	fn only_the_expiry_payout_version_passes() {
		let payout = rpc::pver::PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT;
		assert!(require_expiry_payout_version(with_pver(Some(payout))).is_ok());
		assert!(require_expiry_payout_version(with_pver(None)).is_ok());
		for pver in [rpc::MIN_PROTOCOL_VERSION, rpc::MAX_PROTOCOL_VERSION, payout - 1] {
			let status = require_expiry_payout_version(with_pver(Some(pver))).unwrap_err();
			assert_eq!(status.code(), tonic::Code::InvalidArgument);
			assert!(status.message().contains("Your client version is too old"), "{}", status.message());
		}
	}
}
