//! The public RPC of a server in expiry payout mode: the protocol version
//! gate, and the owner mailbox and payout that the VTXO status reports.

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use tonic::service::interceptor::InterceptedService;

use ark::VtxoId;
use ark::attestations::VtxoStatusAttestation;
use ark::tree::signed::UnlockHash;
use server_rpc::{self as rpc, protos, RequestExt};

use crate::Server;
use crate::database::expiry_payout::payout::{ExpiryPayoutReceipt, ExpiryPayoutState};
use crate::error::ExpiryPayoutRefusal;
use crate::rpcserver::{StatusContext, ToStatusResult};

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

/// The owner mailbox and the expiry payout of VTXOs, as the VTXO status
/// RPCs report them. Empty when the server is not in payout mode.
#[derive(Default)]
pub(crate) struct VtxoPayouts {
	owners: BTreeMap<VtxoId, PublicKey>,
	receipts: BTreeMap<VtxoId, ExpiryPayoutReceipt>,
}

impl VtxoPayouts {
	pub(crate) fn owner_mailbox(&self, id: &VtxoId) -> Vec<u8> {
		self.owners.get(id).map(|owner| owner.serialize().to_vec()).unwrap_or_default()
	}

	pub(crate) fn expiry_payout(&self, id: &VtxoId) -> Option<protos::ExpiryPayout> {
		self.receipts.get(id).copied().map(Into::into)
	}
}

impl From<ExpiryPayoutReceipt> for protos::ExpiryPayout {
	fn from(receipt: ExpiryPayoutReceipt) -> Self {
		let state = match receipt.state {
			ExpiryPayoutState::Pending => protos::ExpiryPayoutState::Pending,
			ExpiryPayoutState::Paid => protos::ExpiryPayoutState::Paid,
			ExpiryPayoutState::Forfeited => protos::ExpiryPayoutState::Forfeited,
		};
		protos::ExpiryPayout {
			state: state as i32,
			gross_sat: receipt.gross.to_sat(),
			fee_sat: receipt.fee.to_sat(),
			payout_sat: receipt.payout.to_sat(),
		}
	}
}

impl Server {
	pub(crate) async fn vtxo_payouts(&self, ids: &[VtxoId]) -> Result<VtxoPayouts, tonic::Status> {
		if !self.config.expiry_payouts {
			return Ok(VtxoPayouts::default());
		}
		self.db.read(async |t| {
			let owners = t.vtxo_owner_mailboxes(ids).await?;
			let receipts = t.expiry_payout_receipts(&owners).await?;
			Ok(VtxoPayouts { owners, receipts })
		}).await.to_status()
	}

	/// The status of a board that was co-signed but never registered. Its
	/// funding output is paid out under the board's own VTXO id.
	pub(crate) async fn unregistered_board_status(
		&self,
		id: VtxoId,
		attestation: &VtxoStatusAttestation,
	) -> Result<Option<protos::VtxoStatus>, tonic::Status> {
		if !self.config.expiry_payouts {
			return Ok(None);
		}
		let status = self.db.read(async |t| {
			let Some(board) = t.unregistered_board_status(id).await? else { return Ok(None) };
			let owners = BTreeMap::from([(board.root, board.mailbox)]);
			let receipt = t.expiry_payout_receipts(&owners).await?.get(&board.root).copied();
			Ok(Some((board, receipt)))
		}).await.to_status()?;
		let Some((board, receipt)) = status else { return Ok(None) };
		attestation.verify_key(id, board.user_pubkey).badarg("invalid VTXO status attestation")?;
		let spend_state = if board.onchain_spent || receipt.is_some() {
			protos::VtxoSpendState::Spent
		} else {
			protos::VtxoSpendState::Unregistered
		};
		Ok(Some(protos::VtxoStatus {
			vtxo_id: id.to_bytes().to_vec(),
			spend_state: spend_state as i32,
			owner_mailbox: board.mailbox.serialize().to_vec(),
			expiry_payout: receipt.map(Into::into),
		}))
	}

	/// Refuse the status of a round participation that an expiry payout
	/// cancelled.
	pub(crate) async fn check_participation_not_cancelled(
		&self,
		unlock_hash: UnlockHash,
	) -> Result<(), tonic::Status> {
		if self.db.read(async |t| t.participation_cancelled_for_payout(unlock_hash).await).await.to_status()? {
			let error = anyhow::Error::new(ExpiryPayoutRefusal::RoundCancelledBeforeForfeit(unlock_hash));
			return Err(error).to_status();
		}
		Ok(())
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
