
mod aspd;
pub use self::aspd::*;
pub use self::aspd::ark_service_server::{ArkService, ArkServiceServer};
pub use self::aspd::admin_service_server::{AdminService, AdminServiceServer};

mod convert {
	use crate::rpc;
	use crate::round::RoundEvent;

	impl From<RoundEvent> for rpc::RoundEvent {
		fn from(e: RoundEvent) -> Self {
			rpc::RoundEvent {
				event: Some(match e {
					RoundEvent::Start { id, offboard_feerate } => {
						rpc::round_event::Event::Start(rpc::RoundStart {
							round_id: id,
							offboard_feerate_sat_vkb: offboard_feerate.to_sat_per_kwu() * 4,
						})
					},
					RoundEvent::VtxoProposal {
						id, vtxos_spec, unsigned_round_tx, cosign_agg_nonces,
					} => {
						rpc::round_event::Event::VtxoProposal(rpc::VtxoProposal {
							round_id: id,
							vtxos_spec: vtxos_spec.encode(),
							unsigned_round_tx: bitcoin::consensus::serialize(&unsigned_round_tx),
							vtxos_agg_nonces: cosign_agg_nonces.into_iter()
								.map(|n| n.serialize().to_vec())
								.collect(),
						})
					},
					RoundEvent::RoundProposal { id, cosign_sigs, forfeit_nonces } => {
						rpc::round_event::Event::RoundProposal(rpc::RoundProposal {
							round_id: id,
							vtxo_cosign_signatures: cosign_sigs.into_iter()
								.map(|s| s.serialize().to_vec()).collect(),
							forfeit_nonces: forfeit_nonces.into_iter().map(|(id, nonces)| {
								rpc::ForfeitNonces {
									input_vtxo_id: id.bytes().to_vec(),
									pub_nonces: nonces.into_iter()
										.map(|n| n.serialize().to_vec())
										.collect(),
								}
							}).collect(),
						})
					},
					RoundEvent::Finished { id, signed_round_tx } => {
						rpc::round_event::Event::Finished(rpc::RoundFinished {
							round_id: id,
							signed_round_tx: bitcoin::consensus::serialize(&signed_round_tx.tx),
						})
					},
				})
			}
		}
	}

	impl From<ark::lightning::PaymentStatus> for rpc::PaymentStatus {
		fn from(value: ark::lightning::PaymentStatus) -> Self {
			match value {
				ark::lightning::PaymentStatus::Complete => rpc::PaymentStatus::Complete,
				ark::lightning::PaymentStatus::Pending => rpc::PaymentStatus::Pending,
				ark::lightning::PaymentStatus::Failed => rpc::PaymentStatus::Failed,
			}
		}
	}
}
