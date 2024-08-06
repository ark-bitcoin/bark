
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
						id, vtxos_spec, round_tx, cosigners, cosign_agg_nonces,
					} => {
						rpc::round_event::Event::VtxoProposal(rpc::VtxoProposal {
							round_id: id,
							vtxos_spec: vtxos_spec.encode(),
							round_tx: bitcoin::consensus::serialize(&round_tx),
							vtxos_signers: cosigners.into_iter()
								.map(|k| k.serialize().to_vec())
								.collect(),
							vtxos_agg_nonces: cosign_agg_nonces.into_iter()
								.map(|n| n.serialize().to_vec())
								.collect(),
						})
					},
					RoundEvent::RoundProposal { id, vtxos, round_tx, forfeit_nonces } => {
						rpc::round_event::Event::RoundProposal(rpc::RoundProposal {
							round_id: id,
							signed_vtxos: vtxos.encode(),
							round_tx: bitcoin::consensus::serialize(&round_tx),
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
					RoundEvent::Finished { id, vtxos, round_tx } => {
						rpc::round_event::Event::Finished(rpc::RoundFinished {
							round_id: id,
							signed_vtxos: vtxos.encode(),
							round_tx: bitcoin::consensus::serialize(&round_tx),
						})
					},
				})
			}
		}
	}
}
