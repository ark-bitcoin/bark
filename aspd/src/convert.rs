use crate::rpc;
use crate::round::RoundEvent;

impl From<RoundEvent> for rpc::RoundEvent {
	fn from(e: RoundEvent) -> Self {
		rpc::RoundEvent {
			event: Some(match e {
				RoundEvent::Start { round_id, offboard_feerate } => {
					rpc::round_event::Event::Start(rpc::RoundStart {
						round_id,
						offboard_feerate_sat_vkb: offboard_feerate.to_sat_per_kwu() * 4,
					})
				},
				RoundEvent::Attempt { round_id, attempt } => {
					rpc::round_event::Event::Attempt(rpc::RoundAttempt {
						round_id, attempt,
					})
				},
				RoundEvent::VtxoProposal {
					round_id, vtxos_spec, unsigned_round_tx, cosign_agg_nonces,
				} => {
					rpc::round_event::Event::VtxoProposal(rpc::VtxoProposal {
						round_id,
						vtxos_spec: vtxos_spec.encode(),
						unsigned_round_tx: bitcoin::consensus::serialize(&unsigned_round_tx),
						vtxos_agg_nonces: cosign_agg_nonces.into_iter()
							.map(|n| n.serialize().to_vec())
							.collect(),
					})
				},
				RoundEvent::RoundProposal { round_id, cosign_sigs, forfeit_nonces } => {
					rpc::round_event::Event::RoundProposal(rpc::RoundProposal {
						round_id,
						vtxo_cosign_signatures: cosign_sigs.into_iter()
							.map(|s| s.serialize().to_vec()).collect(),
						forfeit_nonces: forfeit_nonces.into_iter().map(|(id, nonces)| {
							rpc::ForfeitNonces {
								input_vtxo_id: id.to_bytes().to_vec(),
								pub_nonces: nonces.into_iter()
									.map(|n| n.serialize().to_vec())
									.collect(),
							}
						}).collect(),
					})
				},
				RoundEvent::Finished { round_id, signed_round_tx } => {
					rpc::round_event::Event::Finished(rpc::RoundFinished {
						round_id,
						signed_round_tx: bitcoin::consensus::serialize(&signed_round_tx.tx),
					})
				},
			})
		}
	}
}
