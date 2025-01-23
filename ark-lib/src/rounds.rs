
use std::fmt;
use std::collections::HashMap;

use bitcoin::{FeeRate, Transaction};
use bitcoin::secp256k1::schnorr;

use crate::{musig, VtxoId};
use crate::tree::signed::VtxoTreeSpec;


#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start {
		round_id: u64,
		offboard_feerate: FeeRate,
	},
	Attempt {
		round_id: u64,
		attempt: u64,
	},
	VtxoProposal {
		round_id: u64,
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	},
	RoundProposal {
		round_id: u64,
		cosign_sigs: Vec<schnorr::Signature>,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		round_id: u64,
		signed_round_tx: Transaction,
	},
}

/// A more concise way to display [RoundEvent].
impl fmt::Display for RoundEvent {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Start { round_id, offboard_feerate } => {
				f.debug_struct("Start")
					.field("round_id", round_id)
					.field("offboard_feerate", offboard_feerate)
					.finish()
			},
			Self::Attempt { round_id, attempt } => {
				f.debug_struct("Attempt")
					.field("round_id", round_id)
					.field("attempt", attempt)
					.finish()
			},
			Self::VtxoProposal { round_id, unsigned_round_tx, .. } => {
				f.debug_struct("VtxoProposal")
					.field("round_id", round_id)
					.field("unsigned_round_txid", &unsigned_round_tx.compute_txid())
					.finish()
			},
			Self::RoundProposal { round_id, .. } => {
				f.debug_struct("RoundProposal")
					.field("round_id", round_id)
					.finish()
			},
			Self::Finished { round_id, signed_round_tx } => {
				f.debug_struct("Finished")
					.field("round_id", round_id)
					.field("signed_round_txid", &signed_round_tx.compute_txid())
					.finish()
			},
		}
	}
}
