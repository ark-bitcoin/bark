
use std::fmt;
use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::{FeeRate, Transaction, Txid};
use bitcoin::secp256k1::schnorr;

use crate::{musig, VtxoId};
use crate::tree::signed::VtxoTreeSpec;



/// Identifier for a past round.
///
/// It is the txid of the round tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoundId(Txid);

impl RoundId {
	/// Create a new [RoundId] from the round tx's [Txid].
	pub const fn new(txid: Txid) -> RoundId {
		RoundId(txid)
	}

	pub fn from_slice(bytes: &[u8]) -> Result<RoundId, bitcoin::hashes::FromSliceError> {
		Txid::from_slice(bytes).map(RoundId::new)
	}

	pub fn as_round_txid(&self) -> Txid {
		self.0
	}
}

impl From<Txid> for RoundId {
	fn from(txid: Txid) -> RoundId {
		RoundId::new(txid)
	}
}

impl std::ops::Deref for RoundId {
	type Target = Txid;
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl fmt::Display for RoundId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl FromStr for RoundId {
	type Err = bitcoin::hashes::hex::HexToArrayError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Txid::from_str(s).map(RoundId::new)
	}
}

impl serde::Serialize for RoundId {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		if s.is_human_readable() {
			s.collect_str(self)
		} else {
			s.serialize_bytes(self.as_ref())
		}
	}
}

impl<'de> serde::Deserialize<'de> for RoundId {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = RoundId;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a RoundId, which is a Txid")
			}
			fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				RoundId::from_slice(v).map_err(serde::de::Error::custom)
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				RoundId::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		if d.is_human_readable() {
			d.deserialize_str(Visitor)
		} else {
			d.deserialize_bytes(Visitor)
		}
	}
}


#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start {
		round_seq: usize,
		offboard_feerate: FeeRate,
	},
	Attempt {
		round_seq: usize,
		attempt: u64,
	},
	VtxoProposal {
		round_seq: usize,
		unsigned_round_tx: Transaction,
		vtxos_spec: VtxoTreeSpec,
		cosign_agg_nonces: Vec<musig::MusigAggNonce>,
	},
	RoundProposal {
		round_seq: usize,
		cosign_sigs: Vec<schnorr::Signature>,
		forfeit_nonces: HashMap<VtxoId, Vec<musig::MusigPubNonce>>,
	},
	Finished {
		round_seq: usize,
		signed_round_tx: Transaction,
	},
}

/// A more concise way to display [RoundEvent].
impl fmt::Display for RoundEvent {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Start { round_seq, offboard_feerate } => {
				f.debug_struct("Start")
					.field("round_seq", round_seq)
					.field("offboard_feerate", offboard_feerate)
					.finish()
			},
			Self::Attempt { round_seq, attempt } => {
				f.debug_struct("Attempt")
					.field("round_seq", round_seq)
					.field("attempt", attempt)
					.finish()
			},
			Self::VtxoProposal { round_seq, unsigned_round_tx, .. } => {
				f.debug_struct("VtxoProposal")
					.field("round_seq", round_seq)
					.field("unsigned_round_txid", &unsigned_round_tx.compute_txid())
					.finish()
			},
			Self::RoundProposal { round_seq, .. } => {
				f.debug_struct("RoundProposal")
					.field("round_seq", round_seq)
					.finish()
			},
			Self::Finished { round_seq, signed_round_tx } => {
				f.debug_struct("Finished")
					.field("round_seq", round_seq)
					.field("signed_round_txid", &signed_round_tx.compute_txid())
					.finish()
			},
		}
	}
}
