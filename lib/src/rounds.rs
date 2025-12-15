pub use crate::challenges::RoundAttemptChallenge;

use std::fmt;
use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::schnorr;

use crate::musig;
use crate::tree::signed::VtxoTreeSpec;

/// A round tx must have at least vtxo tree and connector chain outputs.
/// Can also have several offboard outputs on next indices.
pub const MIN_ROUND_TX_OUTPUTS: usize = 2;

/// The output index of the vtxo tree root in the round tx.
pub const ROUND_TX_VTXO_TREE_VOUT: u32 = 0;

/// Unique identifier for a round.
///
/// It is a simple sequence number.
///
/// It is used to identify a round before we have a round tx.
/// [RoundId] should be used as soon as we have a round tx.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoundSeq(u64);

impl RoundSeq {
	pub const fn new(seq: u64) -> Self {
		Self(seq)
	}

	pub fn increment(&mut self) {
		self.0 += 1;
	}

	pub fn inner(&self) -> u64 {
		self.0
	}
}

impl From<u64> for RoundSeq {
	fn from(v: u64) -> Self {
	    Self::new(v)
	}
}

impl From<RoundSeq> for u64 {
	fn from(v: RoundSeq) -> u64 {
	    v.0
	}
}

impl fmt::Display for RoundSeq {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
}

impl fmt::Debug for RoundSeq {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

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
pub struct RoundAttempt {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub challenge: RoundAttemptChallenge,
}

#[derive(Debug, Clone)]
pub struct VtxoProposal {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub unsigned_round_tx: Transaction,
	pub vtxos_spec: VtxoTreeSpec,
	pub cosign_agg_nonces: Vec<musig::AggregatedNonce>,
}

#[derive(Debug, Clone)]
pub struct RoundFinished {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub cosign_sigs: Vec<schnorr::Signature>,
	pub signed_round_tx: Transaction,
}

#[derive(Debug, Clone)]
pub enum RoundEvent {
	Attempt(RoundAttempt),
	VtxoProposal(VtxoProposal),
	Finished(RoundFinished),
}

impl RoundEvent {
	/// String representation of the kind of event
	pub fn kind(&self) -> &'static str {
		match self {
			Self::Attempt(_) => "RoundAttempt",
			Self::VtxoProposal { .. } => "VtxoProposal",
			Self::Finished { .. } => "Finished",
		}
	}

	pub fn round_seq(&self) -> RoundSeq {
		match self {
			Self::Attempt(e) => e.round_seq,
			Self::VtxoProposal(e) => e.round_seq,
			Self::Finished(e) => e.round_seq,
		}
	}

	pub fn attempt_seq(&self) -> usize {
		match self {
			Self::Attempt(e) => e.attempt_seq,
			Self::VtxoProposal(e) => e.attempt_seq,
			Self::Finished(e) => e.attempt_seq,
		}
	}
}

/// A more concise way to display [RoundEvent].
impl fmt::Display for RoundEvent {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Attempt(RoundAttempt { round_seq, attempt_seq, challenge }) => {
				f.debug_struct("RoundAttempt")
					.field("round_seq", round_seq)
					.field("attempt_seq", attempt_seq)
					.field("challenge", &challenge.inner().as_hex())
					.finish()
			},
			Self::VtxoProposal(VtxoProposal { round_seq, attempt_seq, unsigned_round_tx, .. }) => {
				f.debug_struct("VtxoProposal")
					.field("round_seq", round_seq)
					.field("attempt_seq", attempt_seq)
					.field("unsigned_round_txid", &unsigned_round_tx.compute_txid())
					.finish()
			},
			Self::Finished(RoundFinished {
				round_seq, attempt_seq, signed_round_tx, ..
			}) => {
				f.debug_struct("Finished")
					.field("round_seq", round_seq)
					.field("attempt_seq", attempt_seq)
					.field("signed_round_txid", &signed_round_tx.compute_txid())
					.finish()
			},
		}
	}
}
