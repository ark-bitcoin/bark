
use std::fmt;
use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{key::Keypair, FeeRate, Transaction, Txid};
use bitcoin::secp256k1::{self, schnorr, Message};

use crate::{musig, OffboardRequest, SECP, SignedVtxoRequest, Vtxo, VtxoId};
use crate::encode::ProtocolEncoding;
use crate::tree::signed::VtxoTreeSpec;

/// A round tx must have at least vtxo tree and connector chain outputs.
/// Can also have several offboard outputs on next indices.
pub const MIN_ROUND_TX_OUTPUTS: usize = 2;

/// The output index of the vtxo tree root in the round tx.
pub const ROUND_TX_VTXO_TREE_VOUT: u32 = 0;
/// The output index of the connector chain  start in the round tx.
pub const ROUND_TX_CONNECTOR_VOUT: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtxoOwnershipChallenge([u8; 32]);

impl VtxoOwnershipChallenge {
	const CHALENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark round input ownership proof ";

	pub fn new(value: [u8; 32]) -> Self {
		Self(value)
	}

	pub fn generate() -> Self {
		Self(rand::random())
	}

	pub fn inner(&self) -> [u8; 32] {
		self.0
	}

	/// Combines [VtxoOwnershipChallenge] and [VtxoId] in a signable message
	///
	/// Note: because we use [`VtxoId`] in the message, there is no
	fn as_signable_message(&self, vtxo_id: VtxoId, vtxo_reqs: &[SignedVtxoRequest], offboard_reqs: &[OffboardRequest]) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&self.0).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&vtxo_reqs.len().to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.vtxo.amount.to_sat().to_be_bytes()).unwrap();
			req.vtxo.policy.encode(&mut engine).unwrap();
			req.cosign_pubkey.encode(&mut engine).unwrap();
		}

		engine.write_all(&offboard_reqs.len().to_be_bytes()).unwrap();
		for req in offboard_reqs {
			req.to_txout().encode(&mut engine).unwrap();
		}
		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(&self, vtxo_id: VtxoId, vtxo_reqs: &[SignedVtxoRequest], offboard_reqs: &[OffboardRequest], vtxo_keypair: Keypair) -> schnorr::Signature {
		SECP.sign_schnorr(&self.as_signable_message(vtxo_id, vtxo_reqs, offboard_reqs), &vtxo_keypair)
	}

	pub fn verify_input_vtxo_sig(
		&self,
		vtxo: &Vtxo,
		vtxo_reqs: &[SignedVtxoRequest],
		offboard_reqs: &[OffboardRequest],
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		SECP.verify_schnorr(
			sig,
			&self.as_signable_message(vtxo.id(), vtxo_reqs, offboard_reqs),
			&vtxo.user_pubkey().x_only_public_key().0,
		)
	}
}

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
pub struct RoundInfo {
	pub round_seq: RoundSeq,
	pub offboard_feerate: FeeRate,
}

#[derive(Debug, Clone)]
pub struct RoundAttempt {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub challenge: VtxoOwnershipChallenge,
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
pub struct RoundProposal {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub cosign_sigs: Vec<schnorr::Signature>,
	pub forfeit_nonces: HashMap<VtxoId, Vec<musig::PublicNonce>>,
	pub connector_pubkey: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RoundFinished {
	pub round_seq: RoundSeq,
	pub attempt_seq: usize,
	pub signed_round_tx: Transaction,
}

#[derive(Debug, Clone)]
pub enum RoundEvent {
	Start(RoundInfo),
	Attempt(RoundAttempt),
	VtxoProposal(VtxoProposal),
	RoundProposal(RoundProposal),
	Finished(RoundFinished),
}

impl RoundEvent {
	pub fn round_seq(&self) -> RoundSeq {
		match self {
			Self::Start(e) => e.round_seq,
			Self::Attempt(e) => e.round_seq,
			Self::VtxoProposal(e) => e.round_seq,
			Self::RoundProposal(e) => e.round_seq,
			Self::Finished(e) => e.round_seq,
		}
	}
}

/// A more concise way to display [RoundEvent].
impl fmt::Display for RoundEvent {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Start(RoundInfo { round_seq, offboard_feerate }) => {
				f.debug_struct("Start")
					.field("round_seq", round_seq)
					.field("offboard_feerate", offboard_feerate)
					.finish()
			},
			Self::Attempt(RoundAttempt { round_seq, attempt_seq, challenge }) => {
				f.debug_struct("Attempt")
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
			Self::RoundProposal(RoundProposal { round_seq, attempt_seq, connector_pubkey, .. }) => {
				f.debug_struct("RoundProposal")
					.field("round_seq", round_seq)
					.field("attempt_seq", attempt_seq)
					.field("connector_pubkey", &connector_pubkey)
					.finish()
			},
			Self::Finished(RoundFinished { round_seq, attempt_seq, signed_round_tx }) => {
				f.debug_struct("Finished")
					.field("round_seq", round_seq)
					.field("attempt_seq", attempt_seq)
					.field("signed_round_txid", &signed_round_tx.compute_txid())
					.finish()
			},
		}
	}
}
