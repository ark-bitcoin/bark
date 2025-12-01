//! Representations of VTXOs in an Ark.


// # The internal representation of VTXOs.
//
// The [Vtxo] type is a struct that exposes a public API through methods, but
// we have deliberately decided to hide all its internal representation from
// the user.
//
// ## Objectives
//
// The objectives of the internal structure of [Vtxo] are the following:
// - have a stable encoding and decoding through [ProtocolEncoding]
// - enable constructing all exit transactions required to perform a
//   unilateral exit for the VTXO
// - enable a user to validate that the exit transaction chain is safe,
//   meaning that there are no unexpected spend paths that could break
//   the exit. this means that
//   - all transitions between transactions (i.e. where a child spends its
//     parent) have only known spend paths and no malicious additional ones
//   - all outputs of all exit transactions are standard, so they can be
//     relayed on the public relay network
//   - the necessary fee anchors are in place to allow the user to fund his
//     exit
//
// ## Internal structure
//
// Each [Vtxo] has what we call a "chain anchor" and a "genesis". The chain
// anchor is the transaction that is to be confirmed on-chain to anchor the
// VTXO's existence into the chain. The genesis represents the data required
// to "conceive" the [Vtxo]'s UTXO on the chain, connected to the chain anchor.
// Conceptually, the genesis data consists of two main things:
// - the output policy data and input witness data for each transition.
//   This ensures we can validate the policy used for the transition and we have
//   the necessary data to satisfy it.
// - the additional output data to reconstruct the transactions in full
//   (since our own transition is just one of the outputs)
//
// Since an exit of N transactions has N times the tx construction data,
// but N+1 times the transition policy data, we decided to structure the
// genesis series as follows:
//
// The genesis consists of "genesis items", which contain:
// - the output policy of the previous output (of the parent)
// - the witness to satisfy this policy
// - the additional output data to construct an exit tx
//
// This means that
// - there are an equal number of genesis items as there are exit transactions
// - the first item will hold the output policy of the chain anchor
// - to construct the output of the exit tx at a certain level, we get the
//   output policy from the next genesis item
// - the last tx's output policy is not held in the genesis, but it is held as
//   the VTXO's own output policy

pub mod policy;
pub(crate) mod genesis;
mod validation;

pub use self::validation::VtxoValidationError;
pub use self::policy::{VtxoPolicy, VtxoPolicyKind};
pub(crate) use self::genesis::{GenesisItem, GenesisTransition};

pub use self::policy::{
	PubkeyVtxoPolicy, CheckpointVtxoPolicy, ServerHtlcRecvVtxoPolicy,
	ServerHtlcSendVtxoPolicy
};
pub use self::policy::clause::{
	VtxoClause, DelayedSignClause, DelayedTimelockSignClause, HashDelaySignClause,
	TapScriptClause,
};

use std::collections::HashSet;
use std::iter::FusedIterator;
use std::{fmt, io};
use std::str::FromStr;

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};

use bitcoin_ext::{fee, BlockDelta, BlockHeight, TxOutExt};

use crate::{musig, scripts};
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::lightning::PaymentHash;
use crate::tree::signed::{UnlockHash, UnlockPreimage};

/// The total signed tx weight of a exit tx.
pub const EXIT_TX_WEIGHT: Weight = Weight::from_vb_unchecked(124);

/// The current version of the vtxo encoding.
const VTXO_ENCODING_VERSION: u16 = 1;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("failed to parse vtxo id, must be 36 bytes")]
pub struct VtxoIdParseError;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoId([u8; 36]);

impl VtxoId {
	/// Size in bytes of an encoded [VtxoId].
	pub const ENCODE_SIZE: usize = 36;

	pub fn from_slice(b: &[u8]) -> Result<VtxoId, VtxoIdParseError> {
		if b.len() == 36 {
			let mut ret = [0u8; 36];
			ret[..].copy_from_slice(&b[0..36]);
			Ok(Self(ret))
		} else {
			Err(VtxoIdParseError)
		}
	}

	pub fn utxo(self) -> OutPoint {
		let vout = [self.0[32], self.0[33], self.0[34], self.0[35]];
		OutPoint::new(Txid::from_slice(&self.0[0..32]).unwrap(), u32::from_le_bytes(vout))
	}

	pub fn to_bytes(self) -> [u8; 36] {
		self.0
	}
}

impl From<OutPoint> for VtxoId {
	fn from(p: OutPoint) -> VtxoId {
		let mut ret = [0u8; 36];
		ret[0..32].copy_from_slice(&p.txid[..]);
		ret[32..].copy_from_slice(&p.vout.to_le_bytes());
		VtxoId(ret)
	}
}

impl AsRef<[u8]> for VtxoId {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl fmt::Display for VtxoId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(&self.utxo(), f)
	}
}

impl fmt::Debug for VtxoId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl FromStr for VtxoId {
	type Err = VtxoIdParseError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(OutPoint::from_str(s).map_err(|_| VtxoIdParseError)?.into())
	}
}

impl serde::Serialize for VtxoId {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		if s.is_human_readable() {
			s.collect_str(self)
		} else {
			s.serialize_bytes(self.as_ref())
		}
	}
}

impl<'de> serde::Deserialize<'de> for VtxoId {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = VtxoId;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a VtxoId")
			}
			fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				VtxoId::from_slice(v).map_err(serde::de::Error::custom)
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				VtxoId::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		if d.is_human_readable() {
			d.deserialize_str(Visitor)
		} else {
			d.deserialize_bytes(Visitor)
		}
	}
}

impl ProtocolEncoding for VtxoId {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.0)
	}
	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let array: [u8; 36] = r.read_byte_array()
			.map_err(|_| ProtocolDecodingError::invalid("invalid vtxo id. Expected 36 bytes"))?;

		Ok(VtxoId(array))
	}
}

/// Returns the clause to unilaterally spend a VTXO
pub(crate) fn exit_clause(
	user_pubkey: PublicKey,
	exit_delta: BlockDelta,
) -> ScriptBuf {
	scripts::delayed_sign(exit_delta, user_pubkey.x_only_public_key().0)
}

/// Create an exit tx.
///
/// When the `signature` argument is provided,
/// it will be placed in the input witness.
pub fn create_exit_tx(
	prevout: OutPoint,
	output: TxOut,
	signature: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: prevout,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: {
				let mut ret = Witness::new();
				if let Some(sig) = signature {
					ret.push(&sig[..]);
				}
				ret
			},
		}],
		output: vec![output, fee::fee_anchor()],
	}
}

/// Enum type used to represent a preimage<>hash relationship
/// for which the preimage might be known but the hash always
/// should be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaybePreimage {
	Preimage([u8; 32]),
	Hash(sha256::Hash),
}

impl MaybePreimage {
	/// Get the hash
	pub fn hash(&self) -> sha256::Hash {
		match self {
			Self::Preimage(p) => sha256::Hash::hash(p),
			Self::Hash(h) => *h,
		}
	}
}

/// Type of the items yielded by [VtxoTxIter], the iterator returned by
/// [Vtxo::transactions].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VtxoTxIterItem {
	/// The actual transaction.
	pub tx: Transaction,
	/// The index of the relevant output of this tx
	pub output_idx: usize,
}

/// Iterator returned by [Vtxo::transactions].
pub struct VtxoTxIter<'a> {
	vtxo: &'a Vtxo,

	prev: OutPoint,
	genesis_idx: usize,
	current_amount: Amount,
	done: bool,
}

impl<'a> VtxoTxIter<'a> {
	fn new(vtxo: &'a Vtxo) -> VtxoTxIter<'a> {
		// Add all the amounts that go into the other outputs.
		let onchain_amount = vtxo.amount() + vtxo.genesis.iter().map(|i| {
			i.other_outputs.iter().map(|o| o.value).sum()
		}).sum();
		VtxoTxIter {
			prev: vtxo.anchor_point,
			vtxo: vtxo,
			genesis_idx: 0,
			current_amount: onchain_amount,
			done: false,
		}
	}
}

impl<'a> Iterator for VtxoTxIter<'a> {
	type Item = VtxoTxIterItem;

	fn next(&mut self) -> Option<Self::Item> {
		if self.done {
			return None;
		}

		let item = self.vtxo.genesis.get(self.genesis_idx).expect("broken impl");
		let next_amount = self.current_amount.checked_sub(
			item.other_outputs.iter().map(|o| o.value).sum()
		).expect("we calculated this amount beforehand");

		let next_output = if let Some(item) = self.vtxo.genesis.get(self.genesis_idx + 1) {
			item.transition.input_txout(
				next_amount,
				self.vtxo.server_pubkey,
				self.vtxo.expiry_height,
				self.vtxo.exit_delta,
			)
		} else {
			// when we reach the end of the chain, we take the eventual output of the vtxo
			self.done = true;
			self.vtxo.policy.txout(self.vtxo.amount, self.vtxo.server_pubkey, self.vtxo.exit_delta, self.vtxo.expiry_height)
		};

		let tx = item.tx(self.prev, next_output, self.vtxo.server_pubkey, self.vtxo.expiry_height);
		self.prev = OutPoint::new(tx.compute_txid(), item.output_idx as u32);
		self.genesis_idx += 1;
		self.current_amount = next_amount;
		let output_idx = item.output_idx as usize;
		Some(VtxoTxIterItem { tx, output_idx })
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let len = self.vtxo.genesis.len().saturating_sub(self.genesis_idx);
		(len, Some(len))
	}
}

impl<'a> ExactSizeIterator for VtxoTxIter<'a> {}
impl<'a> FusedIterator for VtxoTxIter<'a> {}


/// Information that specifies a VTXO, independent of its origin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoSpec {
	pub policy: VtxoPolicy,
	pub amount: Amount,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: BlockDelta,
}

impl VtxoSpec {
	/// The taproot spend info for the output of this [Vtxo].
	pub fn output_taproot(&self) -> taproot::TaprootSpendInfo {
		self.policy.taproot(self.server_pubkey, self.exit_delta, self.expiry_height)
	}

	/// The scriptPubkey of the output of this [Vtxo].
	pub fn output_script_pubkey(&self) -> ScriptBuf {
		self.policy.script_pubkey(self.server_pubkey, self.exit_delta, self.expiry_height)
	}

	/// The transaction output (eventual UTXO) of this [Vtxo].
	pub fn txout(&self) -> TxOut {
		self.policy.txout(self.amount, self.server_pubkey, self.exit_delta, self.expiry_height)
	}
}

/// Represents a VTXO in the Ark.
///
/// The correctness of the return values of methods on this type is conditional
/// on the VTXO being valid. For invalid VTXOs, the methods should never panic,
/// but can return incorrect values.
/// It is advised to always validate a VTXO upon receipt using [Vtxo::validate].
///
/// Be mindful of calling [Clone] on a [Vtxo], as they can be of
/// non-negligible size. It is advised to use references where possible
/// or use an [std::rc::Rc] or [std::sync::Arc] if needed.
///
/// Implementations of [PartialEq], [Eq], [PartialOrd], [Ord] and [Hash] are
/// proxied to the implementation on [Vtxo::id].
#[derive(Debug, Clone)]
pub struct Vtxo {
	pub(crate) policy: VtxoPolicy,
	pub(crate) amount: Amount,
	pub(crate) expiry_height: BlockHeight,

	pub(crate) server_pubkey: PublicKey,
	pub(crate) exit_delta: BlockDelta,

	pub(crate) anchor_point: OutPoint,
	pub(crate) genesis: Vec<genesis::GenesisItem>,

	/// The resulting actual "point" of the VTXO. I.e. the output of the last
	/// exit tx of this VTXO.
	///
	/// We keep this for two reasons:
	/// - the ID is based on this, so it should be cheaply accessible
	/// - it forms as a good checksum for all the internal genesis data
	pub(crate) point: OutPoint,
}

impl Vtxo {
	/// Get the identifier for this [Vtxo].
	///
	/// This is the same as [Vtxo::point] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		self.point.into()
	}

	/// Get the spec for this VTXO.
	pub fn spec(&self) -> VtxoSpec {
		VtxoSpec {
			policy: self.policy.clone(),
			amount: self.amount,
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
		}
	}

	/// The outpoint from which to build forfeit or arkoor txs.
	///
	/// This can be an on-chain utxo or an off-chain vtxo.
	pub fn point(&self) -> OutPoint {
		self.point
	}

	/// The amount of the [Vtxo].
	pub fn amount(&self) -> Amount {
		self.amount
	}

	/// The UTXO that should be confirmed for this [Vtxo] to be valid.
	///
	/// It is the very root of the VTXO.
	pub fn chain_anchor(&self) -> OutPoint {
		self.anchor_point
	}

	/// The output policy of this VTXO.
	pub fn policy(&self) -> &VtxoPolicy {
		&self.policy
	}

	/// The output policy type of this VTXO.
	pub fn policy_type(&self) -> VtxoPolicyKind {
		self.policy.policy_type()
	}

	/// The expiry height of the [Vtxo].
	pub fn expiry_height(&self) -> BlockHeight {
		self.expiry_height
	}

	/// The server pubkey used in arkoor transitions.
	pub fn server_pubkey(&self) -> PublicKey {
		self.server_pubkey
	}

	/// The relative timelock block delta used for exits.
	pub fn exit_delta(&self) -> BlockDelta {
		self.exit_delta
	}

	/// Returns the total exit depth (including OOR depth) of the vtxo.
	pub fn exit_depth(&self) -> u16 {
		self.genesis.len() as u16
	}

	/// The public key used to cosign arkoor txs spending this [Vtxo].
	/// This will return [None] if [VtxoPolicy::is_arkoor_compatible] returns false
	/// for this VTXO's policy.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		self.policy.arkoor_pubkey()
	}

	/// Iterate over all arkoor pubkeys in the arkoor chain of this vtxo.
	///
	/// This does not include the current arkoor pubkey, for that use
	/// [Vtxo::arkoor_pubkey].
	pub fn past_arkoor_pubkeys(&self) -> impl Iterator<Item = PublicKey> + '_ {
		self.genesis.iter().filter_map(|g| {
			match &g.transition {
				// NB in principle, a genesis item's transition MUST have
				// an arkoor pubkey, otherwise the vtxo is invalid
				GenesisTransition::Arkoor(inner) => inner.policy.arkoor_pubkey(),
				_ => None,
			}
		})
	}


	/// Returns the user pubkey associated with this [Vtxo].
	pub fn user_pubkey(&self) -> PublicKey {
		self.policy.user_pubkey()
	}

	/// Return the aggregate pubkey of the user and server pubkey used in
	/// hArk forfeit transactions
	pub(crate) fn forfeit_agg_pubkey(&self) -> XOnlyPublicKey {
		let ret = musig::combine_keys([self.user_pubkey(), self.server_pubkey()]);
		debug_assert_eq!(ret, self.output_taproot().internal_key());
		ret
	}

	/// The taproot spend info for the output of this [Vtxo].
	pub fn output_taproot(&self) -> taproot::TaprootSpendInfo {
		self.policy.taproot(self.server_pubkey, self.exit_delta, self.expiry_height)
	}

	/// The scriptPubkey of the output of this [Vtxo].
	pub fn output_script_pubkey(&self) -> ScriptBuf {
		self.policy.script_pubkey(self.server_pubkey, self.exit_delta, self.expiry_height)
	}

	/// The transaction output (eventual UTXO) of this [Vtxo].
	pub fn txout(&self) -> TxOut {
		self.policy.txout(self.amount, self.server_pubkey, self.exit_delta, self.expiry_height)
	}

	/// Whether this VTXO is fully signed
	///
	/// It is possible to represent unsigned VTXOs, for which this method
	/// will return false.
	pub fn is_fully_signed(&self) -> bool {
		self.genesis.iter().all(|g| g.transition.is_fully_signed())
	}

	/// Iterator that constructs all the exit txs for this [Vtxo].
	pub fn transactions(&self) -> VtxoTxIter<'_> {
		VtxoTxIter::new(self)
	}

	/// The set of all arkoor pubkeys present in the arkoor part
	/// of the VTXO exit path.
	pub fn arkoor_pubkeys(&self) -> HashSet<PublicKey> {
		self.genesis.iter().filter_map(|i| match &i.transition {
			GenesisTransition::Arkoor(inner) => inner.policy.arkoor_pubkey(),
			GenesisTransition::Cosigned(_) => None,
			GenesisTransition::HashLockedCosigned(_) => None,
		}).collect()
	}

	/// Check if this VTXO is standard for relay purposes
	///
	/// A VTXO is standard if:
	/// - Its own output is standard
	/// - all sibling outputs in the exit path are standard
	pub fn is_standard(&self) -> bool {
		self.txout().is_standard() && self.genesis.iter()
			.all(|i| i.other_outputs.iter().all(|o| o.is_standard()))
	}

	/// Fully validate this VTXO and its entire transaction chain.
	///
	/// The `chain_anchor_tx` must be the tx with txid matching
	/// [Vtxo::chain_anchor].
	pub fn validate(
		&self,
		chain_anchor_tx: &Transaction,
	) -> Result<(), VtxoValidationError> {
		self::validation::validate(&self, chain_anchor_tx)
	}

	/// Returns the "hArk" unlock hash if this is a hArk leaf VTXO
	pub fn unlock_hash(&self) -> Option<UnlockHash> {
		match self.genesis.last()?.transition {
			GenesisTransition::HashLockedCosigned(ref inner) => Some(inner.unlock.hash()),
			_ => None,
		}
	}

	/// Provide the leaf signature for an unfinalized hArk VTXO
	///
	/// Returns true if this VTXO was an unfinalized hArk VTXO.
	pub fn provide_unlock_signature(&mut self, signature: schnorr::Signature) -> bool {
		match self.genesis.last_mut().map(|g| &mut g.transition) {
			Some(GenesisTransition::HashLockedCosigned(inner)) => {
				inner.signature.replace(signature);
				true
			},
			_ => false,
		}
	}

	/// Provide the unlock preimage for an unfinalized hArk VTXO
	///
	/// Returns true if this VTXO was an unfinalized hArk VTXO and the preimage matched.
	pub fn provide_unlock_preimage(&mut self, preimage: UnlockPreimage) -> bool {
		match self.genesis.last_mut().map(|g| &mut g.transition) {
			Some(GenesisTransition::HashLockedCosigned(ref mut inner)) => {
				if inner.unlock.hash() == UnlockHash::hash(&preimage) {
					inner.unlock = MaybePreimage::Preimage(preimage);
					true
				} else {
					false
				}
			},
			_ => false,
		}
	}

	/// Shortcut to fully finalize a hark leaf using both keys
	#[cfg(any(test, feature = "test-util"))]
	pub fn finalize_hark_leaf(
		&mut self,
		user_key: &bitcoin::secp256k1::Keypair,
		server_key: &bitcoin::secp256k1::Keypair,
		chain_anchor: &Transaction,
		unlock_preimage: UnlockPreimage,
	) {
		use crate::tree::signed::{LeafVtxoCosignContext, LeafVtxoCosignResponse};

		// first sign and provide the signature
		let (ctx, req) = LeafVtxoCosignContext::new(self, chain_anchor, user_key);
		let cosign = LeafVtxoCosignResponse::new_cosign(&req, self, chain_anchor, server_key);
		assert!(ctx.finalize(self, cosign));
		// then provide preimage
		assert!(self.provide_unlock_preimage(unlock_preimage));
	}
}

impl PartialEq for Vtxo {
	fn eq(&self, other: &Self) -> bool {
		PartialEq::eq(&self.id(), &other.id())
	}
}

impl Eq for Vtxo {}

impl PartialOrd for Vtxo {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		PartialOrd::partial_cmp(&self.id(), &other.id())
	}
}

impl Ord for Vtxo {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		Ord::cmp(&self.id(), &other.id())
	}
}

impl std::hash::Hash for Vtxo {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		std::hash::Hash::hash(&self.id(), state)
	}
}

impl AsRef<Vtxo> for Vtxo {
	fn as_ref(&self) -> &Vtxo {
	    self
	}
}

/// Implemented on anything that is kinda a [Vtxo]
pub trait VtxoRef {
	/// The [VtxoId] of the VTXO
	fn vtxo_id(&self) -> VtxoId;

	/// If the [Vtxo] can be provided, provides it
	fn vtxo(&self) -> Option<&Vtxo>;
}

impl VtxoRef for VtxoId {
	fn vtxo_id(&self) -> VtxoId { *self }
	fn vtxo(&self) -> Option<&Vtxo> { None }
}

impl<'a> VtxoRef for &'a VtxoId {
	fn vtxo_id(&self) -> VtxoId { **self }
	fn vtxo(&self) -> Option<&Vtxo> { None }
}

impl VtxoRef for Vtxo {
	fn vtxo_id(&self) -> VtxoId { self.id() }
	fn vtxo(&self) -> Option<&Vtxo> { Some(self) }
}

impl<'a> VtxoRef for &'a Vtxo {
	fn vtxo_id(&self) -> VtxoId { self.id() }
	fn vtxo(&self) -> Option<&Vtxo> { Some(*self) }
}

/// The byte used to encode the [VtxoPolicy::Pubkey] output type.
const VTXO_POLICY_PUBKEY: u8 = 0x00;

/// The byte used to encode the [VtxoPolicy::ServerHtlcSend] output type.
const VTXO_POLICY_SERVER_HTLC_SEND: u8 = 0x01;

/// The byte used to encode the [VtxoPolicy::ServerHtlcRecv] output type.
const VTXO_POLICY_SERVER_HTLC_RECV: u8 = 0x02;

/// The byte used to encode the [VtxoPolicy::Checkpoint] output type.
const VTXO_CHECKPOINT_CHECKPOINT: u8 = 0x03;

impl ProtocolEncoding for VtxoPolicy {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				w.emit_u8(VTXO_POLICY_PUBKEY)?;
				user_pubkey.encode(w)?;
			},
			Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }) => {
				w.emit_u8(VTXO_CHECKPOINT_CHECKPOINT)?;
				user_pubkey.encode(w)?;
			},
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				w.emit_u8(VTXO_POLICY_SERVER_HTLC_SEND)?;
				user_pubkey.encode(w)?;
				payment_hash.to_sha256_hash().encode(w)?;
				w.emit_u32(*htlc_expiry)?;
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy {
				user_pubkey, payment_hash, htlc_expiry, htlc_expiry_delta,
			}) => {
				w.emit_u8(VTXO_POLICY_SERVER_HTLC_RECV)?;
				user_pubkey.encode(w)?;
				payment_hash.to_sha256_hash().encode(w)?;
				w.emit_u32(*htlc_expiry)?;
				w.emit_u16(*htlc_expiry_delta)?;
			},
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		match r.read_u8()? {
			VTXO_POLICY_PUBKEY => {
				let user_pubkey = PublicKey::decode(r)?;
				Ok(Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }))
			},
			VTXO_CHECKPOINT_CHECKPOINT => {
				let user_pubkey = PublicKey::decode(r)?;
				Ok(Self::new_checkpoint(user_pubkey))
			}
			VTXO_POLICY_SERVER_HTLC_SEND => {
				let user_pubkey = PublicKey::decode(r)?;
				let payment_hash = PaymentHash::from(sha256::Hash::decode(r)?.to_byte_array());
				let htlc_expiry = r.read_u32()?;
				Ok(Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }))
			},
			VTXO_POLICY_SERVER_HTLC_RECV => {
				let user_pubkey = PublicKey::decode(r)?;
				let payment_hash = PaymentHash::from(sha256::Hash::decode(r)?.to_byte_array());
				let htlc_expiry = r.read_u32()?;
				let htlc_expiry_delta = r.read_u16()?;
				Ok(Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry, htlc_expiry_delta }))
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid VtxoType type byte: {v:#x}",
			))),
		}
	}
}

/// The byte used to encode the [GenesisTransition::Cosigned] gen transition type.
const GENESIS_TRANSITION_TYPE_COSIGNED: u8 = 1;

/// The byte used to encode the [GenesisTransition::Arkoor] gen transition type.
const GENESIS_TRANSITION_TYPE_ARKOOR: u8 = 2;

/// The byte used to encode the [GenesisTransition::HashLockedCosigned] gen transition type.
const GENESIS_TRANSITION_TYPE_HASH_LOCKED_COSIGNED: u8 = 3;

impl ProtocolEncoding for GenesisTransition {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Cosigned(t) => {
				w.emit_u8(GENESIS_TRANSITION_TYPE_COSIGNED)?;
				w.emit_u16(t.pubkeys.len().try_into().expect("cosign pubkey length overflow"))?;
				for pk in t.pubkeys.iter() {
					pk.encode(w)?;
				}
				t.signature.encode(w)?;
			},
			Self::HashLockedCosigned(t) => {
				w.emit_u8(GENESIS_TRANSITION_TYPE_HASH_LOCKED_COSIGNED)?;
				t.user_pubkey.encode(w)?;
				t.signature.encode(w)?;
				match t.unlock {
					MaybePreimage::Preimage(p) => {
						w.emit_u8(0)?;
						w.emit_slice(&p[..])?;
					},
					MaybePreimage::Hash(h) => {
						w.emit_u8(1)?;
						w.emit_slice(&h[..])?;
					},
				}
			},
			Self::Arkoor(t) => {
				w.emit_u8(GENESIS_TRANSITION_TYPE_ARKOOR)?;
				t.policy.encode(w)?;
				t.signature.encode(w)?;
			},
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		match r.read_u8()? {
			GENESIS_TRANSITION_TYPE_COSIGNED => {
				let nb_pubkeys = r.read_u16()? as usize;
				let mut pubkeys = Vec::with_capacity(nb_pubkeys);
				for _ in 0..nb_pubkeys {
					pubkeys.push(PublicKey::decode(r)?);
				}
				let signature = schnorr::Signature::decode(r)?;
				Ok(Self::new_cosigned(pubkeys, signature))
			},
			GENESIS_TRANSITION_TYPE_HASH_LOCKED_COSIGNED => {
				let user_pubkey = PublicKey::decode(r)?;
				let signature = Option::<schnorr::Signature>::decode(r)?;
				let unlock = match r.read_u8()? {
					0 => MaybePreimage::Preimage(r.read_byte_array()?),
					1 => MaybePreimage::Hash(ProtocolEncoding::decode(r)?),
					v => return Err(ProtocolDecodingError::invalid(format_args!(
						"invalid HashLockedCosignedTransitionWitness type byte: {v:#x}",
					))),
				};
				Ok(Self::new_hash_locked_cosigned(user_pubkey, signature, unlock))
			},
			GENESIS_TRANSITION_TYPE_ARKOOR => {
				let policy = VtxoPolicy::decode(r)?;
				let signature = Option::<schnorr::Signature>::decode(r)?;
				Ok(Self::new_arkoor(policy, signature))
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid GenesisTransistion type byte: {v:#x}",
			))),
		}
	}
}

impl ProtocolEncoding for Vtxo {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_u16(VTXO_ENCODING_VERSION)?;
		w.emit_u64(self.amount.to_sat())?;
		w.emit_u32(self.expiry_height)?;
		self.server_pubkey.encode(w)?;
		w.emit_u16(self.exit_delta)?;
		self.anchor_point.encode(w)?;

		w.emit_u8(self.genesis.len().try_into().expect("genesis length overflow"))?;
		for item in &self.genesis {
			item.transition.encode(w)?;
			let nb_outputs = item.other_outputs.len() + 1;
			w.emit_u8(nb_outputs.try_into().expect("genesis item output length overflow"))?;
			w.emit_u8(item.output_idx)?;
			for txout in &item.other_outputs {
				txout.encode(w)?;
			}
		}

		self.policy.encode(w)?;
		self.point.encode(w)?;
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let version = r.read_u16()?;
		if version != VTXO_ENCODING_VERSION {
			return Err(ProtocolDecodingError::invalid(format_args!(
				"invalid Vtxo encoding version byte: {version:#x}",
			)));
		}

		let amount = Amount::from_sat(r.read_u64()?);
		let expiry_height = r.read_u32()?;
		let server_pubkey = PublicKey::decode(r)?;
		let exit_delta = r.read_u16()?;
		let anchor_point = OutPoint::decode(r)?;

		let nb_genesis_items = r.read_u8()? as usize;
		let mut genesis = Vec::with_capacity(nb_genesis_items);
		for _ in 0..nb_genesis_items {
			let transition = GenesisTransition::decode(r)?;
			let nb_outputs = r.read_u8()? as usize;
			let output_idx = r.read_u8()?;
			let nb_other = nb_outputs.checked_sub(1)
				.ok_or_else(|| ProtocolDecodingError::invalid("genesis item with 0 outputs"))?;
			let mut other_outputs = Vec::with_capacity(nb_other);
			for _ in 0..nb_other {
				other_outputs.push(TxOut::decode(r)?);
			}
			genesis.push(GenesisItem { transition, output_idx, other_outputs });
		}

		let output = VtxoPolicy::decode(r)?;
		let point = OutPoint::decode(r)?;

		Ok(Self {
			amount, expiry_height, server_pubkey, exit_delta, anchor_point, genesis, policy: output, point,
		})
	}
}


#[cfg(any(test, feature = "test-util"))]
pub mod test {
	use std::iter;
	use std::collections::HashMap;

	use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
	use bitcoin::hex::{DisplayHex, FromHex};
	use bitcoin::secp256k1::Keypair;
	use bitcoin::transaction::Version;

	use crate::{VtxoRequest, SECP};
	use crate::arkoor::ArkoorDestination;
	use crate::arkoor::package::ArkoorPackageBuilder;
	use crate::tree::signed::{VtxoLeafSpec, VtxoTreeSpec};
	use crate::board::BoardBuilder;
	use crate::encode::test::encoding_roundtrip;

	use super::*;

	#[allow(unused)]
	#[macro_export]
	macro_rules! assert_eq_vtxos {
		($v1:expr, $v2:expr) => {
			let v1 = &$v1;
			let v2 = &$v2;
			assert_eq!(
				v1.serialize().as_hex().to_string(),
				v2.serialize().as_hex().to_string(),
				"vtxo {} != {}", v1.id(), v2.id(),
			);
		};
	}

	#[derive(Debug, PartialEq, Eq)]
	pub struct VtxoTestVectors {
		pub server_key: Keypair,

		pub anchor_tx: Transaction,
		pub board_vtxo: Vtxo,

		pub arkoor_htlc_out_vtxo: Vtxo,
		pub arkoor2_vtxo: Vtxo,

		pub round_tx: Transaction,
		pub round1_vtxo: Vtxo,
		pub round2_vtxo: Vtxo,

		pub arkoor3_user_key: Keypair,
		pub arkoor3_vtxo: Vtxo,
	}

	#[allow(unused)] // under the "test-util" feature it's unused
	fn generate_vtxo_vectors() -> VtxoTestVectors {
		let expiry_height = 101_010;
		let exit_delta = 2016;
		let server_key = Keypair::from_str("916da686cedaee9a9bfb731b77439f2a3f1df8664e16488fba46b8d2bfe15e92").unwrap();
		let board_user_key = Keypair::from_str("fab9e598081a3e74b2233d470c4ad87bcc285b6912ed929568e62ac0e9409879").unwrap();
		let amount = Amount::from_sat(10_000);
		let builder = BoardBuilder::new(
			board_user_key.public_key(),
			expiry_height,
			server_key.public_key(),
			exit_delta,
		);
		let anchor_tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(10_000),
				script_pubkey: builder.funding_script_pubkey(),
			}],
		};
		println!("chain anchor tx: {}", serialize_hex(&anchor_tx));
		let anchor_point = OutPoint::new(anchor_tx.compute_txid(), 0);
		let builder = builder.set_funding_details(amount, anchor_point)
			.generate_user_nonces();

		let board_cosign = {
			BoardBuilder::new_for_cosign(
				builder.user_pubkey,
				builder.expiry_height,
				builder.server_pubkey,
				builder.exit_delta,
				amount,
				anchor_point,
				*builder.user_pub_nonce(),
			).server_cosign(&server_key)
		};

		assert!(builder.verify_cosign_response(&board_cosign));
		let board_vtxo = builder.build_vtxo(&board_cosign, &board_user_key).unwrap();
		encoding_roundtrip(&board_vtxo);
		println!("board vtxo: {}", board_vtxo.serialize().as_hex());

		// arkoor1: htlc send

		let arkoor_htlc_out_user_key = Keypair::from_str("33b6f3ede430a1a53229f55da7117242d8392cbfc64a57249ba70731dba71408").unwrap();
		let payment_hash = PaymentHash::from(sha256::Hash::hash("arkoor1".as_bytes()).to_byte_array());
		let arkoor1_dest1 = ArkoorDestination {
			total_amount: Amount::from_sat(9000),
			policy: VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy {
				user_pubkey: arkoor_htlc_out_user_key.public_key(),
				payment_hash,
				htlc_expiry: expiry_height - 1000,
			}),
		};
		let arkoor1_dest2 = ArkoorDestination {
			total_amount: Amount::from_sat(1000),
			policy: VtxoPolicy::new_pubkey("0229b7de0ce4d573192d002a6f9fd1109e00f7bae52bf10780d6f6e73e12a8390f".parse().unwrap()),
		};
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&board_user_key);
		let builder = ArkoorPackageBuilder::new_with_checkpoints(
			[board_vtxo.clone()], vec![arkoor1_dest1, arkoor1_dest2],
		).unwrap().generate_user_nonces(&[board_user_key]).unwrap();
		let cosign = ArkoorPackageBuilder::from_cosign_request(
			builder.cosign_request(),
		).unwrap().server_cosign(&server_key).unwrap().cosign_response();
		let [arkoor_htlc_out_vtxo, change] = builder.user_cosign(&[board_user_key], cosign).unwrap()
			.build_signed_vtxos().try_into().unwrap();
		encoding_roundtrip(&arkoor_htlc_out_vtxo);
		encoding_roundtrip(&change);
		println!("arkoor1_vtxo: {}", arkoor_htlc_out_vtxo.serialize().as_hex());

		// arkoor2: regular pubkey

		let arkoor2_user_key = Keypair::from_str("fcc43a4f03356092a945ca1d7218503156bed3f94c2fa224578ce5b158fbf5a6").unwrap();
		let arkoor2_dest1 = ArkoorDestination {
			total_amount: Amount::from_sat(8000),
			policy: VtxoPolicy::new_pubkey(arkoor2_user_key.public_key()),
		};
		let arkoor2_dest2 = ArkoorDestination {
			total_amount: Amount::from_sat(1000),
			policy: VtxoPolicy::new_pubkey("037039dc4f4b16e78059d2d56eb98d181cb1bdff2675694d39d92c4a2ea08ced88".parse().unwrap()),
		};
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&arkoor_htlc_out_user_key);
		let builder = ArkoorPackageBuilder::new_with_checkpoints(
			[arkoor_htlc_out_vtxo.clone()], vec![arkoor2_dest1, arkoor2_dest2],
		).unwrap().generate_user_nonces(&[arkoor_htlc_out_user_key]).unwrap();
		let cosign = ArkoorPackageBuilder::from_cosign_request(
			builder.cosign_request(),
		).unwrap().server_cosign(&server_key).unwrap().cosign_response();
		let [arkoor2_vtxo, change] = builder.user_cosign(&[arkoor_htlc_out_user_key], cosign).unwrap()
			.build_signed_vtxos().try_into().unwrap();
		encoding_roundtrip(&arkoor2_vtxo);
		encoding_roundtrip(&change);
		println!("arkoor2_vtxo: {}", arkoor2_vtxo.serialize().as_hex());

		// round 1

		//TODO(stevenroose) rename to round htlc in
		let round1_user_key = Keypair::from_str("0a832e9574070c94b5b078600a18639321c880c830c5ba2f2a96850c7dcc4725").unwrap();
		let round1_cosign_key = Keypair::from_str("e14bfc3199842c76816eec1d93c9da00b850c4ed19e414e246d07e845e465a2b").unwrap();
		let round1_unlock_preimage = UnlockPreimage::from_hex("c05bc2f82c8c64e470cd4d87aca42989b46879ca32320cd035db124bb78c4e74").unwrap();
		let round1_unlock_hash = UnlockHash::hash(&round1_unlock_preimage);
		println!("round1_cosign_key: {}", round1_cosign_key.public_key());
		let round1_req = VtxoLeafSpec {
			vtxo: VtxoRequest {
				amount: Amount::from_sat(10_000),
				policy: VtxoPolicy::new_pubkey(round1_user_key.public_key()),
			},
			cosign_pubkey: Some(round1_cosign_key.public_key()),
			unlock_hash: round1_unlock_hash,
		};
		let round1_nonces = iter::repeat_with(|| musig::nonce_pair(&round1_cosign_key)).take(5).collect::<Vec<_>>();

		let round2_user_key = Keypair::from_str("c0b645b01cac427717a18b30c7c9238dee2b3885f659930144fbe05061ad6166").unwrap();
		let round2_cosign_key = Keypair::from_str("628789cd7b7e02766d184ecfecc433798c9640349e41822df7996c66a56fc633").unwrap();
		let round2_unlock_preimage = UnlockPreimage::from_hex("61050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d").unwrap();
		let round2_unlock_hash = UnlockHash::hash(&round2_unlock_preimage);
		println!("round2_cosign_key: {}", round2_cosign_key.public_key());
		let round2_payment_hash = PaymentHash::from(sha256::Hash::hash("round2".as_bytes()).to_byte_array());
		let round2_req = VtxoLeafSpec {
			vtxo: VtxoRequest {
				amount: Amount::from_sat(10_000),
				policy: VtxoPolicy::new_server_htlc_recv(
					round2_user_key.public_key(),
					round2_payment_hash,
					expiry_height - 2000,
					40,
				),
			},
			cosign_pubkey: Some(round2_cosign_key.public_key()),
			unlock_hash: round2_unlock_hash,
		};
		let round2_nonces = iter::repeat_with(|| musig::nonce_pair(&round2_cosign_key)).take(5).collect::<Vec<_>>();

		let others = [
			"93b376f64ada74f0fbf940be86f888459ac94655dc6a7805cc790b3c95a2a612",
			"00add86ff531ef53f877780622f0b376669ec6ad7e090131820ff7007e79f529",
			"775b836f2acf53de4ff9beeba2a17d5475e9b027d82fece72033ef06b954c7cd",
			"395c2c210481990a5d12d33dca37995e235a34b717c89647a33907c62e32dc09",
			"8f02f2a7aa1746bbcc92bba607b7166b6a77e9d0efd9d09dae7c2dc3addbdef1",
		];
		let mut other_reqs = Vec::new();
		let mut other_nonces = Vec::new();
		for k in others {
			let user_key = Keypair::from_str(k).unwrap();
			let cosign_key = Keypair::from_seckey_slice(&SECP, &sha256::Hash::hash(k.as_bytes())[..]).unwrap();
			other_reqs.push(VtxoLeafSpec {
				vtxo: VtxoRequest {
					amount: Amount::from_sat(5_000),
					policy: VtxoPolicy::new_pubkey(user_key.public_key()),
				},
				cosign_pubkey: Some(cosign_key.public_key()),
				unlock_hash: sha256::Hash::hash(k.as_bytes()),
			});
			other_nonces.push(iter::repeat_with(|| musig::nonce_pair(&cosign_key)).take(5).collect::<Vec<_>>());
		}

		let server_cosign_key = Keypair::from_str("4371a4a7989b89ebe1b2582db4cd658cb95070977e6f10601ddc1e9b53edee79").unwrap();
		let spec = VtxoTreeSpec::new(
			[&round1_req, &round2_req].into_iter().chain(other_reqs.iter()).cloned().collect(),
			server_key.public_key(),
			expiry_height,
			exit_delta,
			vec![server_cosign_key.public_key()],
		);
		let round_tx = Transaction {
			version: Version::TWO,
			lock_time: LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(45_000),
				script_pubkey: spec.funding_tx_script_pubkey(),
			}],
		};
		println!("round tx: {}", serialize_hex(&round_tx));
		let all_nonces = {
			let mut map = HashMap::new();
			map.insert(round1_cosign_key.public_key(), round1_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			map.insert(round2_cosign_key.public_key(), round2_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			for (req, nonces) in other_reqs.iter().zip(other_nonces.iter()) {
				map.insert(req.cosign_pubkey.unwrap(), nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			}
			map
		};
		let (server_cosign_sec_nonces, server_cosign_pub_nonces) = iter::repeat_with(|| {
			musig::nonce_pair(&server_cosign_key)
		}).take(spec.nb_internal_nodes()).unzip::<_, _, Vec<_>, Vec<_>>();
		let cosign_agg_nonces = spec.calculate_cosign_agg_nonces(&all_nonces, &[&server_cosign_pub_nonces]).unwrap();
		let root_point = OutPoint::new(round_tx.compute_txid(), 0);
		let tree = spec.into_unsigned_tree(root_point);
		let part_sigs = {
			let mut map = HashMap::new();
			map.insert(round1_cosign_key.public_key(), {
				let secs = round1_nonces.into_iter().map(|(s, _)| s).collect();
				let r = tree.cosign_branch(&cosign_agg_nonces, 0, &round1_cosign_key, secs).unwrap();
				r
			});
			map.insert(round2_cosign_key.public_key(), {
				let secs = round2_nonces.into_iter().map(|(s, _)| s).collect();
				tree.cosign_branch(&cosign_agg_nonces, 1, &round2_cosign_key, secs).unwrap()
			});
			for (i, (req, nonces)) in other_reqs.iter().zip(other_nonces.into_iter()).enumerate() {
				let cosign_key = Keypair::from_seckey_slice(
					&SECP, &sha256::Hash::hash(others[i].as_bytes())[..],
				).unwrap();
				map.insert(req.cosign_pubkey.unwrap(), {
					let secs = nonces.into_iter().map(|(s, _)| s).collect();
					tree.cosign_branch(&cosign_agg_nonces, 2 + i, &cosign_key, secs).unwrap()
				});
			}
			map
		};
		let server_cosign_sigs = tree.cosign_tree(
			&cosign_agg_nonces, &server_cosign_key, server_cosign_sec_nonces,
		);
		let cosign_sigs = tree.combine_partial_signatures(&cosign_agg_nonces, &part_sigs, &[&server_cosign_sigs]).unwrap();
		if let Err(pk) = tree.verify_cosign_sigs(&cosign_sigs) {
			panic!("invalid cosign sig for pk: {}", pk);
		}
		let signed = tree.into_signed_tree(cosign_sigs).into_cached_tree();
		// we don't need forfeits
		let mut vtxo_iter = signed.all_vtxos();
		let round1_vtxo = {
			let mut ret = vtxo_iter.next().unwrap();
			ret.finalize_hark_leaf(&round1_user_key, &server_key, &round_tx, round1_unlock_preimage);
			ret
		};
		encoding_roundtrip(&round1_vtxo);
		println!("round1_vtxo: {}", round1_vtxo.serialize().as_hex());
		let round2_vtxo = {
			let mut ret = vtxo_iter.next().unwrap();
			ret.finalize_hark_leaf(&round2_user_key, &server_key, &round_tx, round2_unlock_preimage);
			ret
		};
		encoding_roundtrip(&round2_vtxo);
		println!("round2_vtxo: {}", round2_vtxo.serialize().as_hex());

		// arkoor3: off from round2's htlc

		let arkoor3_user_key = Keypair::from_str("ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f").unwrap();
		let arkoor3_dest = ArkoorDestination {
			total_amount: Amount::from_sat(10_000),
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: arkoor3_user_key.public_key() }),
		};
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&round2_user_key);
		let builder = ArkoorPackageBuilder::new_with_checkpoints(
			[round2_vtxo.clone()], vec![arkoor3_dest],
		).unwrap().generate_user_nonces(&[round2_user_key]).unwrap();
		let cosign = ArkoorPackageBuilder::from_cosign_request(
			builder.cosign_request(),
		).unwrap().server_cosign(&server_key).unwrap().cosign_response();
		let [arkoor3_vtxo] = builder.user_cosign(&[round2_user_key], cosign).unwrap()
			.build_signed_vtxos().try_into().unwrap();
		encoding_roundtrip(&arkoor3_vtxo);
		println!("arkoor3_vtxo: {}", arkoor3_vtxo.serialize().as_hex());

		VtxoTestVectors {
			server_key,
			anchor_tx,
			board_vtxo,
			arkoor_htlc_out_vtxo,
			arkoor2_vtxo,
			round_tx,
			round1_vtxo,
			round2_vtxo,
			arkoor3_user_key,
			arkoor3_vtxo,
		}
	}

	lazy_static! {
		/// A set of deterministically generated and fully correct VTXOs.
		pub static ref VTXO_VECTORS: VtxoTestVectors = VtxoTestVectors {
			server_key: Keypair::from_str("916da686cedaee9a9bfb731b77439f2a3f1df8664e16488fba46b8d2bfe15e92").unwrap(),
			anchor_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000011027000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d00000000").unwrap(),
			board_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000001010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62be19abd3f0f0ee3a1ffa9a86b6e13ab9899aef88e5c10c14a047c0256ea880a234913cf2a63c90c851bd9a3e7cd7ce1eba919726a406d34c59123275536622f5010000030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee4c99b744ad009b7070f330794bf003fa8e5cd46ea1a6eb854aaf469385e3080000000000").unwrap(),
			arkoor_htlc_out_vtxo: ProtocolEncoding::deserialize_hex("01002823000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000003010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b621c35ec73855eda07716d857d428fe01a6ed3f9f02f830914eb4b95a94317f663bec8a3dc09d8d8df2611959ba9ca1e1261d6f2f79778fc8edc8aaeb4bd6b4abe01000200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee1aca15ff7c551b90b1b442c64d3079dde840213d2e97b19c9eef09ffc149989d2ca09d634e3ce054820250532a2141d2746d692032b410fad4e5ba80bc39f9b40200e803000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d0203030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee04a4db2cceeac0f4fff3e758155b51187b318fde7076b4e4d3b5c00c6bb643f478e1cf7ddada03317987a971b86ac468e3b1a7ec2673b37d9c72e4a91ae0042e01000103eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73712358912c950a9a7d04bb9011ee9f6a16b6127a5aab7415803d48c0225f620f5aa8601006b46ceafff6c10e1c1d07fa308e79cfdac35e952c1e2ccf3f8c9797c776db17200000000").unwrap(),
			arkoor2_vtxo: ProtocolEncoding::deserialize_hex("0100401f000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000005010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b621c35ec73855eda07716d857d428fe01a6ed3f9f02f830914eb4b95a94317f663bec8a3dc09d8d8df2611959ba9ca1e1261d6f2f79778fc8edc8aaeb4bd6b4abe01000200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee1aca15ff7c551b90b1b442c64d3079dde840213d2e97b19c9eef09ffc149989d2ca09d634e3ce054820250532a2141d2746d692032b410fad4e5ba80bc39f9b40200e803000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d0203030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee04a4db2cceeac0f4fff3e758155b51187b318fde7076b4e4d3b5c00c6bb643f478e1cf7ddada03317987a971b86ac468e3b1a7ec2673b37d9c72e4a91ae0042e0100020103eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73712358912c950a9a7d04bb9011ee9f6a16b6127a5aab7415803d48c0225f620f5aa860100f8fd2158ece9874609d33a4a03721e82b9d5025abdaa2a4df2143d8b689de1fea73bdde9ec40b7788d19fa7d5ed8499d8a3fa3bbe45e5642ac78cc50129e92430200e80300000000000022512045827da6714a3cadf6646b36f4e18841a8572d7c6f849e8376058be8381941c8020303eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e737250c3f06a00d78429a1261a13907897fd2e9f320db77660b676f1ee89367b3731d6331eb22c819613717e82abeae9a55e0816d8c77cd27f69ea82389c23510370100000265cca13271cafd0b90c440e722a1937b7c4faf4ccd7dee0548d152c24ce4b2a8dca043938fa10d4ea2d54ab3743f9e092b9f671aa30161bcbd3942b46b1b195700000000").unwrap(),
			round_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff000000000001c8af000000000000225120649657f65947abfd83ff629ad8a851c795f419ed4d52a2748d3f868cc3e6c94d00000000").unwrap(),
			round1_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000003010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743662156b3287dbfa9053520ef877f5c6424920a37751548c942c86d1c0ba15c5dffc452f73642fff9d20b60e32e8fb749c819ae9cc1bd686e00b3e7b257782656040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743c0a42892e2cd996341b3c722da8ed6ae10f5e0ee1952d65b97ae1b70271f2b7ca00ca83a85cefefe0c8c01facc1e1fd521748038b7a561b2062786d4b2ecac5704001027000000000000225120e9d56cdf22598ce6c05950b3580e194a19e53f8b887fc6c4111ca2a82a0608a88813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030374a3ec37cc4ccd29717388e6dc24f2aa366632f1a36a49e73cd7671b23179298286a7abdc629f2e0ee861e77501502201052ed905369a55e431d028d4bdbc5dc6ed9b18ae988b709225bbb3ba1686b923b3716992fe681ae0869dada96dd058100c05bc2f82c8c64e470cd4d87aca42989b46879ca32320cd035db124bb78c4e740100000374a3ec37cc4ccd29717388e6dc24f2aa366632f1a36a49e73cd7671b2317929862d6c4b8e408915af8279d4f14431f517a0c9ecc46fae2e8b0a5f72cfcf506c800000000").unwrap(),
			round2_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000003010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743662156b3287dbfa9053520ef877f5c6424920a37751548c942c86d1c0ba15c5dffc452f73642fff9d20b60e32e8fb749c819ae9cc1bd686e00b3e7b257782656040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743c0a42892e2cd996341b3c722da8ed6ae10f5e0ee1952d65b97ae1b70271f2b7ca00ca83a85cefefe0c8c01facc1e1fd521748038b7a561b2062786d4b2ecac57040110270000000000002251202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c8813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd8cdf97edbcb05e33ddb0f683fd678786e097af9eace2879053ea21e8b56c674f30b231828f75d62adb235165aa3d9f80c10092c85b69b7802721ba00cd0c6bcc0061050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d0100020256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd9ea50d885c3f66d40d27e779648ba8dc730629663f65a3e6f7749b4a35b6dfecc28201002800ca6a1d9ccb57f92a11eb4383517f0046482462046eeb9090496785f1893b766f00000000").unwrap(),
			arkoor3_user_key: Keypair::from_str("ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f").unwrap(),
			arkoor3_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000005010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743662156b3287dbfa9053520ef877f5c6424920a37751548c942c86d1c0ba15c5dffc452f73642fff9d20b60e32e8fb749c819ae9cc1bd686e00b3e7b257782656040388130000000000002251205acb7b65f8da14622a055640893e952e20f68e051087b85be4d56e50cdafd4318813000000000000225120973b9be7e6ee51f8851347130113e4001ab1d01252dd1d09713a6c900cb327f2881300000000000022512052cc228fe0f4951032fbaeb45ed8b73163cedb897412407e5b431d740040a951010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743c0a42892e2cd996341b3c722da8ed6ae10f5e0ee1952d65b97ae1b70271f2b7ca00ca83a85cefefe0c8c01facc1e1fd521748038b7a561b2062786d4b2ecac57040110270000000000002251202ec5640d3ba147e40c916e8fa9b0ee89557d10465db1d55a49c87edebe53104c8813000000000000225120c3731a9dc38c67dfa2dd206ee346d6225f1f37b97d77d518c59b9c9a291762288813000000000000225120a4ad17a5f329a164977981f1b7638c7a70b0dd1bed29a85637aed2952dd2e38c030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd8cdf97edbcb05e33ddb0f683fd678786e097af9eace2879053ea21e8b56c674f30b231828f75d62adb235165aa3d9f80c10092c85b69b7802721ba00cd0c6bcc0061050792ef121826fda248a789c8ba75b955844c65acd2c6361950bdd31dae7d010002020256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd9ea50d885c3f66d40d27e779648ba8dc730629663f65a3e6f7749b4a35b6dfecc2820100280065d223ebca35fbf9443e18bcff274a9540179868f7bfd4afe8f756a2394719114b172f295e7ccbe39a76f450fddc894ed448ddb483a112657cd0cadc0fd63be6010002030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd043c07a4e140b184437e9e1cc66d96a3363b89f0c6fa67f4e074ebed259aca90cc9eb37f3754a4c73bccd6327637e84e892812f8269ccbd51e280315e85f135501000002ed1334f116cea9128e1f59f1d5a431cb4f338f0998e2b32f654c310bf7831f97016422a562a4826f26ff351ecb5b1122e0d27958053fd6595a9424a0305fad0700000000").unwrap(),
		};
	}

	#[test]
	fn test_generate_vtxo_vectors() {
		let g = generate_vtxo_vectors();
		// the generation code prints its inner values

		let v = &*VTXO_VECTORS;
		println!("\n\nstatic:");
		println!("  anchor_tx: {}", serialize_hex(&v.anchor_tx));
		println!("  board_vtxo: {}", v.board_vtxo.serialize().as_hex().to_string());
		println!("  arkoor_htlc_out_vtxo: {}", v.arkoor_htlc_out_vtxo.serialize().as_hex().to_string());
		println!("  arkoor2_vtxo: {}", v.arkoor2_vtxo.serialize().as_hex().to_string());
		println!("  round_tx: {}", serialize_hex(&v.round_tx));
		println!("  round1_vtxo: {}", v.round1_vtxo.serialize().as_hex().to_string());
		println!("  round2_vtxo: {}", v.round2_vtxo.serialize().as_hex().to_string());
		println!("  arkoor3_vtxo: {}", v.arkoor3_vtxo.serialize().as_hex().to_string());

		assert_eq!(g.anchor_tx, v.anchor_tx, "anchor_tx does not match");
		assert_eq!(g.board_vtxo, v.board_vtxo, "board_vtxo does not match");
		assert_eq!(g.arkoor_htlc_out_vtxo, v.arkoor_htlc_out_vtxo, "arkoor_htlc_out_vtxo does not match");
		assert_eq!(g.arkoor2_vtxo, v.arkoor2_vtxo, "arkoor2_vtxo does not match");
		assert_eq!(g.round_tx, v.round_tx, "round_tx does not match");
		assert_eq!(g.round1_vtxo, v.round1_vtxo, "round1_vtxo does not match");
		assert_eq!(g.round2_vtxo, v.round2_vtxo, "round2_vtxo does not match");
		assert_eq!(g.arkoor3_vtxo, v.arkoor3_vtxo, "arkoor3_vtxo does not match");

		// this passes because the Eq is based on id which doesn't compare signatures
		assert_eq!(g, *v);
	}

	#[test]
	fn exit_depth() {
		let vtxos = &*VTXO_VECTORS;
		// board
		assert_eq!(vtxos.board_vtxo.exit_depth(), 1 /* cosign */);

		// round
		assert_eq!(vtxos.round1_vtxo.exit_depth(), 3 /* cosign */);

		// arkoor
		assert_eq!(
			vtxos.arkoor_htlc_out_vtxo.exit_depth(),
			1 /* cosign */ + 1 /* checkpoint*/ + 1 /* arkoor */,
		);
		assert_eq!(
			vtxos.arkoor2_vtxo.exit_depth(),
			1 /* cosign */ + 2 /* checkpoint */ + 2 /* arkoor */,
		);
		assert_eq!(
			vtxos.arkoor3_vtxo.exit_depth(),
			3 /* cosign */ + 1 /* checkpoint */ + 1 /* arkoor */,
		);
	}
}
