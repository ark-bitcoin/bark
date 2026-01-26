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
pub use self::policy::{Policy, VtxoPolicy, VtxoPolicyKind, ServerVtxoPolicy};
pub(crate) use self::genesis::{GenesisItem, GenesisTransition};

pub use self::policy::{
	PubkeyVtxoPolicy, CheckpointVtxoPolicy, ExpiryVtxoPolicy,
	ServerHtlcRecvVtxoPolicy, ServerHtlcSendVtxoPolicy
};
pub use self::policy::clause::{
	VtxoClause, DelayedSignClause, DelayedTimelockSignClause, HashDelaySignClause,
	TapScriptClause,
};

/// Type alias for a server-internal VTXO that may have policies without user pubkeys.
pub type ServerVtxo = Vtxo<ServerVtxoPolicy>;

use std::iter::FusedIterator;
use std::{fmt, io};
use std::str::FromStr;

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};
use bitcoin::taproot::TapTweakHash;

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
pub struct VtxoTxIter<'a, P: Policy = VtxoPolicy> {
	vtxo: &'a Vtxo<P>,

	prev: OutPoint,
	genesis_idx: usize,
	current_amount: Amount,
	done: bool,
}

impl<'a, P: Policy> VtxoTxIter<'a, P> {
	fn new(vtxo: &'a Vtxo<P>) -> VtxoTxIter<'a, P> {
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

impl<'a, P: Policy> Iterator for VtxoTxIter<'a, P> {
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

impl<'a, P: Policy> ExactSizeIterator for VtxoTxIter<'a, P> {}
impl<'a, P: Policy> FusedIterator for VtxoTxIter<'a, P> {}


/// Information that specifies a VTXO, independent of its origin.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoSpec<P = VtxoPolicy> {
	pub policy: P,
	pub amount: Amount,
	pub expiry_height: BlockHeight,
	pub server_pubkey: PublicKey,
	pub exit_delta: BlockDelta,
}

impl<P: Policy> VtxoSpec<P> {
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
pub struct Vtxo<P = VtxoPolicy> {
	pub(crate) policy: P,
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

impl<P: Policy> Vtxo<P> {
	/// Get the identifier for this [Vtxo].
	///
	/// This is the same as [Vtxo::point] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		self.point.into()
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
	pub fn policy(&self) -> &P {
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

	/// Iterate over all oor transitions in this VTXO
	///
	/// The outer `Vec` cointains one element for each transition.
	/// The inner `Vec` contains all pubkeys within that transition.
	///
	/// This does not include the current arkoor pubkey, for that use
	/// [Vtxo::arkoor_pubkey].
	pub fn past_arkoor_pubkeys(&self) -> Vec<Vec<PublicKey>> {
		self.genesis.iter().filter_map(|g| {
			match &g.transition {
				// NB in principle, a genesis item's transition MUST have
				// an arkoor pubkey, otherwise the vtxo is invalid
				GenesisTransition::Arkoor(inner) => Some(inner.client_cosigners().collect()),
				_ => None,
			}
		}).collect()
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

	/// Check if this VTXO is standard for relay purposes
	///
	/// A VTXO is standard if:
	/// - Its own output is standard
	/// - all sibling outputs in the exit path are standard
	pub fn is_standard(&self) -> bool {
		self.txout().is_standard() && self.genesis.iter()
			.all(|i| i.other_outputs.iter().all(|o| o.is_standard()))
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

	/// Get the spec for this VTXO.
	pub fn spec(&self) -> VtxoSpec<P> {
		VtxoSpec {
			policy: self.policy.clone(),
			amount: self.amount,
			expiry_height: self.expiry_height,
			server_pubkey: self.server_pubkey,
			exit_delta: self.exit_delta,
		}
	}

	/// Iterator that constructs all the exit txs for this [Vtxo].
	pub fn transactions(&self) -> VtxoTxIter<'_, P> {
		VtxoTxIter::new(self)
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
}

impl Vtxo {
	/// Returns the user pubkey associated with this [Vtxo].
	pub fn user_pubkey(&self) -> PublicKey {
		self.policy.user_pubkey()
	}

	/// The public key used to cosign arkoor txs spending this [Vtxo].
	/// This will return [None] if [VtxoPolicy::is_arkoor_compatible] returns false
	/// for this VTXO's policy.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		self.policy.arkoor_pubkey()
	}

	/// Return the aggregate pubkey of the user and server pubkey used in
	/// hArk forfeit transactions
	pub(crate) fn forfeit_agg_pubkey(&self) -> XOnlyPublicKey {
		let ret = musig::combine_keys([self.user_pubkey(), self.server_pubkey()]);
		debug_assert_eq!(ret, self.output_taproot().internal_key());
		ret
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

impl Vtxo<ServerVtxoPolicy> {
	/// Try to convert into a user [Vtxo]
	///
	/// Returns the original value on failure.
	pub fn try_into_user_vtxo(self) -> Result<Vtxo, ServerVtxo> {
		if let Some(p) = self.policy.clone().into_user_policy() {
			Ok(Vtxo {
				policy: p,
				amount: self.amount,
				expiry_height: self.expiry_height,
				server_pubkey: self.server_pubkey,
				exit_delta: self.exit_delta,
				anchor_point: self.anchor_point,
				genesis: self.genesis,
				point: self.point,
			})
		} else {
			Err(self)
		}
	}
}

impl<P: Policy> PartialEq for Vtxo<P> {
	fn eq(&self, other: &Self) -> bool {
		PartialEq::eq(&self.id(), &other.id())
	}
}

impl<P: Policy> Eq for Vtxo<P> {}

impl<P: Policy> PartialOrd for Vtxo<P> {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		PartialOrd::partial_cmp(&self.id(), &other.id())
	}
}

impl<P: Policy> Ord for Vtxo<P> {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		Ord::cmp(&self.id(), &other.id())
	}
}

impl<P: Policy> std::hash::Hash for Vtxo<P> {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		std::hash::Hash::hash(&self.id(), state)
	}
}

impl AsRef<Vtxo> for Vtxo {
	fn as_ref(&self) -> &Vtxo {
	    self
	}
}

impl From<Vtxo> for ServerVtxo {
	fn from(vtxo: Vtxo) -> ServerVtxo {
		ServerVtxo {
			policy: vtxo.policy.into(),
			amount: vtxo.amount,
			expiry_height: vtxo.expiry_height,
			server_pubkey: vtxo.server_pubkey,
			exit_delta: vtxo.exit_delta,
			anchor_point: vtxo.anchor_point,
			genesis: vtxo.genesis,
			point: vtxo.point,
		}
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

/// The byte used to encode the [ServerVtxoPolicy::Checkpoint] output type.
const VTXO_POLICY_CHECKPOINT: u8 = 0x03;

/// The byte used to encode the [ServerVtxoPolicy::Expiry] output type.
const VTXO_POLICY_EXPIRY: u8 = 0x04;

impl ProtocolEncoding for VtxoPolicy {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				w.emit_u8(VTXO_POLICY_PUBKEY)?;
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
		let type_byte = r.read_u8()?;
		decode_vtxo_policy(type_byte, r)
	}
}

/// Decode a [VtxoPolicy] with the given type byte
///
/// We have this function so it can be reused in [VtxoPolicy] and [ServerVtxoPolicy].
fn decode_vtxo_policy<R: io::Read + ?Sized>(
	type_byte: u8,
	r: &mut R,
) -> Result<VtxoPolicy, ProtocolDecodingError> {
	match type_byte {
		VTXO_POLICY_PUBKEY => {
			let user_pubkey = PublicKey::decode(r)?;
			Ok(VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey }))
		},
		VTXO_POLICY_SERVER_HTLC_SEND => {
			let user_pubkey = PublicKey::decode(r)?;
			let payment_hash = PaymentHash::from(sha256::Hash::decode(r)?.to_byte_array());
			let htlc_expiry = r.read_u32()?;
			Ok(VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }))
		},
		VTXO_POLICY_SERVER_HTLC_RECV => {
			let user_pubkey = PublicKey::decode(r)?;
			let payment_hash = PaymentHash::from(sha256::Hash::decode(r)?.to_byte_array());
			let htlc_expiry = r.read_u32()?;
			let htlc_expiry_delta = r.read_u16()?;
			Ok(VtxoPolicy::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry, htlc_expiry_delta }))
		},
		v => Err(ProtocolDecodingError::invalid(format_args!(
			"invalid VtxoPolicy type byte: {v:#x}",
		))),
	}
}

impl ProtocolEncoding for ServerVtxoPolicy {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::User(p) => p.encode(w)?,
			Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }) => {
				w.emit_u8(VTXO_POLICY_CHECKPOINT)?;
				user_pubkey.encode(w)?;
			},
			Self::Expiry(ExpiryVtxoPolicy { internal_key }) => {
				w.emit_u8(VTXO_POLICY_EXPIRY)?;
				internal_key.encode(w)?;
			},
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let type_byte = r.read_u8()?;
		match type_byte {
			VTXO_POLICY_PUBKEY | VTXO_POLICY_SERVER_HTLC_SEND | VTXO_POLICY_SERVER_HTLC_RECV => {
				Ok(Self::User(decode_vtxo_policy(type_byte, r)?))
			},
			VTXO_POLICY_CHECKPOINT => {
				let user_pubkey = PublicKey::decode(r)?;
				Ok(Self::Checkpoint(CheckpointVtxoPolicy { user_pubkey }))
			},
			VTXO_POLICY_EXPIRY => {
				let internal_key = XOnlyPublicKey::decode(r)?;
				Ok(Self::Expiry(ExpiryVtxoPolicy { internal_key }))
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid ServerVtxoPolicy type byte: {v:#x}",
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
				w.emit_u16(t.client_cosigners.len().try_into().expect("Length overflow"))?;
				for cosigner in t.client_cosigners.iter() {
					cosigner.encode(w)?;
				};
				t.tap_tweak.encode(w)?;
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
				let nb_cosigners: usize = r.read_u16()?.into();

				let mut pubkeys = Vec::with_capacity(nb_cosigners);
				for _ in 0..nb_cosigners {
					pubkeys.push(PublicKey::decode(r)?);
				}
				let taptweak = TapTweakHash::decode(r)?;
				let signature = Option::<schnorr::Signature>::decode(r)?;
				Ok(Self::new_arkoor(pubkeys, taptweak, signature))
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid GenesisTransistion type byte: {v:#x}",
			))),
		}
	}
}

impl<P: Policy + ProtocolEncoding> ProtocolEncoding for Vtxo<P> {
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

		let policy = P::decode(r)?;
		let point = OutPoint::decode(r)?;

		Ok(Self {
			amount, expiry_height, server_pubkey, exit_delta, anchor_point, genesis, policy, point,
		})
	}
}


#[cfg(test)]
mod test {
	use bitcoin::consensus::encode::serialize_hex;
	use bitcoin::hex::DisplayHex;

	use crate::test_util::vectors::{generate_vtxo_vectors, VTXO_VECTORS};

	use super::*;

	#[test]
	fn test_generate_vtxo_vectors() {
		let g = generate_vtxo_vectors();
		// the generation code prints its inner values

		println!("\n\ngenerated:");
		println!("  anchor_tx: {}", serialize_hex(&g.anchor_tx));
		println!("  board_vtxo: {}", g.board_vtxo.serialize().as_hex().to_string());
		println!("  arkoor_htlc_out_vtxo: {}", g.arkoor_htlc_out_vtxo.serialize().as_hex().to_string());
		println!("  arkoor2_vtxo: {}", g.arkoor2_vtxo.serialize().as_hex().to_string());
		println!("  round_tx: {}", serialize_hex(&g.round_tx));
		println!("  round1_vtxo: {}", g.round1_vtxo.serialize().as_hex().to_string());
		println!("  round2_vtxo: {}", g.round2_vtxo.serialize().as_hex().to_string());
		println!("  arkoor3_vtxo: {}", g.arkoor3_vtxo.serialize().as_hex().to_string());


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
