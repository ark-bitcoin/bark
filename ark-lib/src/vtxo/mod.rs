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


mod validation;
pub use self::validation::{Validation, VtxoValidationError};

use std::iter::FusedIterator;
use std::{fmt, io};
use std::str::FromStr;

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, PublicKey};

use bitcoin_ext::{fee, BlockHeight, TaprootSpendInfoExt};

use crate::{musig, util};
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};
use crate::lightning::{server_htlc_receive_taproot, server_htlc_send_taproot, PaymentHash};
use crate::tree::signed::cosign_taproot;



/// The total signed tx weight of a exit tx.
pub const EXIT_TX_WEIGHT: Weight = Weight::from_vb_unchecked(124);

/// The input weight required to claim a VTXO.
const VTXO_CLAIM_INPUT_WEIGHT: Weight = Weight::from_wu(138);

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

/// Returns the clause to unilaterally spend a VTXO
fn exit_clause(
	user_pubkey: PublicKey,
	exit_delta: u16,
) -> ScriptBuf {
	util::delayed_sign(exit_delta, user_pubkey.x_only_public_key().0)
}

/// Returns taproot spend info for a regular vtxo exit output.
pub fn exit_taproot(
	user_pubkey: PublicKey,
	asp_pubkey: PublicKey,
	exit_delta: u16,
) -> taproot::TaprootSpendInfo {
	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	taproot::TaprootBuilder::new()
		.add_leaf(0, exit_clause(user_pubkey, exit_delta)).unwrap()
		.finalize(&util::SECP, combined_pk).unwrap()
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


/// Type enum of [VtxoPolicy].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VtxoPolicyType {
	/// Standard VTXO output protected with a public key.
	Pubkey,
	/// A VTXO that represents an HTLC with the Ark server to send money.
	ServerHtlcSend,
	/// A VTXO that represents an HTLC with the Ark server to receive money.
	ServerHtlcRecv,
}

impl fmt::Display for VtxoPolicyType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    match self {
			Self::Pubkey => f.write_str("pubkey"),
			Self::ServerHtlcSend => f.write_str("server-htlc-send"),
			Self::ServerHtlcRecv => f.write_str("server-htlc-receive"),
		}
	}
}

impl FromStr for VtxoPolicyType {
	type Err = String;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"pubkey" => Self::Pubkey,
			"server-htlc-send" => Self::ServerHtlcSend,
			"server-htlc-receive" => Self::ServerHtlcRecv,
			_ => return Err(format!("unknown VtxoPolicyType: {}", s)),
		})
	}
}

impl serde::Serialize for VtxoPolicyType {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(self)
	}
}

impl<'de> serde::Deserialize<'de> for VtxoPolicyType {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = VtxoPolicyType;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a VtxoPolicyType")
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				VtxoPolicyType::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubkeyVtxoPolicy {
	pub user_pubkey: PublicKey,
}

impl From<PubkeyVtxoPolicy> for VtxoPolicy {
	fn from(policy: PubkeyVtxoPolicy) -> Self {
		Self::Pubkey(policy)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerHtlcSendVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub htlc_expiry: BlockHeight,
}

impl From<ServerHtlcSendVtxoPolicy> for VtxoPolicy {
	fn from(policy: ServerHtlcSendVtxoPolicy) -> Self {
		Self::ServerHtlcSend(policy)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerHtlcRecvVtxoPolicy {
	pub user_pubkey: PublicKey,
	pub payment_hash: PaymentHash,
	pub htlc_expiry: BlockHeight,
}

impl From<ServerHtlcRecvVtxoPolicy> for VtxoPolicy {
	fn from(policy: ServerHtlcRecvVtxoPolicy) -> Self {
		Self::ServerHtlcRecv(policy)
	}
}

/// The output policy of the VTXO.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VtxoPolicy {
	/// Standard VTXO output protected with a public key.
	///
	/// This can be the result of either:
	/// - a board
	/// - a round
	/// - an arkoor tx
	/// - change from a LN payment
	Pubkey(PubkeyVtxoPolicy),
	/// A VTXO that represents an HTLC with the Ark server to send money.
	ServerHtlcSend(ServerHtlcSendVtxoPolicy),
	/// A VTXO that represents an HTLC with the Ark server to receive money.
	ServerHtlcRecv(ServerHtlcRecvVtxoPolicy),
}

impl VtxoPolicy {
	pub fn new_pubkey(user_pubkey: PublicKey) -> Self {
		Self::Pubkey(PubkeyVtxoPolicy { user_pubkey })
	}

	pub fn new_server_htlc_send(user_pubkey: PublicKey, payment_hash: PaymentHash, htlc_expiry: BlockHeight) -> Self {
		Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry })
	}

	pub fn new_server_htlc_recv(user_pubkey: PublicKey, payment_hash: PaymentHash, htlc_expiry: BlockHeight) -> Self {
		Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry })
	}

	pub fn as_pubkey(&self) -> Option<&PubkeyVtxoPolicy> {
		match self {
			Self::Pubkey(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_server_htlc_send(&self) -> Option<&ServerHtlcSendVtxoPolicy> {
		match self {
			Self::ServerHtlcSend(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_server_htlc_recv(&self) -> Option<&ServerHtlcRecvVtxoPolicy> {
		match self {
			Self::ServerHtlcRecv(v) => Some(v),
			_ => None,
		}
	}

	/// The policy type id.
	pub fn policy_type(&self) -> VtxoPolicyType {
		match self {
			Self::Pubkey { .. } => VtxoPolicyType::Pubkey,
			Self::ServerHtlcSend { .. } => VtxoPolicyType::ServerHtlcSend,
			Self::ServerHtlcRecv { .. } => VtxoPolicyType::ServerHtlcRecv,
		}
	}

	/// Whether a [Vtxo] with this output can be spend in an arkoor tx.
	pub fn is_arkoor_compatible(&self) -> bool {
		match self {
			Self::Pubkey { .. } => true,
			Self::ServerHtlcSend { .. } => false,
			Self::ServerHtlcRecv { .. } => false,
		}
	}

	/// The public key used to cosign arkoor txs spending a [Vtxo] with this output.
	/// This will return [None] if [VtxoPolicy::is_arkoor_compatible] returns false.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => Some(*user_pubkey),
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, .. }) => Some(*user_pubkey),
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, .. }) => Some(*user_pubkey),
		}
	}

	/// Returns the user pubkey associated with a [Vtxo] with this output.
	pub fn user_pubkey(&self) -> PublicKey {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => *user_pubkey,
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, .. }) => *user_pubkey,
		}
	}

	pub(crate) fn taproot(
		&self,
		asp_pubkey: PublicKey,
		exit_delta: u16,
	) -> taproot::TaprootSpendInfo {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				exit_taproot(*user_pubkey, asp_pubkey, exit_delta)
			},
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				server_htlc_send_taproot(*payment_hash, asp_pubkey, *user_pubkey, exit_delta, *htlc_expiry)
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				server_htlc_receive_taproot(*payment_hash, asp_pubkey, *user_pubkey, exit_delta, *htlc_expiry)
			},
		}
	}

	/// Returns the tapscript internal to the [VtxoPolicy::taproot] that is used for the user exit.
	pub fn user_exit_clause(&self, exit_delta: u16) -> ScriptBuf {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				exit_clause(*user_pubkey, exit_delta)
			},
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, htlc_expiry, .. }) => {
				util::delay_timelock_sign(
					2 * exit_delta, *htlc_expiry, user_pubkey.x_only_public_key().0,
				)
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, .. }) => {
				util::hash_delay_sign(
					payment_hash.to_sha256_hash(), 2 * exit_delta, user_pubkey.x_only_public_key().0,
				)
			},
		}

	}

	pub(crate) fn script_pubkey(&self, asp_pubkey: PublicKey, exit_delta: u16) -> ScriptBuf {
		self.taproot(asp_pubkey, exit_delta).script_pubkey()
	}

	pub(crate) fn txout(&self, amount: Amount, asp_pubkey: PublicKey, exit_delta: u16) -> TxOut {
		TxOut {
			value: amount,
			script_pubkey: self.script_pubkey(asp_pubkey, exit_delta),
		}
	}
}

/// A transition from one genesis tx to the next.
///
/// See private module-level documentation for more info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GenesisTransition {
	/// A transition based on a cosignature.
	///
	/// This can be either the result of a cosigned "clArk" tree branch transition
	/// or a board which is cosigned just with the server.
	Cosigned {
		/// All the user cosign pubkeys signing the node.
		///
		/// Has to include server's cosign pubkey because it differs
		/// from its regular pubkey.
		pubkeys: Vec<PublicKey>,
		signature: schnorr::Signature,
	},
	/// A regular arkoor spend, using the co-signed p2tr key-spend path.
	Arkoor {
		policy: VtxoPolicy,
		signature: Option<schnorr::Signature>,
	},
}

impl GenesisTransition {
	/// Taproot that this transition is satisfying.
	fn input_taproot(
		&self,
		asp_pubkey: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: u16,
	) -> taproot::TaprootSpendInfo {
		match self {
			Self::Cosigned { pubkeys, .. } => {
				let agg_pk = musig::combine_keys(pubkeys.iter().copied());
				cosign_taproot(agg_pk, asp_pubkey, expiry_height)
			},
			Self::Arkoor { policy, .. } => policy.taproot(asp_pubkey, exit_delta),
		}
	}

	/// Output that this transition is spending.
	fn input_txout(
		&self,
		amount: Amount,
		asp_pubkey: PublicKey,
		expiry_height: BlockHeight,
		exit_delta: u16,
	) -> TxOut {
		let taproot = self.input_taproot(asp_pubkey, expiry_height, exit_delta);
		TxOut {
			value: amount,
			script_pubkey: taproot.script_pubkey(),
		}
	}

	/// The transaction witness for this transition.
	fn witness(&self) -> Witness {
		match self {
			Self::Cosigned { signature, .. } => Witness::from_slice(&[&signature[..]]),
			Self::Arkoor { signature: Some(sig), .. } => Witness::from_slice(&[&sig[..]]),
			Self::Arkoor { signature: None, .. } => Witness::new(),
		}
	}

	/// Whether this transition is spending a policy that also contains an exit clause.
	fn has_exit(&self) -> bool {
		match self {
			Self::Cosigned { .. } => false,
			Self::Arkoor { .. } => true,
		}
	}
}

/// An item in a VTXO's genesis.
///
/// See private module-level documentation for more info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GenesisItem {
	/// The transition from the previous tx to this one.
	pub(crate) transition: GenesisTransition,
	/// The output index ("vout") of the output going to the next genesis item.
	pub(crate) output_idx: u8,
	/// The other outputs to construct the exit tx.
	// NB empty for the first item
	pub(crate) other_outputs: Vec<TxOut>,
}

impl GenesisItem {
	/// Construct the exit transaction at this level of the genesis.
	fn tx(&self, prev: OutPoint, next: TxOut) -> Transaction {
		Transaction {
			version: bitcoin::transaction::Version(3),
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: prev,
				script_sig: ScriptBuf::new(),
				sequence: Sequence::ZERO,
				witness: self.transition.witness(),
			}],
			output: {
				let mut out = Vec::with_capacity(self.other_outputs.len() + 2);
				out.extend(self.other_outputs.iter().take(self.output_idx as usize).cloned());
				out.push(next);
				out.extend(self.other_outputs.iter().skip(self.output_idx as usize).cloned());
				out.push(fee::fee_anchor());
				out
			},
		}
	}
}

/// Type of the items yielded by [VtxoTxIter], the iterator returned by
/// [Vtxo::transactions].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VtxoTxIterItem {
	/// The actual transaction.
	pub tx: Transaction,
	/// Whether this tx is an exit tx, meaning that it contains exit outputs.
	pub is_exit: bool,
}

//TODO(stevenroose) what do you guys think?
// impl std::ops::Deref for VtxoTxIterItem {
// 	type Target = Transaction;
// 	fn deref(&self) -> &Self::Target {
// 	    &self.tx
// 	}
// }

/// Iterator returned by [Vtxo::transactions].
pub struct VtxoTxIter<'a> {
	vtxo: &'a Vtxo,

	prev: OutPoint,
	genesis_idx: usize,
	current_amount: Amount,
	/// We're in the end part of the chain where txs are exit txs.
	/// This can only go from false to true, not back to false.
	exit: bool,
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
			exit: false,
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
			self.exit = self.exit || item.transition.has_exit();
			item.transition.input_txout(
				next_amount,
				self.vtxo.asp_pubkey,
				self.vtxo.expiry_height,
				self.vtxo.exit_delta,
			)
		} else {
			// when we reach the end of the chain, we take the eventual output of the vtxo
			self.done = true;
			self.exit = true;
			self.vtxo.policy.txout(self.vtxo.amount, self.vtxo.asp_pubkey, self.vtxo.exit_delta)
		};

		let tx = item.tx(self.prev, next_output);
		self.prev = OutPoint::new(tx.compute_txid(), item.output_idx as u32);
		self.genesis_idx += 1;
		self.current_amount = next_amount;
		Some(VtxoTxIterItem { tx, is_exit: self.exit })
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
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,
}

impl VtxoSpec {
	/// The taproot spend info for the output of this [Vtxo].
	pub fn output_taproot(&self) -> taproot::TaprootSpendInfo {
		self.policy.taproot(self.asp_pubkey, self.exit_delta)
	}

	/// The scriptPubkey of the output of this [Vtxo].
	pub fn output_script_pubkey(&self) -> ScriptBuf {
		self.policy.script_pubkey(self.asp_pubkey, self.exit_delta)
	}

	/// The transaction output (eventual UTXO) of this [Vtxo].
	pub fn txout(&self) -> TxOut {
		self.policy.txout(self.amount, self.asp_pubkey, self.exit_delta)
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

	pub(crate) asp_pubkey: PublicKey,
	pub(crate) exit_delta: u16,

	pub(crate) anchor_point: OutPoint,
	pub(crate) genesis: Vec<GenesisItem>,

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
			asp_pubkey: self.asp_pubkey,
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
	pub fn policy_type(&self) -> VtxoPolicyType {
		self.policy.policy_type()
	}

	/// The expiry height of the [Vtxo].
	pub fn expiry_height(&self) -> BlockHeight {
		self.expiry_height
	}

	/// The server pubkey used in arkoor transitions.
	pub fn asp_pubkey(&self) -> PublicKey {
		self.asp_pubkey
	}

	/// The relative timelock block delta used for exits.
	pub fn exit_delta(&self) -> u16 {
		self.exit_delta
	}

	/// Returns the OOR depth of the vtxo.
	pub fn arkoor_depth(&self) -> u16 {
		// NB this relies on the invariant that all arkoor transitions
		// follow the cosign transitions
		self.genesis.iter().rev().take_while(|item| match item.transition {
			GenesisTransition::Cosigned { .. } => false,
			GenesisTransition::Arkoor { .. } => true,
		}).count() as u16
	}

	/// Get the payment hash if this vtxo is an HTLC send arkoor vtxo.
	pub fn server_htlc_out_payment_hash(&self) -> Option<PaymentHash> {
		match self.policy {
			VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy { payment_hash, .. }) => Some(payment_hash),
			VtxoPolicy::ServerHtlcRecv { .. } => None,
			VtxoPolicy::Pubkey { .. } => None,
		}
	}

	/// Whether this [Vtxo] can be spent in an arkoor tx.
	pub fn is_arkoor_compatible(&self) -> bool {
		self.genesis.iter().all(|i| match i.transition {
			GenesisTransition::Cosigned { .. } => true,
			GenesisTransition::Arkoor { ref policy, .. } => policy.is_arkoor_compatible(),
		}) && self.policy.is_arkoor_compatible()
	}

	/// The public key used to cosign arkoor txs spending this [Vtxo].
	/// This will return [None] if [Vtxo::is_arkoor_compatible] returns false.
	pub fn arkoor_pubkey(&self) -> Option<PublicKey> {
		self.policy.arkoor_pubkey()
	}

	/// Iterate over all arkoor pubkeys in the arkoor chain of this vtxo.
	///
	/// This does not include the current arkoor pubkey, for that use
	/// [Vtxo::arkoor_pubkey].
	pub fn past_arkoor_pubkeys(&self) -> impl Iterator<Item = PublicKey> + '_ {
		self.genesis.iter().filter_map(|g| {
			match g.transition {
				// NB in principle, a genesis item's transition MUST have
				// an arkoor pubkey, otherwise the vtxo is invalid
				GenesisTransition::Arkoor { ref policy, .. } => policy.arkoor_pubkey(),
				_ => None,
			}
		})
	}

	/// Returns the user pubkey associated with this [Vtxo].
	pub fn user_pubkey(&self) -> PublicKey {
		self.policy.user_pubkey()
	}

	/// The taproot spend info for the output of this [Vtxo].
	pub fn output_taproot(&self) -> taproot::TaprootSpendInfo {
		self.policy.taproot(self.asp_pubkey, self.exit_delta)
	}

	/// The scriptPubkey of the output of this [Vtxo].
	pub fn output_script_pubkey(&self) -> ScriptBuf {
		self.policy.script_pubkey(self.asp_pubkey, self.exit_delta)
	}

	/// The transaction output (eventual UTXO) of this [Vtxo].
	pub fn txout(&self) -> TxOut {
		self.policy.txout(self.amount, self.asp_pubkey, self.exit_delta)
	}

	/// Whether this VTXO contains our-of-round parts. This is true for both
	/// arkoor and lightning vtxos.
	pub fn is_arkoor(&self) -> bool {
		self.genesis.iter().any(|t| t.transition.has_exit())
	}

	/// Iterator that constructs all the exit txs for this [Vtxo].
	pub fn transactions(&self) -> VtxoTxIter {
		VtxoTxIter::new(self)
	}

	/// The satisfaction weight required to spend the output
	/// when doing a unilateral exit.
	pub fn claim_satisfaction_weight(&self)  -> Weight {
		match self.policy {
			VtxoPolicy::Pubkey { .. } => VTXO_CLAIM_INPUT_WEIGHT,
			//TODO(stevenroose) think about this. it's the same if you use keyspend
			// but it's not the same if you have to use exit spend
			// I guess the same holds for any vtxo
			VtxoPolicy::ServerHtlcSend { .. } => VTXO_CLAIM_INPUT_WEIGHT,
			VtxoPolicy::ServerHtlcRecv { .. } => VTXO_CLAIM_INPUT_WEIGHT,
		}
	}

	/// Fully validate this VTXO and its entire transaction chain.
	///
	/// The `chain_anchor_tx` must be the tx with txid matching
	/// [Vtxo::chain_anchor].
	pub fn validate(
		&self,
		chain_anchor_tx: &Transaction,
	) -> Result<Validation, VtxoValidationError> {
		self::validation::validate(&self, chain_anchor_tx)
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

/// The byte used to encode the [VtxoPolicy::Pubkey] output type.
const VTXO_POLICY_REGULAR: u8 = 0x01;

/// The byte used to encode the [VtxoPolicy::ServerHtlcSend] output type.
const VTXO_POLICY_SERVER_HTLC_SEND: u8 = 0x02;

/// The byte used to encode the [VtxoPolicy::ServerHtlcRecv] output type.
const VTXO_POLICY_SERVER_HTLC_RECV: u8 = 0x03;

impl ProtocolEncoding for VtxoPolicy {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }) => {
				w.emit_u8(VTXO_POLICY_REGULAR)?;
				user_pubkey.encode(w)?;
			},
			Self::ServerHtlcSend(ServerHtlcSendVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				w.emit_u8(VTXO_POLICY_SERVER_HTLC_SEND)?;
				user_pubkey.encode(w)?;
				payment_hash.to_sha256_hash().encode(w)?;
				w.emit_u32(*htlc_expiry)?;
			},
			Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }) => {
				w.emit_u8(VTXO_POLICY_SERVER_HTLC_RECV)?;
				user_pubkey.encode(w)?;
				payment_hash.to_sha256_hash().encode(w)?;
				w.emit_u32(*htlc_expiry)?;
			},
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		match r.read_u8()? {
			VTXO_POLICY_REGULAR => {
				let user_pubkey = PublicKey::decode(r)?;
				Ok(Self::Pubkey(PubkeyVtxoPolicy { user_pubkey }))
			},
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
				Ok(Self::ServerHtlcRecv(ServerHtlcRecvVtxoPolicy { user_pubkey, payment_hash, htlc_expiry }))
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid VtxoType type byte: {v:x}",
			))),
		}
	}
}

/// The byte used to encode the [GenesisTransition::Cosigned] gen transition type.
const GENESIS_TRANSITION_TYPE_COSIGNED: u8 = 1;

/// The byte used to encode the [GenesisTransition::Arkoor] gen transition type.
const GENESIS_TRANSITION_TYPE_ARKOOR: u8 = 2;

impl ProtocolEncoding for GenesisTransition {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Cosigned { pubkeys, signature } => {
				w.emit_u8(GENESIS_TRANSITION_TYPE_COSIGNED)?;
				w.emit_u16(pubkeys.len().try_into().expect("cosign pubkey length overflow"))?;
				for pk in pubkeys {
					pk.encode(w)?;
				}
				signature.encode(w)?;
			},
			Self::Arkoor { policy, signature } => {
				w.emit_u8(GENESIS_TRANSITION_TYPE_ARKOOR)?;
				policy.encode(w)?;
				signature.encode(w)?;
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
				Ok(Self::Cosigned { pubkeys, signature })
			},
			GENESIS_TRANSITION_TYPE_ARKOOR => {
				let policy = VtxoPolicy::decode(r)?;
				let signature = Option::<schnorr::Signature>::decode(r)?;
				Ok(Self::Arkoor { policy, signature })
			},
			v => Err(ProtocolDecodingError::invalid(format_args!(
				"invalid GenesisTransistion type byte: {v:x}",
			))),
		}
	}
}

impl ProtocolEncoding for Vtxo {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_u16(VTXO_ENCODING_VERSION)?;
		w.emit_u64(self.amount.to_sat())?;
		w.emit_u32(self.expiry_height)?;
		self.asp_pubkey.encode(w)?;
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
				"invalid Vtxo encoding version byte: {version:x}",
			)));
		}

		let amount = Amount::from_sat(r.read_u64()?);
		let expiry_height = r.read_u32()?;
		let asp_pubkey = PublicKey::decode(r)?;
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
			amount, expiry_height, asp_pubkey, exit_delta, anchor_point, genesis, policy: output, point,
		})
	}
}


#[cfg(any(test, feature = "test-util"))]
pub mod test {
	use std::iter;
	use std::collections::HashMap;

	use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
	use bitcoin::hex::DisplayHex;
	use bitcoin::secp256k1::Keypair;
	use bitcoin::transaction::Version;

	use crate::arkoor::ArkoorBuilder;
	use crate::board::BoardBuilder;
	use crate::encode::test::encoding_roundtrip;
	use crate::tree::signed::VtxoTreeSpec;
	use crate::util::SECP;
	use crate::{SignedVtxoRequest, VtxoRequest};

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
		pub anchor_tx: Transaction,
		pub board_vtxo: Vtxo,

		pub arkoor_htlc_out_vtxo: Vtxo,
		pub arkoor2_vtxo: Vtxo,

		pub round_tx: Transaction,
		pub round1_vtxo: Vtxo,
		pub round2_vtxo: Vtxo,

		pub arkoor3_vtxo: Vtxo,
	}

	#[allow(unused)] // under the "test-util" feature it's unused
	fn generate_vtxo_vectors() -> VtxoTestVectors {
		let expiry_height = 101_010;
		let exit_delta = 2016;
		let asp_key = Keypair::from_str("916da686cedaee9a9bfb731b77439f2a3f1df8664e16488fba46b8d2bfe15e92").unwrap();
		let board_user_key = Keypair::from_str("fab9e598081a3e74b2233d470c4ad87bcc285b6912ed929568e62ac0e9409879").unwrap();
		let amount = Amount::from_sat(10_000);
		let builder = BoardBuilder::new(
			board_user_key.public_key(),
			expiry_height,
			asp_key.public_key(),
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
				builder.asp_pubkey,
				builder.exit_delta,
				amount,
				anchor_point,
				*builder.user_pub_nonce(),
			).server_cosign(&asp_key)
		};

		assert!(builder.verify_cosign_response(&board_cosign));
		let board_vtxo = builder.build_vtxo(&board_cosign, &board_user_key).unwrap();
		encoding_roundtrip(&board_vtxo);
		println!("board vtxo: {}", board_vtxo.serialize().as_hex());

		// arkoor1: htlc send

		let arkoor_htlc_out_user_key = Keypair::from_str("33b6f3ede430a1a53229f55da7117242d8392cbfc64a57249ba70731dba71408").unwrap();
		let payment_hash = PaymentHash::from(sha256::Hash::hash("arkoor1".as_bytes()).to_byte_array());
		let arkoor1out1 = VtxoRequest {
			amount: Amount::from_sat(9000),
			policy: VtxoPolicy::ServerHtlcSend(ServerHtlcSendVtxoPolicy {
				user_pubkey: arkoor_htlc_out_user_key.public_key(),
				payment_hash,
				htlc_expiry: expiry_height - 1000,
			}),
		};
		let arkoor1out2 = VtxoRequest {
			amount: Amount::from_sat(1000),
			policy: VtxoPolicy::new_pubkey("0229b7de0ce4d573192d002a6f9fd1109e00f7bae52bf10780d6f6e73e12a8390f".parse().unwrap()),
		};
		let outputs = [&arkoor1out1, &arkoor1out2];
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&board_user_key);
		let builder = ArkoorBuilder::new(&board_vtxo, &pub_nonce, &outputs).unwrap();
		let cosign = builder.server_cosign(&asp_key);
		assert!(builder.verify_cosign_response(&cosign));
		let [arkoor_htlc_out_vtxo, change] = builder.build_vtxos(
			sec_nonce, &board_user_key, &cosign,
		).unwrap().try_into().unwrap();
		encoding_roundtrip(&arkoor_htlc_out_vtxo);
		encoding_roundtrip(&change);
		println!("arkoor1_vtxo: {}", arkoor_htlc_out_vtxo.serialize().as_hex());

		// arkoor2: regular pubkey

		let arkoor2_user_key = Keypair::from_str("fcc43a4f03356092a945ca1d7218503156bed3f94c2fa224578ce5b158fbf5a6").unwrap();
		let arkoor2out1 = VtxoRequest {
			amount: Amount::from_sat(8000),
			policy: VtxoPolicy::new_pubkey(arkoor2_user_key.public_key()),
		};
		let arkoor2out2 = VtxoRequest {
			amount: Amount::from_sat(1000),
			policy: VtxoPolicy::new_pubkey("037039dc4f4b16e78059d2d56eb98d181cb1bdff2675694d39d92c4a2ea08ced88".parse().unwrap()),
		};
		let outputs = [&arkoor2out1, &arkoor2out2];
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&arkoor_htlc_out_user_key);
		let builder = ArkoorBuilder::new(&arkoor_htlc_out_vtxo, &pub_nonce, &outputs).unwrap();
		let arkoor2_cosign = builder.server_cosign(&asp_key);
		assert!(builder.verify_cosign_response(&arkoor2_cosign));
		let [arkoor2_vtxo, change] = builder.build_vtxos(
			sec_nonce, &arkoor_htlc_out_user_key, &arkoor2_cosign,
		).unwrap().try_into().unwrap();
		encoding_roundtrip(&arkoor2_vtxo);
		encoding_roundtrip(&change);
		println!("arkoor2_vtxo: {}", arkoor2_vtxo.serialize().as_hex());

		// round

		//TODO(stevenroose) rename to round htlc in
		let round1_user_key = Keypair::from_str("0a832e9574070c94b5b078600a18639321c880c830c5ba2f2a96850c7dcc4725").unwrap();
		let round1_cosign_key = Keypair::from_str("e14bfc3199842c76816eec1d93c9da00b850c4ed19e414e246d07e845e465a2b").unwrap();
		println!("round1_cosign_key: {}", round1_cosign_key.public_key());
		let round1_req = SignedVtxoRequest {
			vtxo: VtxoRequest {
				amount: Amount::from_sat(10_000),
				policy: VtxoPolicy::new_pubkey(round1_user_key.public_key()),
			},
			cosign_pubkey: round1_cosign_key.public_key(),
		};
		let round1_nonces = iter::repeat_with(|| musig::nonce_pair(&round1_cosign_key)).take(5).collect::<Vec<_>>();

		let round2_user_key = Keypair::from_str("c0b645b01cac427717a18b30c7c9238dee2b3885f659930144fbe05061ad6166").unwrap();
		let round2_cosign_key = Keypair::from_str("628789cd7b7e02766d184ecfecc433798c9640349e41822df7996c66a56fc633").unwrap();
		println!("round2_cosign_key: {}", round2_cosign_key.public_key());
		let round2_payment_hash = PaymentHash::from(sha256::Hash::hash("round2".as_bytes()).to_byte_array());
		let round2_req = SignedVtxoRequest {
			vtxo: VtxoRequest {
				amount: Amount::from_sat(10_000),
				policy: VtxoPolicy::new_server_htlc_recv(
					round2_user_key.public_key(),
					round2_payment_hash,
					expiry_height - 2000,
				),
			},
			cosign_pubkey: round2_cosign_key.public_key(),
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
			other_reqs.push(SignedVtxoRequest {
				vtxo: VtxoRequest {
					amount: Amount::from_sat(5_000),
					policy: VtxoPolicy::new_pubkey(user_key.public_key()),
				},
				cosign_pubkey: cosign_key.public_key(),
			});
			other_nonces.push(iter::repeat_with(|| musig::nonce_pair(&cosign_key)).take(5).collect::<Vec<_>>());
		}

		let asp_cosign_key = Keypair::from_str("4371a4a7989b89ebe1b2582db4cd658cb95070977e6f10601ddc1e9b53edee79").unwrap();
		let spec = VtxoTreeSpec::new(
			[&round1_req, &round2_req].into_iter().chain(other_reqs.iter()).cloned().collect(),
			asp_key.public_key(),
			asp_cosign_key.public_key(),
			expiry_height,
			exit_delta,
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
				script_pubkey: spec.round_tx_script_pubkey(),
			}],
		};
		println!("round tx: {}", serialize_hex(&round_tx));
		let all_nonces = {
			let mut map = HashMap::new();
			map.insert(round1_cosign_key.public_key(), round1_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			map.insert(round2_cosign_key.public_key(), round2_nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			for (req, nonces) in other_reqs.iter().zip(other_nonces.iter()) {
				map.insert(req.cosign_pubkey, nonces.iter().map(|n| n.1).collect::<Vec<_>>());
			}
			map
		};
		let (asp_cosign_sec_nonces, asp_cosign_pub_nonces) = iter::repeat_with(|| {
			musig::nonce_pair(&asp_cosign_key)
		}).take(spec.nb_nodes()).unzip::<_, _, Vec<_>, Vec<_>>();
		let cosign_agg_nonces = spec.calculate_cosign_agg_nonces(&all_nonces, &asp_cosign_pub_nonces);
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
				map.insert(req.cosign_pubkey, {
					let secs = nonces.into_iter().map(|(s, _)| s).collect();
					tree.cosign_branch(&cosign_agg_nonces, 2 + i, &cosign_key, secs).unwrap()
				});
			}
			map
		};
		let asp_cosign_sigs = tree.cosign_tree(
			&cosign_agg_nonces, &asp_cosign_key, asp_cosign_sec_nonces,
		);
		let cosign_sigs = tree.combine_partial_signatures(&cosign_agg_nonces, &part_sigs, asp_cosign_sigs).unwrap();
		tree.verify_cosign_sigs(&cosign_sigs).unwrap();
		let signed = tree.into_signed_tree(cosign_sigs).into_cached_tree();
		// we don't need forfeits
		let mut vtxo_iter = signed.all_vtxos();
		let round1_vtxo = vtxo_iter.next().unwrap();
		encoding_roundtrip(&round1_vtxo);
		println!("round1_vtxo: {}", round1_vtxo.serialize().as_hex());
		let round2_vtxo = vtxo_iter.next().unwrap();
		encoding_roundtrip(&round2_vtxo);
		println!("round2_vtxo: {}", round2_vtxo.serialize().as_hex());

		// arkoor3: off from round2's htlc

		let arkoor3_user_key = Keypair::from_str("ad12595bdbdab56cb61d1f60ccc46ff96b11c5d6fe06ae7ba03d3a5f4347440f").unwrap();
		let arkoor3out = VtxoRequest {
			amount: Amount::from_sat(10_000),
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: arkoor3_user_key.public_key() }),
		};
		let outputs = [&arkoor3out];
		let (sec_nonce, pub_nonce) = musig::nonce_pair(&round2_user_key);
		let builder = ArkoorBuilder::new(&round2_vtxo, &pub_nonce, &outputs).unwrap();
		let arkoor3_cosign = builder.server_cosign(&asp_key);
		assert!(builder.verify_cosign_response(&arkoor3_cosign));
		let [arkoor3_vtxo] = builder.build_vtxos(
			sec_nonce, &round2_user_key, &arkoor3_cosign,
		).unwrap().try_into().unwrap();
		encoding_roundtrip(&arkoor3_vtxo);
		println!("arkoor3_vtxo: {}", arkoor3_vtxo.serialize().as_hex());

		VtxoTestVectors {
			anchor_tx,
			board_vtxo,
			arkoor_htlc_out_vtxo,
			arkoor2_vtxo,
			round_tx,
			round1_vtxo,
			round2_vtxo,
			arkoor3_vtxo,
		}
	}

	lazy_static! {
		/// A set of deterministically generated and fully correct VTXOs.
		pub static ref VTXO_VECTORS: VtxoTestVectors = VtxoTestVectors {
			anchor_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000011027000000000000225120652675904a84ea02e24b57b3d547203d2ce71526113d35bf4d02e0b4efbe9a2d00000000").unwrap(),
			board_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000001010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b628cd6bef7a3ec8e0c19e0df56a0cc217afd4f0fa5a6055caf53a50df9984f6b9c286c1b07dcc8066c95e1cee8db94ca2d7283c6efccee2efcea67ac4012de67c7010001030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee4c99b744ad009b7070f330794bf003fa8e5cd46ea1a6eb854aaf469385e3080000000000").unwrap(),
			arkoor_htlc_out_vtxo: ProtocolEncoding::deserialize_hex("01002823000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000002010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b628cd6bef7a3ec8e0c19e0df56a0cc217afd4f0fa5a6055caf53a50df9984f6b9c286c1b07dcc8066c95e1cee8db94ca2d7283c6efccee2efcea67ac4012de67c701000201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee1d06597c1b5acd7bf94b19596da30b1eec4ce6be5b6aa64466592dfd160b3f2c841b3ae313b8055e7f5f9a2692805e27e60aff793d41f9709118a5e597fa65d70200e8030000000000002251209b987ec3c169c70d1ed6aef420a4858e3e3ec9d8404358787d4e06ba926a4ae40203eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73712358912c950a9a7d04bb9011ee9f6a16b6127a5aab7415803d48c0225f620f5aa860100c692b81703c12cac1e8d69b86fa9f0e2f167168d96ae1045ef8d9192bc4a6e4c00000000").unwrap(),
			arkoor2_vtxo: ProtocolEncoding::deserialize_hex("0100401f000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007ed4d23932a2625a78fe5c75bded751da3a99e23a297a527c01bd7bc8372128f20000000003010200030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee0365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b628cd6bef7a3ec8e0c19e0df56a0cc217afd4f0fa5a6055caf53a50df9984f6b9c286c1b07dcc8066c95e1cee8db94ca2d7283c6efccee2efcea67ac4012de67c701000201030a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee1d06597c1b5acd7bf94b19596da30b1eec4ce6be5b6aa64466592dfd160b3f2c841b3ae313b8055e7f5f9a2692805e27e60aff793d41f9709118a5e597fa65d70200e8030000000000002251209b987ec3c169c70d1ed6aef420a4858e3e3ec9d8404358787d4e06ba926a4ae4020203eb4570ae385202d4a48f06bdb14126910b90c07f8e42d7dc5e28a860c085e73712358912c950a9a7d04bb9011ee9f6a16b6127a5aab7415803d48c0225f620f5aa8601001271637adbd04c6eb5a654ff34c8abc84ea2fe4871196d47d4d0617fb9ae0e50bebcf7335a6cfda5267f0b09c5243a1a0c047f10cc2ee2583a00bd544655d8a70200e80300000000000022512018d297ade3cfbb7080b65e21af238ac88c15e38734f5f462530c34a225e80ca9010265cca13271cafd0b90c440e722a1937b7c4faf4ccd7dee0548d152c24ce4b2a8d4f7d410cf052720ffc5ce4668c4371448ffe98b7037f7c42aa943d717fcd67700000000").unwrap(),
			round_tx: deserialize_hex("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff000000000001c8af000000000000225120649657f65947abfd83ff629ad8a851c795f419ed4d52a2748d3f868cc3e6c94d00000000").unwrap(),
			round1_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000003010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433070e6dfa9d859b6c6d4f808916b83f8de90d1d20a5f0b62f3f128e0a761db30e2b6e40364a4237d32637c30a0c9e7bcd57ae54b1f1e144cd269694ad08adbb604038813000000000000225120c6b818ec8692762e68c7bd4c6d4ccebf4c764deb670a2b39daa0d05f53a1c07f8813000000000000225120b1daa25905430275c3b86e002bc586337fc4315e0c2a585969cf0ae60fad2f268813000000000000225120e790cc3be3288cd57290afd4cc977f4aca98023f0cfbad671768b25376e8a5c8010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433e9f7c1d5a6be5a8d3b352756b0774561d520a1038bd5e06d760ea443f91f45846517e1c501b5667b38e1f7909aab61f3ed5105f6e3820f8ef2df0c785974fc904001027000000000000225120b54cbc99321d02aa2114fabb39dc5e8f346e88296dcec79b1b3c0849caba3d6f881300000000000022512058460fc9dbe1e0acb12eeabd9423161ce27fbb50dccab1179f2d843f455354a78813000000000000225120f6dbe7d3ee38ca1eb90721b3ae9d26f456e9e8b305451bede118d42807a471ef010200036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b242743d4dc21f8e941c0692c3c0436c5f6b8addfdb2b9bace74ca710c9edc2f7f14b80a3481b859376d198b2cdf375bf4d364eb4a73d7fd83c9e039045ae01d592d1a50100010374a3ec37cc4ccd29717388e6dc24f2aa366632f1a36a49e73cd7671b231792988588da5d9b08f1767aab3b3a78b6cd27deb937193e153300bcf84b3eeaaef07200000000").unwrap(),
			round2_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000003010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433070e6dfa9d859b6c6d4f808916b83f8de90d1d20a5f0b62f3f128e0a761db30e2b6e40364a4237d32637c30a0c9e7bcd57ae54b1f1e144cd269694ad08adbb604038813000000000000225120c6b818ec8692762e68c7bd4c6d4ccebf4c764deb670a2b39daa0d05f53a1c07f8813000000000000225120b1daa25905430275c3b86e002bc586337fc4315e0c2a585969cf0ae60fad2f268813000000000000225120e790cc3be3288cd57290afd4cc977f4aca98023f0cfbad671768b25376e8a5c8010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433e9f7c1d5a6be5a8d3b352756b0774561d520a1038bd5e06d760ea443f91f45846517e1c501b5667b38e1f7909aab61f3ed5105f6e3820f8ef2df0c785974fc9040110270000000000002251202df700706227474e89354e4ad3ac28f007952140fff42a5a0f0675bdff87f6b3881300000000000022512058460fc9dbe1e0acb12eeabd9423161ce27fbb50dccab1179f2d843f455354a78813000000000000225120f6dbe7d3ee38ca1eb90721b3ae9d26f456e9e8b305451bede118d42807a471ef010200024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc4024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b24274394d8831a07bb3e931cc286d02ddd0a4e23620bdd6d65eb3303c9bb97ac460d8022129f4cc445a852428aaea62fb2703337f2815c644d27b7f8c83ad827a3ce350100030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd9ea50d885c3f66d40d27e779648ba8dc730629663f65a3e6f7749b4a35b6dfecc2820100ce5129b0580c862b0406957e0b12d44a7ef6be930fc0f450e8ff36dcfe2562ba00000000").unwrap(),
			arkoor3_vtxo: ProtocolEncoding::deserialize_hex("01001027000000000000928a01000365a81233741893bbe2461b8d479dadc5880594fe6f7479180d5843820af72b62e007a3c23c49874159964c52b95021596d5a22e8f8b6bc7c16aa8303c24498d3d5ab0000000004010800039e8a040d9c1fba5a7b0db8485d8f167f8d2590afd8595f9eb9ba7a769347ba2602bd0ad185b18089d37d20dd784b99003914faadcc59f37bbf3273a3b5cd22ed5002568a3a6d25000fc942f0443dc76be4ef688e8c8dc055591de1f2cc1c847b1ed3036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433070e6dfa9d859b6c6d4f808916b83f8de90d1d20a5f0b62f3f128e0a761db30e2b6e40364a4237d32637c30a0c9e7bcd57ae54b1f1e144cd269694ad08adbb604038813000000000000225120c6b818ec8692762e68c7bd4c6d4ccebf4c764deb670a2b39daa0d05f53a1c07f8813000000000000225120b1daa25905430275c3b86e002bc586337fc4315e0c2a585969cf0ae60fad2f268813000000000000225120e790cc3be3288cd57290afd4cc977f4aca98023f0cfbad671768b25376e8a5c8010500036e64c16a01e3d18908a15b55251a5db74ff2c1142c02abd048222893b2a18a16024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc403932b1b0224e375471c938ea84bd17df7d8295941b2db68a6623610dd959b2eb303d215f5e88aefa7a2a9794771878f3d6caf20e884c1e0ce923cfa9dea261bb4e2024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b2427433e9f7c1d5a6be5a8d3b352756b0774561d520a1038bd5e06d760ea443f91f45846517e1c501b5667b38e1f7909aab61f3ed5105f6e3820f8ef2df0c785974fc9040110270000000000002251202df700706227474e89354e4ad3ac28f007952140fff42a5a0f0675bdff87f6b3881300000000000022512058460fc9dbe1e0acb12eeabd9423161ce27fbb50dccab1179f2d843f455354a78813000000000000225120f6dbe7d3ee38ca1eb90721b3ae9d26f456e9e8b305451bede118d42807a471ef010200024ac23c8d3f6e0b1116e34f68ee7c9e4c19eba30213e8fae0925d70faf8d1ecc4024482039ebf3624525061f88aa01d4a02b3f2224eee8b4060ae0cbf036b24274394d8831a07bb3e931cc286d02ddd0a4e23620bdd6d65eb3303c9bb97ac460d8022129f4cc445a852428aaea62fb2703337f2815c644d27b7f8c83ad827a3ce35010002030256fda20ffb102f6cf8590d27433ce036d29927fb35324d15d9915df888f16ecd9ea50d885c3f66d40d27e779648ba8dc730629663f65a3e6f7749b4a35b6dfecc2820100b8832e765bd33dc93da5c013e55bc32962243e59be0330348cb1a51f1961296156b7465e3679e8049fd2213f87c8bc9b09a57fe95fab1e6d44e6d5475bab6a2601000102ed1334f116cea9128e1f59f1d5a431cb4f338f0998e2b32f654c310bf7831f97c65dc59b3a15c10f5502838454d82054ce3ea7190c4003af9df79ff11ea5c9ab00000000").unwrap(),
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

		// this passes because the Eq is based on id which doesn't compare signatures
		assert_eq!(g, *v);
	}

	#[test]
	fn arkoor_depth() {
		let vtxos = &*VTXO_VECTORS;
		// board
		assert_eq!(vtxos.board_vtxo.arkoor_depth(), 0);

		// round
		assert_eq!(vtxos.round1_vtxo.arkoor_depth(), 0);

		// arkoor
		assert_eq!(vtxos.arkoor_htlc_out_vtxo.arkoor_depth(), 1);
		assert_eq!(vtxos.arkoor2_vtxo.arkoor_depth(), 2);
		assert_eq!(vtxos.arkoor3_vtxo.arkoor_depth(), 1);
	}
}
