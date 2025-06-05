
use std::fmt;
use std::str::FromStr;

use bitcoin::{
	taproot, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness
};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};

use bitcoin_ext::{fee, BlockHeight};

use crate::lightning::{htlc_in_taproot, htlc_out_taproot};
use crate::board::BoardVtxo;
use crate::arkoor::ArkoorVtxo;
use crate::rounds::RoundVtxo;
use crate::util::{Decodable, Encodable};
use crate::{musig, arkoor, util};


/// The total signed tx weight of a exit tx.
pub const EXIT_TX_WEIGHT: Weight = Weight::from_vb_unchecked(124);

/// The input weight required to claim a VTXO.
const VTXO_CLAIM_INPUT_WEIGHT: Weight = Weight::from_wu(138);


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

/// Returns taproot spend infos to build an exit spk
fn exit_taproot(
	user_pubkey: PublicKey,
	asp_pubkey: PublicKey,
	exit_delta: u16,
) -> taproot::TaprootSpendInfo {
	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	taproot::TaprootBuilder::new()
		.add_leaf(0, exit_clause(user_pubkey, exit_delta)).unwrap()
		.finalize(&util::SECP, combined_pk).unwrap()
}

/// Returns a scriptPubkey that can be used as a VTXO spk to let user
/// unilaterally exit the Ark
pub fn exit_spk(
	user_pubkey: PublicKey,
	asp_pubkey: PublicKey,
	exit_delta: u16,
) -> ScriptBuf {
	let taproot = exit_taproot(user_pubkey, asp_pubkey, exit_delta);
	ScriptBuf::new_p2tr_tweaked(taproot.output_key())
}

/// Create an exit tx.
///
/// When the `signature` argument is provided,
/// it will be placed in the input witness.
pub fn create_exit_tx(
	spec: &VtxoSpec,
	prevout: OutPoint,
	signature: Option<&schnorr::Signature>,
) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version(3),
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: prevout,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: {
				let mut ret = Witness::new();
				if let Some(sig) = signature {
					ret.push(&sig[..]);
				}
				ret
			},
		}],
		output: vec![
			spec.txout(),
			fee::fee_anchor(),
		],
	}
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum VtxoSpkSpec {
	/// A simple sign-or-exit spk
	Exit,
	/// An HTLC from client to server, to atomically receive in the Ark from outside
	HtlcIn {
		payment_hash: sha256::Hash,
		htlc_expiry: u32,
	},
	/// An HTLC from server to client, to atomically send out of the Ark
	HtlcOut {
		payment_hash: sha256::Hash,
		htlc_expiry: u32,
	}
}

impl Decodable for VtxoSpkSpec {}
impl Encodable for VtxoSpkSpec {}

impl fmt::Display for VtxoSpkSpec {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match &self {
			VtxoSpkSpec::Exit { .. } => write!(f, "exit"),
			VtxoSpkSpec::HtlcIn { .. } => write!(f, "htlc-in"),
			VtxoSpkSpec::HtlcOut { .. } => write!(f, "htlc-out"),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VtxoSpec {
	pub user_pubkey: PublicKey,
	pub expiry_height: BlockHeight,
	pub asp_pubkey: PublicKey,
	pub exit_delta: u16,
	pub spk: VtxoSpkSpec,
	/// The amount of the vtxo itself, this is either the exit tx or the
	/// vtxo tree output. It does not include budget for fees, so f.e. to
	/// calculate the board amount needed for this vtxo, fee budget should
	/// be added.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl VtxoSpec {
	/// Get the musig-combined user + asp pubkey.
	pub fn combined_pubkey(&self) -> XOnlyPublicKey {
		musig::combine_keys([self.user_pubkey, self.asp_pubkey])
	}

	/// Returns the clause to unilaterally spend a VTXO, if any
	pub fn exit_clause(&self) -> Option<ScriptBuf> {
		match self.spk {
			VtxoSpkSpec::Exit => Some(exit_clause(self.user_pubkey, self.exit_delta)),
			VtxoSpkSpec::HtlcIn { .. } => None,
			VtxoSpkSpec::HtlcOut { .. } => None,
		}
	}

	pub fn vtxo_taproot(&self) -> taproot::TaprootSpendInfo {
		match self.spk {
			VtxoSpkSpec::Exit => {
				exit_taproot(self.user_pubkey, self.asp_pubkey, self.exit_delta)
			},
			VtxoSpkSpec::HtlcOut { payment_hash, htlc_expiry } => {
				htlc_out_taproot(payment_hash, self.asp_pubkey, self.user_pubkey, self.exit_delta, htlc_expiry)
			},
			VtxoSpkSpec::HtlcIn { payment_hash, htlc_expiry } => {
				htlc_in_taproot(payment_hash, self.asp_pubkey, self.user_pubkey, self.exit_delta, htlc_expiry)
			},
		}
	}

	pub fn taproot_pubkey(&self) -> XOnlyPublicKey {
		self.vtxo_taproot().output_key().to_x_only_public_key()
	}

	pub fn vtxo_taptweak(&self) -> taproot::TapTweakHash {
		self.vtxo_taproot().tap_tweak()
	}

	/// Return the spk to spend the VTXO
	///
	/// In most cases, VTXO spk includes a unilateral exit clause
	pub fn vtxo_spk(&self) -> ScriptBuf {
		ScriptBuf::new_p2tr_tweaked(self.vtxo_taproot().output_key())
	}

	pub fn txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.vtxo_spk(),
			value: self.amount,
		}
	}
}

/// Represents a VTXO in the Ark.
///
/// Implementations of [PartialEq], [Eq], [PartialOrd], [Ord] and [Hash] are
/// proxied to the implementation on [Vtxo::id].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Vtxo {
	Board(BoardVtxo),
	Round(RoundVtxo),
	Arkoor(ArkoorVtxo),
}

impl Vtxo {
	/// This is the same as [Vtxo::point] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		self.point().into()
	}

	/// The outpoint from which to build forfeit or OOR txs.
	///
	/// This can be an on-chain utxo or an off-chain vtxo.
	pub fn point(&self) -> OutPoint {
		match self {
			Vtxo::Board(v) => v.point(),
			Vtxo::Round(v) => v.point(),
			Vtxo::Arkoor(v) => v.point,
		}
	}

	pub fn spec(&self) -> &VtxoSpec {
		match self {
			Vtxo::Board(v) => &v.spec,
			Vtxo::Round(v) => &v.spec,
			Vtxo::Arkoor(v) => &v.spec(),
		}
	}

	pub fn amount(&self) -> Amount {
		self.spec().amount
	}

	pub fn expiry_height(&self) -> BlockHeight {
		self.spec().expiry_height
	}

	pub fn asp_pubkey(&self) -> PublicKey {
		self.spec().asp_pubkey
	}

	pub fn exit_delta(&self) -> u16 {
		self.spec().exit_delta
	}

	pub fn txout(&self) -> TxOut {
		self.spec().txout()
	}

	pub fn input_vtxo_id(&self) -> Option<VtxoId> {
		self.as_arkoor().map(|v| v.input_vtxo_id())
	}

	/// Returns the OOR depth of the vtxo.
	pub fn arkoor_depth(&self) -> u16 {
		match self {
			Vtxo::Board { .. } => 0,
			Vtxo::Round { .. } => 0,
			Vtxo::Arkoor(v) => v.input.arkoor_depth() + 1,
		}
	}

	/// Get the payment hash if this vtxo is an HTLC send arkoor vtxo.
	//TODO(stevenroose) this api will be better after refactor
	pub fn server_htlc_out_payment_hash(&self) -> Option<sha256::Hash> {
		self.as_arkoor().and_then(|v| {
			match v.output_specs[0].spk {
				VtxoSpkSpec::HtlcOut { payment_hash, .. } => Some(payment_hash),
				_ => None,
			}
		})
	}

	/// The exit tx of the vtxo.
	pub fn vtxo_tx(&self) -> Transaction {
		let ret = match self {
			Vtxo::Board(v) => v.exit_tx(),
			Vtxo::Round(v) => v.exit_branch.last().unwrap().clone(),
			Vtxo::Arkoor(v) => {
				let tx = if v.signature.is_none() {
					//TODO(stevenroose) either improve API for or get rid of unsigned vtxos
					arkoor::unsigned_arkoor_tx(&v.input, &v.output_specs)
				} else {
					arkoor::signed_arkoor_tx(&v.input, v.signature.unwrap(), &v.output_specs)
				};
				assert_eq!(tx.compute_txid(), v.point.txid);
				tx
			},
		};
		debug_assert_eq!(ret.compute_txid(), self.id().utxo().txid);
		ret
	}

	/// Collect all off-chain txs required for the exit of this entire vtxo.
	///
	/// The [Vtxo::vtxo_tx] is always included.
	pub fn collect_exit_txs(&self, txs: &mut Vec<Transaction>) {
		match self {
			Vtxo::Board(_) => {
				txs.push(self.vtxo_tx());
			},
			Vtxo::Round(v) => {
				txs.extend(v.exit_branch.iter().cloned());
			},
			Vtxo::Arkoor(v) => {
				v.input.collect_exit_txs(txs);
				txs.push(self.vtxo_tx());
			},
		}
	}

	/// Get a vec with all off-chain txs required for the exit of this entire vtxo.
	///
	/// The [Vtxo::vtxo_tx] is always included.
	pub fn exit_txs(&self) -> Vec<Transaction> {
		let mut ret = Vec::new();
		self.collect_exit_txs(&mut ret);
		ret
	}

	pub fn is_board(&self) -> bool {
		match self {
			Vtxo::Board { .. } => true,
			_ => false,
		}
	}

	/// Whether this VTXO contains our-of-round parts. This is true for both
	/// arkoor and lightning vtxos.
	pub fn is_oor(&self) -> bool {
		match self {
			Vtxo::Board { .. } => false,
			Vtxo::Round { .. } => false,
			Vtxo::Arkoor { .. } => true,
		}
	}

	pub fn vtxo_type(&self) -> &'static str {
		match self {
			Vtxo::Board { .. } => "board",
			Vtxo::Round { .. } => "round",
			Vtxo::Arkoor { .. } => "arkoor",
		}
	}

	pub fn claim_satisfaction_weight(&self)  -> Weight {
		VTXO_CLAIM_INPUT_WEIGHT
	}

	pub fn as_board(&self) -> Option<&BoardVtxo> {
		match self {
			Vtxo::Board(v) => Some(v),
			_ => None,
		}
	}

	pub fn into_board(self) -> Option<BoardVtxo> {
		match self {
			Vtxo::Board(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_round(&self) -> Option<&RoundVtxo> {
		match self {
			Vtxo::Round(v) => Some(v),
			_ => None,
		}
	}

	pub fn into_round(self) -> Option<RoundVtxo> {
		match self {
			Vtxo::Round(v) => Some(v),
			_ => None,
		}
	}

	pub fn as_arkoor(&self) -> Option<&ArkoorVtxo> {
		match self {
			Vtxo::Arkoor(v) => Some(v),
			_ => None,
		}
	}

	pub fn into_arkoor(self) -> Option<ArkoorVtxo> {
		match self {
			Vtxo::Arkoor(v) => Some(v),
			_ => None,
		}
	}
}

impl Encodable for Vtxo {}
impl Decodable for Vtxo {}

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

impl From<BoardVtxo> for Vtxo {
	fn from(v: BoardVtxo) -> Vtxo {
		Vtxo::Board(v)
	}
}

impl From<RoundVtxo> for Vtxo {
	fn from(v: RoundVtxo) -> Vtxo {
		Vtxo::Round(v)
	}
}

impl From<ArkoorVtxo> for Vtxo {
	fn from(v: ArkoorVtxo) -> Vtxo {
		Vtxo::Arkoor(v)
	}
}


#[cfg(test)]
mod test {
	use crate::arkoor::ArkoorVtxo;

use super::*;
	use bitcoin::hashes::hex::FromHex;
	use arkoor::unsigned_arkoor_tx;

	#[test]
	fn vtxo_roundtrip() {
		let pk = "034b56997a369b627dae1621c603bbf2466b8369b37724cc902c5f1b434fc6a38a".parse().unwrap();
		let point = "f338d94399994750d07607e2984b38d967b91fcc0d05e5dd856d674832620ba6:2".parse().unwrap();
		let sig = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let tx = bitcoin::consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex("010000000001040cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10000000000ffffffff0cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10100000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20000000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20100000000ffffffff03e2833d3600000000225120de391fbef06ac409794f11b0589835cb0850f866e8795b6a9b4ac16c479a4ca04a010000000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a64b0953e000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a0340122a381f3e05949d772022456524e5fb15cc54411f9543ae6a83442730f01dd12738d9c6696bd37559d29d5b0061022d9fc2ca41e1d6f34d04dc8b3f18e6d75b2702d601b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c0693471477e72768671054c1edf30412712c5a34ab2a3f14e16088f21bc21317d0140d5c2d47cba2bc70380c6b47ee01a5d8cd461515451562250ffb95dd7333f40f45b87977c8a98b63d6c2b641648e989844dbd2d4dfb51a6e06939caa30c80345203401cb74b31e35b1c3f0b033f1264f4b7167883d157814f99f350c546514d31c49989856986d2c894a6f665b896720fd77a7154cae2cad3097c88e8efaa5bc7b92e2702d701b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c1c06081bed228f8d624d05e58ff9ca0315d14c328648bb27a950b7cc9cb404e4f0140a09b7d8c0bd24707a077be0e3c9a93601f01954aa563a50eb41cbfdd0db0eb5e5df6971aa11eacd2b9faf9a2d9f3dd4d107c9bc8e5ba273c01052e633fa746760f020000").unwrap()).unwrap();

		let oor_sig1 = schnorr::Signature::from_str("784d3ad041909063648c33d076510e357646e60038835c40ec838f9e98ae8aaea4c583e7303ef86be17032d212df7d0276c369e616e905b4a192d97047bd141a").unwrap();

		let board = Vtxo::Board(BoardVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				spk: VtxoSpkSpec::Exit,
				amount: Amount::from_sat(5),
			},
			onchain_output: point,
			exit_tx_signature: sig,
		});
		assert_eq!(board, Vtxo::decode(&board.encode()).unwrap());

		let round = Vtxo::Round(RoundVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				spk: VtxoSpkSpec::Exit,
				amount: Amount::from_sat(5),
			},
			leaf_idx: 3,
			exit_branch: vec![tx.clone()],
		});
		assert_eq!(round, Vtxo::decode(&round.encode()).unwrap());

		let output_specs = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			spk: VtxoSpkSpec::Exit,
			amount: Amount::from_sat(5),
		}];
		let tx = unsigned_arkoor_tx(&round, &output_specs);
		let oor = Vtxo::Arkoor(ArkoorVtxo {
			input: round.clone().into(),
			output_specs,
			signature: Some(oor_sig1),
			point: OutPoint::new(tx.compute_txid(), 0)
		});
		assert_eq!(oor, Vtxo::decode(&oor.encode()).unwrap());

		let output_specs_recursive = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			spk: VtxoSpkSpec::Exit,
			amount: Amount::from_sat(5),
		}];
		let tx_recursive = unsigned_arkoor_tx(&oor, &output_specs_recursive);
		let oor_recursive = Vtxo::Arkoor(ArkoorVtxo {
			input: oor.clone().into(),
			output_specs: output_specs_recursive,
			signature: Some(oor_sig1),
			point: OutPoint::new(tx_recursive.compute_txid(), 0)
		});
		assert_eq!(oor_recursive, Vtxo::decode(&oor_recursive.encode()).unwrap());
	}


	#[test]
	fn arkoor_depth() {
		let pk = "034b56997a369b627dae1621c603bbf2466b8369b37724cc902c5f1b434fc6a38a".parse().unwrap();
		let point = "f338d94399994750d07607e2984b38d967b91fcc0d05e5dd856d674832620ba6:2".parse().unwrap();
		let sig = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let tx = bitcoin::consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex("010000000001040cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10000000000ffffffff0cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10100000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20000000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20100000000ffffffff03e2833d3600000000225120de391fbef06ac409794f11b0589835cb0850f866e8795b6a9b4ac16c479a4ca04a010000000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a64b0953e000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a0340122a381f3e05949d772022456524e5fb15cc54411f9543ae6a83442730f01dd12738d9c6696bd37559d29d5b0061022d9fc2ca41e1d6f34d04dc8b3f18e6d75b2702d601b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c0693471477e72768671054c1edf30412712c5a34ab2a3f14e16088f21bc21317d0140d5c2d47cba2bc70380c6b47ee01a5d8cd461515451562250ffb95dd7333f40f45b87977c8a98b63d6c2b641648e989844dbd2d4dfb51a6e06939caa30c80345203401cb74b31e35b1c3f0b033f1264f4b7167883d157814f99f350c546514d31c49989856986d2c894a6f665b896720fd77a7154cae2cad3097c88e8efaa5bc7b92e2702d701b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c1c06081bed228f8d624d05e58ff9ca0315d14c328648bb27a950b7cc9cb404e4f0140a09b7d8c0bd24707a077be0e3c9a93601f01954aa563a50eb41cbfdd0db0eb5e5df6971aa11eacd2b9faf9a2d9f3dd4d107c9bc8e5ba273c01052e633fa746760f020000").unwrap()).unwrap();

		let oor_sig1 = schnorr::Signature::from_str("784d3ad041909063648c33d076510e357646e60038835c40ec838f9e98ae8aaea4c583e7303ef86be17032d212df7d0276c369e616e905b4a192d97047bd141a").unwrap();
		let oor_sig2 = schnorr::Signature::from_str("115e203be50944e96c00b30f88be5d4523397f66a1845addc95851fbe27ecd82b8e4d5bbd96229b8167a9196de77b3cd62a27c368d00774889900cffe2c932da").unwrap();

		let board = Vtxo::Board(BoardVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				spk: VtxoSpkSpec::Exit,
				amount: Amount::from_sat(5),
			},
			onchain_output: point,
			exit_tx_signature: sig,
		});
		assert_eq!(board.arkoor_depth(), 0);

		let round = Vtxo::Round(RoundVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				spk: VtxoSpkSpec::Exit,
				amount: Amount::from_sat(5),
			},
			leaf_idx: 3,
			exit_branch: vec![tx.clone()],
		});
		assert_eq!(round.arkoor_depth(), 0);

		let input = round.clone();
		let output_specs = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			spk: VtxoSpkSpec::Exit,
			amount: Amount::from_sat(5),
		}];
		let tx = unsigned_arkoor_tx(&input, &output_specs);
		let oor_1 = Vtxo::Arkoor(ArkoorVtxo {
			input: Box::new(input),
			output_specs: output_specs.clone(),
			signature: Some(oor_sig1),
			point: OutPoint::new(tx.compute_txid(), 0)
		});

		let input = oor_1.clone();
		let tx = unsigned_arkoor_tx(&input, &output_specs);
		let oor_2 = Vtxo::Arkoor(ArkoorVtxo {
			input: Box::new(oor_1.clone()),
			output_specs: output_specs.clone(),
			signature: Some(oor_sig2),
			point: OutPoint::new(tx.compute_txid(), 0)
		});

		// oor_1 has one round (depth: 0), should have depth = 1
		assert_eq!(oor_1.arkoor_depth(), 1);
		// oor_2 has one board (depth: 0) and one oor_1 (depth: 1), should have depth = max(0, 1) + 1 = 2
		assert_eq!(oor_2.arkoor_depth(), 2);
	}
}
