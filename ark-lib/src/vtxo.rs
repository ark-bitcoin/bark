
use std::{fmt, io};
use std::str::FromStr;

use bitcoin::{taproot, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Weight};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, PublicKey, XOnlyPublicKey};

use crate::{musig, oor, util};


/// The input weight required to claim a VTXO.
const VTXO_CLAIM_INPUT_WEIGHT: Weight = Weight::from_wu(138);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VtxoId([u8; 36]);

impl VtxoId {
	/// Size in bytes of an encoded [VtxoId].
	pub const ENCODE_SIZE: usize = 36;

	pub fn from_slice(b: &[u8]) -> Result<VtxoId, &'static str> {
		if b.len() == 36 {
			let mut ret = [0u8; 36];
			ret[..].copy_from_slice(&b[0..36]);
			Ok(Self(ret))
		} else {
			Err("invalid vtxo id length; must be 36 bytes")
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
	type Err = <OutPoint as FromStr>::Err;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(OutPoint::from_str(s)?.into())
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

pub fn exit_clause(
	user_pubkey: PublicKey,
	exit_delta: u16,
) -> ScriptBuf {
	util::delayed_sign(exit_delta, user_pubkey.x_only_public_key().0)
}

pub fn exit_taproot(
	user_pubkey: PublicKey,
	asp_pubkey: PublicKey,
	exit_delta: u16,
) -> taproot::TaprootSpendInfo {
	let combined_pk = musig::combine_keys([user_pubkey, asp_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(0, exit_clause(user_pubkey, exit_delta)).unwrap()
		.finalize(&util::SECP, combined_pk).unwrap()
}

pub fn exit_spk(
	user_pubkey: PublicKey,
	asp_pubkey: PublicKey,
	exit_delta: u16,
) -> ScriptBuf {
	let taproot = exit_taproot(user_pubkey, asp_pubkey, exit_delta);
	ScriptBuf::new_p2tr_tweaked(taproot.output_key())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VtxoSpec {
	pub user_pubkey: PublicKey,
	pub asp_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
	/// The amount of the vtxo itself, this is either the reveal tx our the
	/// vtxo tree output. It does not include budget for fees, so f.e. to
	/// calculate the onboard amount needed for this vtxo, fee budget should
	/// be added.
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl VtxoSpec {
	/// Get the musig-combined user + asp pubkey.
	pub fn combined_pubkey(&self) -> XOnlyPublicKey {
		musig::combine_keys([self.user_pubkey, self.asp_pubkey])
	}

	pub fn exit_clause(&self) -> ScriptBuf {
		exit_clause(self.user_pubkey, self.exit_delta)
	}

	pub fn exit_taproot(&self) -> taproot::TaprootSpendInfo {
		exit_taproot(self.user_pubkey, self.asp_pubkey, self.exit_delta)
	}

	pub fn exit_taptweak(&self) -> taproot::TapTweakHash {
		exit_taproot(self.user_pubkey, self.asp_pubkey, self.exit_delta).tap_tweak()
	}

	pub fn exit_spk(&self) -> ScriptBuf {
		exit_spk(self.user_pubkey, self.asp_pubkey, self.exit_delta)
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OnboardVtxo {
	pub spec: VtxoSpec,
	pub input: OutPoint,
	pub reveal_tx_signature: schnorr::Signature,
}

impl OnboardVtxo {
	pub fn reveal_tx(&self) -> Transaction {
		crate::onboard::create_reveal_tx(
			&self.spec, self.input, Some(&self.reveal_tx_signature),
		)
	}

	pub fn point(&self) -> OutPoint {
		//TODO(stevenroose) consider caching this so that we don't have to calculate it
		OutPoint::new(self.reveal_tx().compute_txid(), 0)
	}

	pub fn id(&self) -> VtxoId {
		self.point().into()
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoundVtxo {
	pub spec: VtxoSpec,
	pub leaf_idx: usize,
	//TODO(stevenroose) reduce this to just storing the signatures
	// and calculate branch on exit
	pub exit_branch: Vec<Transaction>,
}

impl RoundVtxo {
	pub fn point(&self) -> OutPoint {
		//TODO(stevenroose) consider caching this so that we don't have to calculate it
		OutPoint::new(self.exit_branch.last().unwrap().compute_txid(), 0).into()
	}

	pub fn id(&self) -> VtxoId {
		self.point().into()
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArkoorVtxo {
	pub inputs: Vec<Vtxo>,
	pub signatures: Vec<schnorr::Signature>,
	pub output_specs:  Vec<VtxoSpec>,
	pub point: OutPoint,
}

impl ArkoorVtxo {
	pub fn id(&self) -> VtxoId {
		self.point.into()
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bolt11ChangeVtxo {
	pub inputs: Vec<Vtxo>,
	/// This has the fields for the spec, but were not necessarily
	/// actually being used for the generation of the vtxos.
	/// Primarily, the expiry height is the first of all the parents
	/// expiry heights.
	pub pseudo_spec: VtxoSpec,
	pub htlc_tx: Transaction,
	pub final_point: OutPoint,
}

impl Bolt11ChangeVtxo {
	pub fn id(&self) -> VtxoId {
		self.final_point.into()
	}
}

/// Represents a VTXO in the Ark.
///
/// Implementations of [PartialEq], [Eq], [PartialOrd], [Ord] and [Hash] are
/// proxied to the implementation on [Vtxo::id].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Vtxo {
	Onboard(OnboardVtxo),
	Round(RoundVtxo),
	Arkoor(ArkoorVtxo),
	Bolt11Change(Bolt11ChangeVtxo),
}

impl Vtxo {
	/// This is the same as [utxo] but encoded as a byte array.
	pub fn id(&self) -> VtxoId {
		self.point().into()
	}

	/// The outpoint from which to build forfeit or OOR txs.
	///
	/// This can be an on-chain utxo or an off-chain vtxo.
	pub fn point(&self) -> OutPoint {
		match self {
			Vtxo::Onboard(v) => v.point(),
			Vtxo::Round(v) => v.point(),
			Vtxo::Arkoor(v) => v.point,
			Vtxo::Bolt11Change(v) => v.final_point,
		}
	}

	pub fn spec(&self) -> &VtxoSpec {
		match self {
			Vtxo::Onboard(v) => &v.spec,
			Vtxo::Round(v) => &v.spec,
			Vtxo::Arkoor(v) => &v.output_specs[v.point.vout as usize],
			Vtxo::Bolt11Change(v) => &v.pseudo_spec,
		}
	}

	pub fn amount(&self) -> Amount {
		match self {
			Vtxo::Onboard(v) => v.spec.amount,
			Vtxo::Round(v) => v.spec.amount,
			Vtxo::Arkoor(_) => self.spec().amount,
			Vtxo::Bolt11Change(v) => {
				v.htlc_tx.output[v.final_point.vout as usize].value
			},
		}
	}

	pub fn txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.spec().exit_spk(),
			value: self.amount(),
		}
	}

	pub fn taproot_pubkey(&self) -> XOnlyPublicKey {
		self.spec().exit_taproot().output_key().to_inner()
	}

	pub fn vtxo_tx(&self) -> Transaction {
		match self {
			Vtxo::Onboard(v) => v.reveal_tx(),
			Vtxo::Round(v) => v.exit_branch.last().unwrap().clone(),
			Vtxo::Arkoor(v) => {
				let tx = oor::signed_oor_tx(&v.inputs, &v.signatures, &v.output_specs);
				assert_eq!(tx.compute_txid(), v.point.txid);
				tx
			},
			Vtxo::Bolt11Change(v) => v.htlc_tx.clone(),
		}
	}

	/// Collect all off-chain txs required for the exit of this entire vtxo.
	///
	/// The [vtxo_tx] is always included.
	pub fn collect_exit_txs(&self, txs: &mut Vec<Transaction>) {
		match self {
			Vtxo::Onboard(_) => {
				txs.push(self.vtxo_tx());
			},
			Vtxo::Round(v) => {
				txs.extend(v.exit_branch.iter().cloned());
			},
			Vtxo::Arkoor(v) => {
				for input in &v.inputs {
					input.collect_exit_txs(txs);
				}

				txs.push(self.vtxo_tx());
			},
			Vtxo::Bolt11Change(v) => {
				for input in &v.inputs {
					input.collect_exit_txs(txs);
				}
				txs.push(v.htlc_tx.clone());
			},
		}
	}

	/// Get a vec with all off-chain txs required for the exit of this entire vtxo.
	///
	/// The [vtxo_tx] is always included.
	pub fn exit_txs(&self) -> Vec<Transaction> {
		let mut ret = Vec::new();
		self.collect_exit_txs(&mut ret);
		ret
	}

	pub fn is_onboard(&self) -> bool {
		match self {
			Vtxo::Onboard { .. } => true,
			_ => false,
		}
	}

	/// Whether this VTXO contains our-of-round parts. This is true for both
	/// arkoor and lightning vtxos.
	pub fn is_oor(&self) -> bool {
		match self {
			Vtxo::Onboard { .. } => false,
			Vtxo::Round { .. } => false,
			Vtxo::Arkoor { .. } => true,
			Vtxo::Bolt11Change { .. } => true,
		}
	}

	pub fn encode(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		ciborium::into_writer(self, &mut buf).unwrap();
		buf
	}

	pub fn encode_into(&self, buf: &mut impl io::Write) {
		ciborium::into_writer(self, buf).unwrap();
	}

	pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<io::Error>> {
		ciborium::from_reader(bytes)
	}

	pub fn vtxo_type(&self) -> &'static str {
		match self {
			Vtxo::Onboard { .. } => "onboard",
			Vtxo::Round { .. } => "round",
			Vtxo::Arkoor { .. } => "arkoor",
			Vtxo::Bolt11Change { .. } => "bolt11change",
		}
	}

	pub fn claim_satisfaction_weight(&self)  -> Weight {
		VTXO_CLAIM_INPUT_WEIGHT
	}

	/// Checks if the VTXO has some counterparty risk
	///
	/// A [`Vtxo::Arkoor`] is considered to have some counterparty risk
	/// if it is (directly or not) based on round VTXOs that aren't owned by the wallet
	pub fn has_counterparty_risk(&self, vtxo_pubkey: &PublicKey) -> bool {
		match self {
			Vtxo::Arkoor(v) => {
				fn inner_has_counterparty_risk(vtxo: &Vtxo, vtxo_pubkey: &PublicKey) -> bool {
					match vtxo {
						Vtxo::Arkoor(v) => {
							v.inputs.iter().any(|i| inner_has_counterparty_risk(i, vtxo_pubkey))
						},
						Vtxo::Bolt11Change(v) => {
							v.inputs.iter().any(|i| inner_has_counterparty_risk(i, vtxo_pubkey))
						},
						//TODO impl key derivation
						Vtxo::Onboard(v) => v.spec.user_pubkey != *vtxo_pubkey,
						//TODO impl key derivation
						Vtxo::Round(v) => v.spec.user_pubkey != *vtxo_pubkey,
					}
				}

				v.inputs.iter().any(|v| inner_has_counterparty_risk(v, vtxo_pubkey))
			},
			_ => false
		}
	}

	pub fn as_onboard(&self) -> Option<&OnboardVtxo> {
		match self {
			Vtxo::Onboard(v) => Some(v),
			_ => None,
		}
	}

	pub fn into_onboard(self) -> Option<OnboardVtxo> {
		match self {
			Vtxo::Onboard(v) => Some(v),
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

	pub fn as_bolt11change(&self) -> Option<&Bolt11ChangeVtxo> {
		match self {
			Vtxo::Bolt11Change(v) => Some(v),
			_ => None,
		}
	}

	pub fn into_bolt11change(self) -> Option<Bolt11ChangeVtxo> {
		match self {
			Vtxo::Bolt11Change(v) => Some(v),
			_ => None,
		}
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

impl From<OnboardVtxo> for Vtxo {
	fn from(v: OnboardVtxo) -> Vtxo {
		Vtxo::Onboard(v)
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

impl From<Bolt11ChangeVtxo> for Vtxo {
	fn from(v: Bolt11ChangeVtxo) -> Vtxo {
		Vtxo::Bolt11Change(v)
	}
}


#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::hashes::hex::FromHex;
use oor::unsigned_oor_transaction;

	#[test]
	fn vtxo_roundtrip() {
		let pk = "034b56997a369b627dae1621c603bbf2466b8369b37724cc902c5f1b434fc6a38a".parse().unwrap();
		let point = "f338d94399994750d07607e2984b38d967b91fcc0d05e5dd856d674832620ba6:2".parse().unwrap();
		let sig = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let tx = bitcoin::consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex("010000000001040cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10000000000ffffffff0cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10100000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20000000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20100000000ffffffff03e2833d3600000000225120de391fbef06ac409794f11b0589835cb0850f866e8795b6a9b4ac16c479a4ca04a010000000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a64b0953e000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a0340122a381f3e05949d772022456524e5fb15cc54411f9543ae6a83442730f01dd12738d9c6696bd37559d29d5b0061022d9fc2ca41e1d6f34d04dc8b3f18e6d75b2702d601b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c0693471477e72768671054c1edf30412712c5a34ab2a3f14e16088f21bc21317d0140d5c2d47cba2bc70380c6b47ee01a5d8cd461515451562250ffb95dd7333f40f45b87977c8a98b63d6c2b641648e989844dbd2d4dfb51a6e06939caa30c80345203401cb74b31e35b1c3f0b033f1264f4b7167883d157814f99f350c546514d31c49989856986d2c894a6f665b896720fd77a7154cae2cad3097c88e8efaa5bc7b92e2702d701b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c1c06081bed228f8d624d05e58ff9ca0315d14c328648bb27a950b7cc9cb404e4f0140a09b7d8c0bd24707a077be0e3c9a93601f01954aa563a50eb41cbfdd0db0eb5e5df6971aa11eacd2b9faf9a2d9f3dd4d107c9bc8e5ba273c01052e633fa746760f020000").unwrap()).unwrap();

		let oor_sig1 = schnorr::Signature::from_str("784d3ad041909063648c33d076510e357646e60038835c40ec838f9e98ae8aaea4c583e7303ef86be17032d212df7d0276c369e616e905b4a192d97047bd141a").unwrap();
		let oor_sig2 = schnorr::Signature::from_str("115e203be50944e96c00b30f88be5d4523397f66a1845addc95851fbe27ecd82b8e4d5bbd96229b8167a9196de77b3cd62a27c368d00774889900cffe2c932da").unwrap();
		let oor_sig3 = schnorr::Signature::from_str("4be220ff1dabd0f7c35798eb19d587de1ad88e80369ef037c5e803f9d776e1c74bc4458698a783add458730d1dbd144c86f3b848cff5486b0fcbd1c17ecc5f76").unwrap();

		let onboard = Vtxo::Onboard(OnboardVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				amount: Amount::from_sat(5),
			},
			input: point,
			reveal_tx_signature: sig,
		});
		assert_eq!(onboard, Vtxo::decode(&onboard.encode()).unwrap());

		let round = Vtxo::Round(RoundVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				amount: Amount::from_sat(5),
			},
			leaf_idx: 3,
			exit_branch: vec![tx.clone()],
		});
		assert_eq!(round, Vtxo::decode(&round.encode()).unwrap());

		let inputs = vec![
			round.clone(),
			onboard.clone(),
		];
		let output_specs = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			amount: Amount::from_sat(5),
		}];
		let tx = unsigned_oor_transaction(&inputs, &output_specs);
		let oor = Vtxo::Arkoor(ArkoorVtxo {
			inputs,
			output_specs,
			signatures: vec![
				oor_sig1,
				oor_sig2
			],
			point: OutPoint::new(tx.compute_txid(), 0)
		});
		assert_eq!(oor, Vtxo::decode(&oor.encode()).unwrap());

		let inputs_recursive = vec![
			round.clone(),
			onboard.clone(),
			oor.clone()
		];
		let output_specs_recursive = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			amount: Amount::from_sat(5),
		}];
		let tx_recursive = unsigned_oor_transaction(&inputs_recursive, &output_specs_recursive);
		let oor_recursive = Vtxo::Arkoor(ArkoorVtxo {
			inputs: inputs_recursive,
			output_specs: output_specs_recursive,
			signatures: vec![
				oor_sig1,
				oor_sig2,
				oor_sig3
			],
			point: OutPoint::new(tx_recursive.compute_txid(), 0)
		});
		assert_eq!(oor_recursive, Vtxo::decode(&oor_recursive.encode()).unwrap());
	}

	#[test]
	fn vtxo_counterparty_risk() {
		let pk = "034b56997a369b627dae1621c603bbf2466b8369b37724cc902c5f1b434fc6a38a".parse().unwrap();
		let tx = bitcoin::consensus::deserialize::<Transaction>(&Vec::<u8>::from_hex("010000000001040cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10000000000ffffffff0cd1965a17fec47521b619d56225abc6a33f73c6afac353048e5f386e10c6bf10100000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20000000000ffffffff91cc47b491ae94ea71cd727959e1758cdc3c0d8b14432497122ba9c566794be20100000000ffffffff03e2833d3600000000225120de391fbef06ac409794f11b0589835cb0850f866e8795b6a9b4ac16c479a4ca04a010000000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a64b0953e000000002251203ecd5454d152946220d6a4ab0ecd61441aa1982486d792c69bb108229283cd0a0340122a381f3e05949d772022456524e5fb15cc54411f9543ae6a83442730f01dd12738d9c6696bd37559d29d5b0061022d9fc2ca41e1d6f34d04dc8b3f18e6d75b2702d601b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c0693471477e72768671054c1edf30412712c5a34ab2a3f14e16088f21bc21317d0140d5c2d47cba2bc70380c6b47ee01a5d8cd461515451562250ffb95dd7333f40f45b87977c8a98b63d6c2b641648e989844dbd2d4dfb51a6e06939caa30c80345203401cb74b31e35b1c3f0b033f1264f4b7167883d157814f99f350c546514d31c49989856986d2c894a6f665b896720fd77a7154cae2cad3097c88e8efaa5bc7b92e2702d701b17520d1520b6d6ac840e0c1478e514d5a14daac218a5dbb945789cc3aee628c25dc60ac21c1c06081bed228f8d624d05e58ff9ca0315d14c328648bb27a950b7cc9cb404e4f0140a09b7d8c0bd24707a077be0e3c9a93601f01954aa563a50eb41cbfdd0db0eb5e5df6971aa11eacd2b9faf9a2d9f3dd4d107c9bc8e5ba273c01052e633fa746760f020000").unwrap()).unwrap();

		let oor_sig1 = schnorr::Signature::from_str("784d3ad041909063648c33d076510e357646e60038835c40ec838f9e98ae8aaea4c583e7303ef86be17032d212df7d0276c369e616e905b4a192d97047bd141a").unwrap();
		let oor_sig2 = schnorr::Signature::from_str("115e203be50944e96c00b30f88be5d4523397f66a1845addc95851fbe27ecd82b8e4d5bbd96229b8167a9196de77b3cd62a27c368d00774889900cffe2c932da").unwrap();
		let oor_sig3 = schnorr::Signature::from_str("4be220ff1dabd0f7c35798eb19d587de1ad88e80369ef037c5e803f9d776e1c74bc4458698a783add458730d1dbd144c86f3b848cff5486b0fcbd1c17ecc5f76").unwrap();

		let round = Vtxo::Round(RoundVtxo {
			spec: VtxoSpec {
				user_pubkey: pk,
				asp_pubkey: pk,
				expiry_height: 15,
				exit_delta: 7,
				amount: Amount::from_sat(5),
			},
			leaf_idx: 3,
			exit_branch: vec![tx.clone()],
		});

		let inputs = vec![
			round.clone(),
		];
		let output_specs = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			amount: Amount::from_sat(5),
		}];
		let tx = unsigned_oor_transaction(&inputs, &output_specs);
		let oor = Vtxo::Arkoor(ArkoorVtxo {
			inputs,
			output_specs,
			signatures: vec![
				oor_sig1,
				oor_sig2
			],
			point: OutPoint::new(tx.compute_txid(), 0)
		});
		assert_eq!(oor, Vtxo::decode(&oor.encode()).unwrap());

		let inputs_recursive = vec![oor.clone()];
		let output_specs_recursive = vec![VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			expiry_height: 15,
			exit_delta: 7,
			amount: Amount::from_sat(5),
		}];
		let tx_recursive = unsigned_oor_transaction(&inputs_recursive, &output_specs_recursive);
		let oor_recursive = Vtxo::Arkoor(ArkoorVtxo {
			inputs: inputs_recursive,
			output_specs: output_specs_recursive,
			signatures: vec![
				oor_sig3
			],
			point: OutPoint::new(tx_recursive.compute_txid(), 0)
		});

		let pk_b = "03bd32ad71ff5d7e803e0d474284d1bb87ec84d26f5d79601c9c64f06660074833".parse().unwrap();

		assert!(oor_recursive.has_counterparty_risk(&pk_b));
		assert!(!oor_recursive.has_counterparty_risk(&pk))
	}
}
