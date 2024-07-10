
pub use secp256k1_zkp as zkp;
pub use secp256k1_zkp::{
	MusigAggNonce, MusigKeyAggCache, MusigPubNonce, MusigPartialSignature, MusigSecNonce,
	MusigSession, MusigSessionId,
};
use bitcoin::secp256k1::{rand, schnorr, Keypair, PublicKey, SecretKey, XOnlyPublicKey};

use crate::util;

lazy_static::lazy_static! {
	/// Global secp context.
	pub static ref SECP: zkp::Secp256k1<zkp::All> = zkp::Secp256k1::new();
}

pub fn xonly_from(pk: zkp::XOnlyPublicKey) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_to(pk: PublicKey) -> zkp::PublicKey {
	zkp::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_from(pk: zkp::PublicKey) -> PublicKey {
	PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn seckey_to(sk: SecretKey) -> zkp::SecretKey {
	zkp::SecretKey::from_slice(&sk.secret_bytes()).unwrap()
}

pub fn keypair_to(kp: &Keypair) -> zkp::Keypair {
	zkp::Keypair::from_seckey_slice(&SECP, &kp.secret_bytes()).unwrap()
}

pub fn keypair_from(kp: &zkp::Keypair) -> Keypair {
	Keypair::from_seckey_slice(&util::SECP, &kp.secret_bytes()).unwrap()
}

pub fn sig_from(s: zkp::schnorr::Signature) -> schnorr::Signature {
	schnorr::Signature::from_slice(&s.serialize()).unwrap()
}

pub fn key_agg<'a>(keys: impl IntoIterator<Item = PublicKey>) -> MusigKeyAggCache {
	let mut keys = keys.into_iter().map(|k| pubkey_to(k)).collect::<Vec<_>>();
	keys.sort_by_key(|k| k.serialize());
	MusigKeyAggCache::new(&SECP, &keys)
}

/// Returns the key agg cache with the tweak applied and the resulting pubkey with the tweak
/// applied.
pub fn tweaked_key_agg<'a>(keys: impl IntoIterator<Item = PublicKey>, tweak: [u8; 32]) -> (MusigKeyAggCache, PublicKey) {
	let mut keys = keys.into_iter().map(|k| pubkey_to(k)).collect::<Vec<_>>();
	keys.sort_by_key(|k| k.serialize());
	let mut ret = MusigKeyAggCache::new(&SECP, &keys);
	let pk = ret.pubkey_xonly_tweak_add(&SECP, zkp::SecretKey::from_slice(&tweak).unwrap()).unwrap();
	(ret, pubkey_from(pk))
}

pub fn combine_keys(keys: impl IntoIterator<Item = PublicKey>) -> XOnlyPublicKey {
	xonly_from(key_agg(keys).agg_pk())
}

pub fn nonce_pair(key: &Keypair) -> (MusigSecNonce, MusigPubNonce) {
	let kp = keypair_to(key);
	zkp::new_musig_nonce_pair(
		&SECP,
		MusigSessionId::assume_unique_per_nonce_gen(rand::random()),
		None,
		Some(kp.secret_key()),
		kp.public_key(),
		None,
		Some(rand::random()),
	).expect("non-zero session id")
}

pub fn nonce_agg(pub_nonces: impl IntoIterator<Item = MusigPubNonce>) -> MusigAggNonce {
	MusigAggNonce::new(&SECP, &pub_nonces.into_iter().collect::<Vec<_>>())
}
	
pub fn partial_sign(
	pubkeys: impl IntoIterator<Item = PublicKey>,
	agg_nonce: MusigAggNonce,
	key: &Keypair,
	sec_nonce: MusigSecNonce,
	sighash: [u8; 32],
	tweak: Option<[u8; 32]>,
	other_sigs: Option<&[MusigPartialSignature]>,
) -> (MusigPartialSignature, Option<schnorr::Signature>) {
	let agg = if let Some(tweak) = tweak {
		tweaked_key_agg(pubkeys, tweak).0
	} else {
		key_agg(pubkeys)
	};

	let msg = zkp::Message::from_digest(sighash);
	let session = MusigSession::new(&SECP, &agg, agg_nonce, msg);
	let my_sig = session.partial_sign(&SECP, sec_nonce, &keypair_to(&key), &agg)
		.expect("nonce not reused");
	let final_sig = if let Some(others) = other_sigs {
		let mut sigs = Vec::with_capacity(others.len() + 1);
		sigs.extend_from_slice(others);
		sigs.push(my_sig);
		Some(session.partial_sig_agg(&sigs))
	} else {
		None
	};
	(my_sig, final_sig.map(sig_from))
}

/// Perform a deterministic partial sign for the given message and the
/// given counterparty key and nonce.
pub fn deterministic_partial_sign(
	my_key: &Keypair,
	their_pubkeys: impl IntoIterator<Item = PublicKey>,
	their_nonces: impl IntoIterator<Item = MusigPubNonce>,
	msg: [u8; 32],
	tweak: Option<[u8; 32]>,
) -> (MusigPubNonce, MusigPartialSignature) {
	let agg = if let Some(tweak) = tweak {
		tweaked_key_agg(their_pubkeys.into_iter().chain(Some(my_key.public_key())), tweak).0
	} else {
		key_agg(their_pubkeys.into_iter().chain(Some(my_key.public_key())))
	};

	let msg = zkp::Message::from_digest(msg);
	let (sec_nonce, pub_nonce) = zkp::new_musig_nonce_pair(
		&SECP,
		MusigSessionId::assume_unique_per_nonce_gen(rand::random()),
		Some(&agg),
		Some(seckey_to(my_key.secret_key())),
		pubkey_to(my_key.public_key()),
		Some(msg),
		Some(rand::random()),
	).expect("non-zero session id");

	let agg_nonce = MusigAggNonce::new(&SECP, &their_nonces.into_iter().chain(Some(pub_nonce)).collect::<Vec<_>>());
	let session = MusigSession::new(&SECP, &agg, agg_nonce, msg);
	let sig = session.partial_sign(&SECP, sec_nonce, &keypair_to(my_key), &agg)
		.expect("nonce not reused");
	(pub_nonce, sig)
}

//TODO(stevenroose) probably get rid of all this by having native byte serializers in secp
pub mod serde {
	use super::*;
	use ::serde::{Deserializer, Serializer};
	use ::serde::de::{self, Error};

	struct BytesVisitor;
	impl<'de> de::Visitor<'de> for BytesVisitor {
		type Value = Vec<u8>;
		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "a byte object")
		}
		fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
			Ok(v.to_vec())
		}
		fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
			Ok(v.to_vec())
		}
		fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
			Ok(v)
		}
	}

	pub mod pubnonce {
		use super::*;
		pub fn serialize<S: Serializer>(pub_nonce: &MusigPubNonce, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&pub_nonce.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MusigPubNonce, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			MusigPubNonce::from_slice(&v).map_err(D::Error::custom)
		}
	}
	pub mod partialsig {
		use super::*;
		pub fn serialize<S: Serializer>(sig: &MusigPartialSignature, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&sig.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MusigPartialSignature, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			MusigPartialSignature::from_slice(&v).map_err(D::Error::custom)
		}
	}
}
