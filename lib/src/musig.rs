
use secp256k1_musig::ffi::MUSIG_SECNONCE_SIZE;
pub use secp256k1_musig as secpm;
pub use secp256k1_musig::musig::{
	AggregatedNonce, PublicNonce, PartialSignature, SecretNonce, Session, SessionSecretRand,
};

use bitcoin::secp256k1::{rand, schnorr, Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use secpm::musig::KeyAggCache;

lazy_static! {
	/// Global secp context.
	pub static ref SECP: secpm::Secp256k1<secpm::All> = secpm::Secp256k1::new();
}

pub fn xonly_from(pk: secpm::XOnlyPublicKey) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_to(pk: PublicKey) -> secpm::PublicKey {
	secpm::PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_from(pk: secpm::PublicKey) -> PublicKey {
	PublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn seckey_to(sk: SecretKey) -> secpm::SecretKey {
	secpm::SecretKey::from_byte_array(sk.secret_bytes()).unwrap()
}

pub fn keypair_to(kp: &Keypair) -> secpm::Keypair {
	secpm::Keypair::from_seckey_byte_array(&SECP, kp.secret_bytes()).unwrap()
}

pub fn keypair_from(kp: &secpm::Keypair) -> Keypair {
	Keypair::from_seckey_slice(&crate::SECP, &kp.secret_bytes()).unwrap()
}

pub fn sig_from(s: secpm::schnorr::Signature) -> schnorr::Signature {
	schnorr::Signature::from_slice(&s.to_byte_array()).unwrap()
}

/// Returns the key agg cache and the resulting pubkey.
///
/// Key order is not important as keys are sorted before aggregation.
pub fn key_agg<'a>(keys: impl IntoIterator<Item = PublicKey>) -> KeyAggCache {
	let mut keys = keys.into_iter().map(|k| pubkey_to(k)).collect::<Vec<_>>();
	keys.sort_by_key(|k| k.serialize());
	let keys = keys.iter().collect::<Vec<_>>(); //TODO(stevenroose) remove when musig pr merged
	KeyAggCache::new(&SECP, &keys)
}

/// Returns the key agg cache with the tweak applied and the resulting pubkey
/// with the tweak applied.
///
/// Key order is not important as keys are sorted before aggregation.
pub fn tweaked_key_agg<'a>(
	keys: impl IntoIterator<Item = PublicKey>,
	tweak: [u8; 32],
) -> (KeyAggCache, PublicKey) {
	let mut keys = keys.into_iter().map(|k| pubkey_to(k)).collect::<Vec<_>>();
	keys.sort_by_key(|k| k.serialize());
	let keys = keys.iter().collect::<Vec<_>>(); //TODO(stevenroose) remove when musig pr merged
	let mut ret = KeyAggCache::new(&SECP, &keys);
	let tweak_scalar = secpm::Scalar::from_be_bytes(tweak).unwrap();
	let pk = ret.pubkey_xonly_tweak_add(&SECP, &tweak_scalar).unwrap();
	(ret, pubkey_from(pk))
}

/// Aggregates the public keys into their aggregate public key.
///
/// Key order is not important as keys are sorted before aggregation.
pub fn combine_keys(keys: impl IntoIterator<Item = PublicKey>) -> XOnlyPublicKey {
	xonly_from(key_agg(keys).agg_pk())
}

pub fn nonce_pair(key: &Keypair) -> (SecretNonce, PublicNonce) {
	let kp = keypair_to(key);
	secpm::musig::new_nonce_pair(
		&SECP,
		SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
		None,
		Some(kp.secret_key()),
		kp.public_key(),
		None,
		Some(rand::random()),
	)
}

pub fn nonce_pair_with_msg(key: &Keypair, msg: &[u8; 32]) -> (SecretNonce, PublicNonce) {
	let kp = keypair_to(key);
	secpm::musig::new_nonce_pair(
		&SECP,
		SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
		None,
		Some(kp.secret_key()),
		kp.public_key(),
		Some(msg),
		Some(rand::random()),
	)
}

pub fn nonce_agg(pub_nonces: &[&PublicNonce]) -> AggregatedNonce {
	AggregatedNonce::new(&SECP, pub_nonces)
}

pub fn combine_partial_signatures(
	pubkeys: impl IntoIterator<Item = PublicKey>,
	agg_nonce: AggregatedNonce,
	sighash: [u8; 32],
	tweak: Option<[u8; 32]>,
	sigs: &[&PartialSignature],
) -> schnorr::Signature {
	let agg = if let Some(tweak) = tweak {
		tweaked_key_agg(pubkeys, tweak).0
	} else {
		key_agg(pubkeys)
	};

	let session = Session::new(&SECP, &agg, agg_nonce, &sighash);
	sig_from(session.partial_sig_agg(&sigs).assume_valid())
}

pub fn partial_sign(
	pubkeys: impl IntoIterator<Item = PublicKey>,
	agg_nonce: AggregatedNonce,
	key: &Keypair,
	sec_nonce: SecretNonce,
	sighash: [u8; 32],
	tweak: Option<[u8; 32]>,
	other_sigs: Option<&[&PartialSignature]>,
) -> (PartialSignature, Option<schnorr::Signature>) {
	let agg = if let Some(tweak) = tweak {
		tweaked_key_agg(pubkeys, tweak).0
	} else {
		key_agg(pubkeys)
	};

	let session = Session::new(&SECP, &agg, agg_nonce, &sighash);
	let my_sig = session.partial_sign(&SECP, sec_nonce, &keypair_to(&key), &agg);
	let final_sig = if let Some(others) = other_sigs {
		let mut sigs = Vec::with_capacity(others.len() + 1);
		sigs.extend_from_slice(others);
		sigs.push(&my_sig);
		Some(session.partial_sig_agg(&sigs))
	} else {
		None
	};
	(my_sig, final_sig.map(|s| sig_from(s.assume_valid())))
}

/// Perform a deterministic partial sign for the given message and the
/// given counterparty key and nonce.
///
/// This is only possible for the first party to sign if it has all the
/// counterparty nonces.
pub fn deterministic_partial_sign(
	my_key: &Keypair,
	their_pubkeys: impl IntoIterator<Item = PublicKey>,
	their_nonces: &[&PublicNonce],
	msg: [u8; 32],
	tweak: Option<[u8; 32]>,
) -> (PublicNonce, PartialSignature) {
	let agg = if let Some(tweak) = tweak {
		tweaked_key_agg(their_pubkeys.into_iter().chain(Some(my_key.public_key())), tweak).0
	} else {
		key_agg(their_pubkeys.into_iter().chain(Some(my_key.public_key())))
	};

	let (sec_nonce, pub_nonce) = secpm::musig::new_nonce_pair(
		&SECP,
		SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
		Some(&agg),
		Some(seckey_to(my_key.secret_key())),
		pubkey_to(my_key.public_key()),
		Some(&msg),
		Some(rand::random()),
	);

	let nonces = their_nonces.into_iter().map(|n| *n).chain(Some(&pub_nonce)).collect::<Vec<_>>();
	let agg_nonce = AggregatedNonce::new(&SECP, &nonces);
	let session = Session::new(&SECP, &agg, agg_nonce, &msg);
	let sig = session.partial_sign(&SECP, sec_nonce, &keypair_to(my_key), &agg);
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
		pub fn serialize<S: Serializer>(pub_nonce: &PublicNonce, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&pub_nonce.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicNonce, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			let b = TryFrom::try_from(&v[..]).map_err(D::Error::custom)?;
			PublicNonce::from_byte_array(b).map_err(D::Error::custom)
		}
	}
	pub mod partialsig {
		use super::*;
		pub fn serialize<S: Serializer>(sig: &PartialSignature, s: S) -> Result<S::Ok, S::Error> {
			s.serialize_bytes(&sig.serialize())
		}
		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PartialSignature, D::Error> {
			let v = d.deserialize_byte_buf(BytesVisitor)?;
			let b = TryFrom::try_from(&v[..]).map_err(D::Error::custom)?;
			PartialSignature::from_byte_array(b).map_err(D::Error::custom)
		}
	}
}
/// A type that actually represents a [SecretNonce] but without the
/// typesystem defenses for dangerous usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousSecretNonce(Vec<u8>);

impl DangerousSecretNonce {
	pub fn new(n: SecretNonce) -> Self {
		DangerousSecretNonce(n.dangerous_into_bytes().to_vec())
	}

	pub fn to_sec_nonce(&self) -> SecretNonce {
		assert_eq!(self.0.len(), MUSIG_SECNONCE_SIZE);
		SecretNonce::dangerous_from_bytes(TryFrom::try_from(&self.0[..]).expect("right size"))
	}
}
