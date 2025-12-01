
pub use secp256k1_musig as secpm;
pub use secp256k1_musig::musig::{
	AggregatedNonce, PublicNonce, PartialSignature, SecretNonce, Session, SessionSecretRand,
};


use bitcoin::secp256k1::{schnorr, Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use secpm::ffi::MUSIG_SECNONCE_SIZE;
use secpm::musig::KeyAggCache;

lazy_static! {
	/// Global secp context.
	pub static ref SECP: secpm::Secp256k1<secpm::All> = secpm::Secp256k1::new();
}

pub fn xonly_from(pk: secpm::XOnlyPublicKey) -> XOnlyPublicKey {
	XOnlyPublicKey::from_slice(&pk.serialize()).unwrap()
}

pub fn pubkey_to(pk: PublicKey) -> secpm::PublicKey {
	secpm::PublicKey::from_slice(&pk.serialize_uncompressed()).unwrap()
}

pub fn pubkey_from(pk: secpm::PublicKey) -> PublicKey {
	PublicKey::from_slice(&pk.serialize_uncompressed()).unwrap()
}

pub fn seckey_to(sk: SecretKey) -> secpm::SecretKey {
	secpm::SecretKey::from_secret_bytes(sk.secret_bytes()).unwrap()
}

pub fn keypair_to(kp: &Keypair) -> secpm::Keypair {
	secpm::Keypair::from_seckey_byte_array(kp.secret_bytes()).unwrap()
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
	KeyAggCache::new(&keys)
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
	let mut ret = KeyAggCache::new(&keys);
	let tweak_scalar = secpm::Scalar::from_be_bytes(tweak).unwrap();
	let pk = ret.pubkey_xonly_tweak_add(&tweak_scalar).unwrap();
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
		SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
		None,
		Some(kp.secret_key()),
		kp.public_key(),
		Some(msg),
		Some(rand::random()),
	)
}

pub fn nonce_agg(pub_nonces: &[&PublicNonce]) -> AggregatedNonce {
	AggregatedNonce::new(pub_nonces)
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

	let session = Session::new(&agg, agg_nonce, &sighash);
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

	let session = Session::new(&agg, agg_nonce, &sighash);
	let my_sig = session.partial_sign(sec_nonce, &keypair_to(&key), &agg);
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
		SessionSecretRand::assume_unique_per_nonce_gen(rand::random()),
		Some(&agg),
		Some(seckey_to(my_key.secret_key())),
		pubkey_to(my_key.public_key()),
		Some(&msg),
		Some(rand::random()),
	);

	let nonces = their_nonces.into_iter().map(|n| *n).chain(Some(&pub_nonce)).collect::<Vec<_>>();
	let agg_nonce = AggregatedNonce::new(&nonces);
	let session = Session::new(&agg, agg_nonce, &msg);
	let sig = session.partial_sign(sec_nonce, &keypair_to(my_key), &agg);
	(pub_nonce, sig)
}

//TODO(stevenroose) probably get rid of all this by having native byte serializers in secp
pub mod serde {
	use super::*;
	use ::serde::{Deserializer, Serializer};
	use ::serde::de::{self, Error};

	pub(super) struct BytesVisitor;
	impl<'de> de::Visitor<'de> for BytesVisitor {
		type Value = Vec<u8>;
		fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			write!(f, "a byte object")
		}
		fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DangerousSecretNonce([u8; MUSIG_SECNONCE_SIZE]);

impl DangerousSecretNonce {
	pub fn dangerous_from_secret_nonce(n: SecretNonce) -> Self {
		DangerousSecretNonce(n.dangerous_into_bytes())
	}

	pub fn to_sec_nonce(&self) -> SecretNonce {
		SecretNonce::dangerous_from_bytes(self.0.clone())
	}

	pub fn serialize(&self) -> [u8; MUSIG_SECNONCE_SIZE] {
		self.0.clone()
	}

	pub fn from_byte_array(bytes: [u8; MUSIG_SECNONCE_SIZE]) -> Self {
		Self(bytes)
	}
}

impl ::serde::Serialize for DangerousSecretNonce {
	fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_bytes(&self.0[..])
	}
}

impl<'de> ::serde::Deserialize<'de> for DangerousSecretNonce {
	fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {

		// can eventually use self::serde::BytesVisitor,
		// but we now also accept lists to be backwards compatible with Vec<u8>
		struct Visitor;
		impl<'de> ::serde::de::Visitor<'de> for Visitor {
			type Value = DangerousSecretNonce;
			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(f, "a sercret musig nonce")
			}
			fn visit_bytes<E: ::serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				TryFrom::try_from(v)
					.map(DangerousSecretNonce::from_byte_array)
					.map_err(|_| ::serde::de::Error::custom("invalid nonce"))
			}
			// be compatible with previous serialization
			fn visit_seq<A: ::serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
			    let mut buf = Vec::with_capacity(MUSIG_SECNONCE_SIZE);
				while let Some(e) = seq.next_element::<u8>()? {
					buf.push(e);
				}

				TryFrom::try_from(&buf[..])
					.map(DangerousSecretNonce::from_byte_array)
					.map_err(|_| ::serde::de::Error::custom("invalid nonce"))
			}
		}

		d.deserialize_any(Visitor)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn check_secnonce_serde_backwards_compat() {
		let old_example = "[34,14,220,241,180,58,27,107,242,94,46,188,49,93,184,43,106,56,122,169,152,94,66,191,174,151,204,92,46,98,136,90,36,157,87,31,121,220,132,111,215,45,84,171,202,93,147,0,95,177,81,31,9,178,49,66,6,46,48,146,122,120,169,193,196,26,248,12,254,130,145,44,72,98,212,216,130,188,160,32,233,255,151,175,212,179,236,166,29,124,170,6,105,95,89,39,57,90,229,234,160,79,115,5,71,11,180,46,211,198,109,140,248,12,53,4,246,201,129,87,194,97,237,214,255,196,105,121,180,98,60,132]";
		let _ = serde_json::from_str::<DangerousSecretNonce>(old_example).unwrap();
	}
}
