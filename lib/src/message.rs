//! Signing and verification of arbitrary messages.
//!
//! Messages are signed with a BIP-340 Schnorr signature over a
//! SHA256 hash of the message bytes:
//! ```text
//! digest = SHA256( "bark/message" || message )
//! ```
//!
//! The hash is prefixed with a constant string to prevent collisions
//! with other signatures.
//!
//! A message can be verified either against a public key directly, or
//! against an Ark [Address].

use std::io::Write;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{schnorr, Keypair, Message, PublicKey};

use crate::SECP;
use crate::address::Address;

const CHALLENGE_MESSAGE_PREFIX: &[u8] = b"bark/message";

/// The digest to be signed for the given message
fn signable_digest(message: &[u8]) -> Message {
	let mut engine = sha256::Hash::engine();
	engine.write_all(CHALLENGE_MESSAGE_PREFIX).unwrap();
	engine.write_all(message).unwrap();

	let hash = sha256::Hash::from_engine(engine).to_byte_array();
	Message::from_digest(hash)
}

/// Sign an arbitrary message with the given keypair
///
/// The message is domain-separated by hashing it with a constant
/// prefix, see the [module documentation](self) for the exact scheme.
pub fn sign(keypair: &Keypair, message: &[u8]) -> schnorr::Signature {
	SECP.sign_schnorr_with_aux_rand(&signable_digest(message), keypair, &rand::random())
}

/// Verify a message signature created by [sign] against
/// the given public key
pub fn verify(
	pubkey: PublicKey,
	message: &[u8],
	signature: &schnorr::Signature,
) -> bool {
	SECP.verify_schnorr(signature, &signable_digest(message), &pubkey.into()).is_ok()
}

/// Verify a message signature created by [sign] against the
/// user public key of the given [Address]
pub fn verify_for_address(
	address: &Address,
	message: &[u8],
	signature: &schnorr::Signature,
) -> bool {
	verify(address.policy().user_pubkey(), message, signature)
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use crate::address::VtxoDelivery;
	use crate::mailbox::BlindedMailboxIdentifier;

	use super::*;

	#[test]
	fn sign_and_verify() {
		let keypair = Keypair::from_str(
			"6b0f024af54172a9aed9a0f044689175787676c469ff2aa75024cae5445c7a02",
		).unwrap();
		let message = b"hello ark";

		let sig = sign(&keypair, message);
		assert!(verify(keypair.public_key(), message, &sig));

		// wrong message
		assert!(!verify(keypair.public_key(), b"hello bark", &sig));

		// wrong key
		let other = Keypair::from_str(
			"0000000000000000000000000000000000000000000000000000000000000001",
		).unwrap();
		assert!(!verify(other.public_key(), message, &sig));

		// an unprefixed plain sha256 signature must not verify
		let plain = Message::from_digest(
			bitcoin::hashes::sha256::Hash::hash(message).to_byte_array(),
		);
		let plain_sig = SECP.sign_schnorr_no_aux_rand(&plain, &keypair);
		assert!(!verify(keypair.public_key(), message, &plain_sig));
	}

	#[test]
	fn verify_message_for_address() {
		let server = PublicKey::from_str(
			"02037188bdd7579a0cd0b22a51110986df1ea08e30192658fe0e219590e4a723d3",
		).unwrap();
		let keypair = Keypair::from_str(
			"6b0f024af54172a9aed9a0f044689175787676c469ff2aa75024cae5445c7a02",
		).unwrap();
		let blinded_id = BlindedMailboxIdentifier::from_pubkey(keypair.public_key());
		let addr = Address::builder()
			.server_pubkey(server)
			.pubkey_policy(keypair.public_key())
			.delivery(VtxoDelivery::ServerMailbox { blinded_id })
			.into_address().unwrap();

		let message = b"hello ark";
		let sig = sign(&keypair, message);
		assert!(verify_for_address(&addr, message, &sig));
		assert!(!verify_for_address(&addr, b"hello bark", &sig));
	}

	/// Pins the signing scheme: this signature was created with
	/// `sign_schnorr_no_aux_rand` over the prefixed digest. If this test
	/// breaks, the message signing scheme changed, which breaks all
	/// existing signatures in the wild.
	#[test]
	fn test_vector() {
		let keypair = Keypair::from_str(
			"6b0f024af54172a9aed9a0f044689175787676c469ff2aa75024cae5445c7a02",
		).unwrap();
		let message = b"ark signmessage test vector";

		let digest = signable_digest(message);
		let sig = SECP.sign_schnorr_no_aux_rand(&digest, &keypair);
		assert_eq!(sig.to_string(),
			"84e04017d4afeb4e945a2f69d2d969edfc5c15a0ced4397ea9dcc07a34bffb15\
			f5ae22424126adc2bc23183b6949f0ec5113e5c99081ffde241c653772e9c64f",
		);
		assert!(verify(keypair.public_key(), message, &sig));
	}
}
