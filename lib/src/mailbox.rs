//! Types for using the Unified Mailbox feature of the bark server.
//!
//! For more information on the mailbox, check the `docs/mailbox.md` file.

use std::io;

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{ecdh, schnorr, Keypair, Message, PublicKey};
use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;

use crate::SECP;
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};

/// Identifier for a mailbox
///
/// Represented as a curve point.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxIdentifier([u8; PUBLIC_KEY_SIZE]);

impl_byte_newtype!(MailboxIdentifier, PUBLIC_KEY_SIZE);

impl MailboxIdentifier {
	/// Convert to public key
	pub fn as_pubkey(&self) -> PublicKey {
		PublicKey::from_slice(&self.0).expect("invalid pubkey")
	}

	/// Convert from a public key
	pub fn from_pubkey(pubkey: PublicKey) -> Self {
		Self(pubkey.serialize())
	}

	/// Blind the mailbox id with the server pubkey and the VTXO privkey
	pub fn to_blinded(
		&self,
		server_pubkey: PublicKey,
		vtxo_key: &Keypair,
	) -> BlindedMailboxIdentifier {
		BlindedMailboxIdentifier::new(*self, server_pubkey, vtxo_key)
	}

	/// Unblind a blinded mailbox identifier
	pub fn from_blinded(
		blinded: BlindedMailboxIdentifier,
		vtxo_pubkey: PublicKey,
		server_key: &Keypair,
	) -> MailboxIdentifier {
		let dh = ecdh::shared_secret_point(&vtxo_pubkey, &server_key.secret_key());
		let neg_dh_pk = point_to_pubkey(&dh).negate(&SECP);
		let ret = PublicKey::combine_keys(&[&blinded.as_pubkey(), &neg_dh_pk])
			.expect("error adding DH secret to mailbox key");
		Self(ret.serialize())
	}
}

impl From<PublicKey> for MailboxIdentifier {
	fn from(pk: PublicKey) -> Self {
		Self::from_pubkey(pk)
	}
}

impl ProtocolEncoding for MailboxIdentifier {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(self.as_ref())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self(r.read_byte_array()?))
	}
}

/// Blinded identifier for a mailbox
///
/// It is blinded by adding to the mailbox public key point the
/// Diffie-Hellman secret between the server's key and the VTXO key from
/// the address.
///
/// Represented as a curve point.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlindedMailboxIdentifier([u8; PUBLIC_KEY_SIZE]);

impl_byte_newtype!(BlindedMailboxIdentifier, PUBLIC_KEY_SIZE);

impl BlindedMailboxIdentifier {
	pub fn new(
		mailbox_id: MailboxIdentifier,
		server_pubkey: PublicKey,
		vtxo_key: &Keypair,
	) -> BlindedMailboxIdentifier {
		let dh = ecdh::shared_secret_point(&server_pubkey, &vtxo_key.secret_key());
		let dh_pk = point_to_pubkey(&dh);
		let ret = PublicKey::combine_keys(&[&mailbox_id.as_pubkey(), &dh_pk])
			.expect("error adding DH secret to mailbox key");
		Self(ret.serialize())
	}

	/// Convert to public key
	pub fn as_pubkey(&self) -> PublicKey {
		PublicKey::from_slice(&self.0).expect("invalid pubkey")
	}

	/// Convert from a public key
	pub fn from_pubkey(pubkey: PublicKey) -> Self {
		Self(pubkey.serialize())
	}
}

impl From<PublicKey> for BlindedMailboxIdentifier {
	fn from(pk: PublicKey) -> Self {
		Self::from_pubkey(pk)
	}
}

impl ProtocolEncoding for BlindedMailboxIdentifier {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(self.as_ref())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self(r.read_byte_array()?))
	}
}

/// Authorization to read a VTXO mailbox
///
/// It is tied to a block hash and is valid only as long as this block
/// is recent. Recentness is specified per Ark server, but users are
/// encouraged to use the tip when creating an authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailboxAuthorization {
	id: MailboxIdentifier,
	expiry: i64,
	sig: schnorr::Signature,
}

impl MailboxAuthorization {
	const CHALENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark VTXO mailbox authorization: ";

	fn signable_message(expiry: i64) -> Message {
		let mut eng = sha256::Hash::engine();
		eng.input(Self::CHALENGE_MESSAGE_PREFIX);
		eng.input(&expiry.to_le_bytes());
		Message::from_digest(sha256::Hash::from_engine(eng).to_byte_array())
	}

	pub fn new(
		mailbox_key: &Keypair,
		expiry: chrono::DateTime<chrono::Local>,
	) -> MailboxAuthorization {
		let expiry = expiry.timestamp();
		let msg = Self::signable_message(expiry);
		MailboxAuthorization {
			id: MailboxIdentifier::from_pubkey(mailbox_key.public_key()),
			expiry: expiry,
			sig: SECP.sign_schnorr_with_aux_rand(&msg, mailbox_key, &rand::random()),
		}
	}

	/// The mailbox ID for which this authorization is signed
	pub fn mailbox(&self) -> MailboxIdentifier {
		self.id
	}

	/// The time at which this authorization expires
	pub fn expiry(&self) -> chrono::DateTime<chrono::Local> {
		chrono::DateTime::from_timestamp_secs(self.expiry)
			.expect("we guarantee valid timestamp")
			.with_timezone(&chrono::Local)
	}

	/// Verify the signature for the mailbox and block hash
	pub fn verify(&self) -> bool {
		let msg = Self::signable_message(self.expiry);
		SECP.verify_schnorr(&self.sig, &msg, &self.id.as_pubkey().into()).is_ok()
	}
}

impl ProtocolEncoding for MailboxAuthorization {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		self.id.encode(w)?;
		w.emit_slice(&self.expiry.to_le_bytes())?;
		self.sig.encode(w)?;
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self {
			id: ProtocolEncoding::decode(r)?,
			expiry: {
				let timestamp = i64::from_le_bytes(r.read_byte_array()?);
				// enforce that timestamp is a valid one
				let _ = chrono::DateTime::from_timestamp_secs(timestamp)
					.ok_or_else(|| ProtocolDecodingError::invalid("invalid timestamp"))?;
				timestamp
			},
			sig: ProtocolEncoding::decode(r)?,
		})
	}
}

/// Convert the raw x,y coordinate pair into a [PublicKey]
fn point_to_pubkey(point: &[u8; 64]) -> PublicKey {
	//TODO(stevenroose) try to get an official api for this
	let mut uncompressed = [0u8; 65];
	uncompressed[0] = 0x04;
	uncompressed[1..].copy_from_slice(point);
	PublicKey::from_slice(&uncompressed).expect("invalid uncompressed pk")
}

#[cfg(test)]
mod test {
	use std::time::Duration;
	use bitcoin::secp256k1::rand;
	use super::*;

	#[test]
	fn mailbox_blinding() {
		let mailbox_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let server_mailbox_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let vtxo_key = Keypair::new(&SECP, &mut rand::thread_rng());

		let mailbox = MailboxIdentifier::from_pubkey(mailbox_key.public_key());

		let blinded = mailbox.to_blinded(server_mailbox_key.public_key(), &vtxo_key);

		let unblinded = MailboxIdentifier::from_blinded(
			blinded, vtxo_key.public_key(), &server_mailbox_key,
		);

		assert_eq!(unblinded, mailbox);
	}

	#[test]
	fn mailbox_authorization() {
		let mailbox_key = Keypair::new(&SECP, &mut rand::thread_rng());
		let mailbox = MailboxIdentifier::from_pubkey(mailbox_key.public_key());

		let expiry = chrono::Local::now() + Duration::from_secs(60);
		let auth = MailboxAuthorization::new(&mailbox_key, expiry);
		assert_eq!(auth.mailbox(), mailbox);
		assert!(auth.verify());

		assert_eq!(auth, MailboxAuthorization::deserialize(&auth.serialize()).unwrap());

		// an old one
		let decoded = MailboxAuthorization::deserialize_hex("023f6712126b93bd479baec93fa4b6e6eb7aa8100b2e818954a351e2eb459ccbeac3380369000000000163b3184156804eb26ffbad964a70840229c4ac80da5da9f9a7557874c45259af48671aa26f567c3c855092c51a1ceeb8a17c7540abe0a50e89866bdb90ece9").unwrap();
		assert_eq!(decoded.expiry, 1761818819);
		assert_eq!(decoded.id.to_string(), "023f6712126b93bd479baec93fa4b6e6eb7aa8100b2e818954a351e2eb459ccbea");
		assert!(decoded.verify());
	}
}

