//! Types for wallet recovery from seed.

use std::io;
use std::time::Duration;

use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{schnorr, Message, PublicKey};

use crate::SECP;
use crate::encode::{ProtocolDecodingError, ProtocolEncoding, ReadExt, WriteExt};

/// Authorization to list the VTXOs owned by the children of an xpub
///
/// It is signed by the private key of the xpub itself, so it proves knowledge
/// of the xpriv rather than of the xpub alone. It is bound to one server and
/// is only valid before its expiry UNIX timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XpubRecoveryAuthorization {
	expiry: i64,
	sig: schnorr::Signature,
}

impl XpubRecoveryAuthorization {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark xpub recovery authorization:";

	/// The furthest in the future an expiry is accepted by [Self::is_valid_now].
	pub const MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);

	fn signable_message(xpub: &Xpub, server_pubkey: PublicKey, expiry: i64) -> Message {
		let mut eng = sha256::Hash::engine();
		eng.input(Self::CHALLENGE_MESSAGE_PREFIX);
		eng.input(&server_pubkey.serialize());
		eng.input(&xpub.encode());
		eng.input(&expiry.to_le_bytes());
		Message::from_digest(sha256::Hash::from_engine(eng).to_byte_array())
	}

	pub fn new(
		xpriv: &Xpriv,
		server_pubkey: PublicKey,
		expiry: chrono::DateTime<chrono::Local>,
	) -> XpubRecoveryAuthorization {
		let expiry = expiry.timestamp();
		let xpub = Xpub::from_priv(&SECP, xpriv);
		let msg = Self::signable_message(&xpub, server_pubkey, expiry);
		let keypair = xpriv.to_keypair(&SECP);
		XpubRecoveryAuthorization {
			expiry: expiry,
			sig: SECP.sign_schnorr_with_aux_rand(&msg, &keypair, &rand::random()),
		}
	}

	/// The time at which this authorization expires
	pub fn expiry(&self) -> chrono::DateTime<chrono::Local> {
		chrono::DateTime::from_timestamp_secs(self.expiry)
			.expect("we guarantee valid timestamp")
			.with_timezone(&chrono::Local)
	}

	/// Verify the signature for the xpub and the server
	pub fn verify(&self, xpub: &Xpub, server_pubkey: PublicKey) -> bool {
		let msg = Self::signable_message(xpub, server_pubkey, self.expiry);
		SECP.verify_schnorr(&self.sig, &msg, &xpub.public_key.into()).is_ok()
	}

	/// Check that the authorization is not expired and doesn't expire further
	/// than [Self::MAX_LIFETIME] from now
	///
	/// Allows for 5 seconds of leeway on both ends for clock skew.
	pub fn is_valid_now(&self) -> bool {
		const LEEWAY: Duration = Duration::from_secs(5);
		let now = chrono::Local::now();
		let expiry = self.expiry();
		expiry >= now - LEEWAY && expiry <= now + Self::MAX_LIFETIME + LEEWAY
	}
}

impl ProtocolEncoding for XpubRecoveryAuthorization {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.expiry.to_le_bytes())?;
		self.sig.encode(w)?;
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self {
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

#[cfg(test)]
mod test {
	use bitcoin::NetworkKind;
	use bitcoin::secp256k1::Keypair;

	use super::*;

	fn new_xpriv(seed: u8) -> Xpriv {
		Xpriv::new_master(NetworkKind::Test, &[seed; 32]).unwrap()
	}

	fn server_pubkey(seed: u8) -> PublicKey {
		Keypair::from_seckey_slice(&SECP, &[seed; 32]).unwrap().public_key()
	}

	#[test]
	fn authorization_verifies_for_its_xpub_and_server_only() {
		let xpriv = new_xpriv(1);
		let xpub = Xpub::from_priv(&SECP, &xpriv);
		let expiry = chrono::Local::now() + Duration::from_secs(60);
		let auth = XpubRecoveryAuthorization::new(&xpriv, server_pubkey(2), expiry);

		assert!(auth.verify(&xpub, server_pubkey(2)));
		assert!(auth.is_valid_now());
		assert!(!auth.verify(&xpub, server_pubkey(3)), "bound to the server");
		let other = Xpub::from_priv(&SECP, &new_xpriv(4));
		assert!(!auth.verify(&other, server_pubkey(2)), "bound to the xpub");

		let decoded = XpubRecoveryAuthorization::deserialize(&auth.serialize()).unwrap();
		assert_eq!(decoded, auth);
	}

	#[test]
	fn authorization_expiry_window() {
		let xpriv = new_xpriv(1);
		let now = chrono::Local::now();

		let expired = XpubRecoveryAuthorization::new(&xpriv, server_pubkey(2),
			now - Duration::from_secs(60));
		assert!(!expired.is_valid_now());

		let too_long = XpubRecoveryAuthorization::new(&xpriv, server_pubkey(2),
			now + XpubRecoveryAuthorization::MAX_LIFETIME + Duration::from_secs(60));
		assert!(!too_long.is_valid_now());
	}
}
