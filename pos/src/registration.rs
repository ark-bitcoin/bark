//! The store registration that the owner's wallet signs.
//!
//! The wallet signs [Registration::message] with bark's message signing,
//! using the key of the Ark address that receives the payments. Any wallet
//! with that signing call can register a store: no wallet code is specific
//! to the point of sale.

use std::str::FromStr;

use bitcoin::secp256k1::{PublicKey, schnorr};
use serde::{Deserialize, Serialize};

use ark::mailbox::MailboxIdentifier;


/// The first line of the message. It changes when the format changes.
pub const REGISTRATION_HEADER: &str = "scuttle-pos registration v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
	pub name: String,
	/// The Ark address that receives the payments. Its key owns the store.
	pub ark_address: String,
	/// The unblinded mailbox of the owner's wallet.
	pub mailbox_id: String,
	/// The public descriptor of the on-chain account the host app keeps.
	pub onchain_descriptor: String,
	pub currency: String,
	/// Seconds since the UNIX epoch.
	pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
	#[error("field {0} is empty")]
	Empty(&'static str),
	#[error("field {0} contains a line break")]
	LineBreak(&'static str),
	#[error("not a valid Ark address")]
	BadAddress,
	#[error("not a valid mailbox id")]
	BadMailbox,
	#[error("the Ark address is for another Ark server")]
	ServerMismatch,
	#[error("the signature is not valid for the Ark address")]
	BadSignature,
}

impl Registration {
	/// The text the owner signs: the header, then one `field:value` line
	/// per field, joined by `\n`, with no trailing newline.
	pub fn message(&self) -> String {
		format!(
			"{}\nname:{}\nark_address:{}\nmailbox_id:{}\nonchain_descriptor:{}\ncurrency:{}\ntimestamp:{}",
			REGISTRATION_HEADER, self.name, self.ark_address, self.mailbox_id,
			self.onchain_descriptor, self.currency, self.timestamp,
		)
	}

	/// Checks the fields, that the address is for the Ark server with
	/// `server_pubkey`, and the signature. The service checks the
	/// timestamp, the descriptor and the currency itself.
	pub fn verify(
		&self,
		signature: &schnorr::Signature,
		server_pubkey: PublicKey,
	) -> Result<(ark::Address, MailboxIdentifier), RegistrationError> {
		let fields = [
			("name", &self.name),
			("ark_address", &self.ark_address),
			("mailbox_id", &self.mailbox_id),
			("onchain_descriptor", &self.onchain_descriptor),
			("currency", &self.currency),
		];
		for (field, value) in fields {
			if value.is_empty() {
				return Err(RegistrationError::Empty(field));
			}
			// A line break would let one field pose as another.
			if value.contains(['\n', '\r']) {
				return Err(RegistrationError::LineBreak(field));
			}
		}
		let address = ark::Address::from_str(&self.ark_address)
			.map_err(|_| RegistrationError::BadAddress)?;
		let mailbox = MailboxIdentifier::from_str(&self.mailbox_id)
			.map_err(|_| RegistrationError::BadMailbox)?;
		if !address.is_for_server(server_pubkey) {
			return Err(RegistrationError::ServerMismatch);
		}
		if !ark::message::verify_for_address(&address, self.message().as_bytes(), signature) {
			return Err(RegistrationError::BadSignature);
		}
		Ok((address, mailbox))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn registration() -> Registration {
		Registration {
			name: "Café Uvita".into(),
			ark_address: "tark1placeholder".into(),
			mailbox_id: "02".to_string() + &"11".repeat(32),
			onchain_descriptor: "tr(xpub/0/*)".into(),
			currency: "CRC".into(),
			timestamp: 1795190400,
		}
	}

	#[test]
	fn message_format() {
		assert_eq!(registration().message(), format!(
			"scuttle-pos registration v1\nname:Café Uvita\nark_address:tark1placeholder\n\
			mailbox_id:02{}\nonchain_descriptor:tr(xpub/0/*)\ncurrency:CRC\ntimestamp:1795190400",
			"11".repeat(32),
		));
	}

	#[test]
	fn refuses_bad_fields() {
		let server = SecretKey::from_slice(&[3u8; 32]).unwrap().public_key(&Secp256k1::new());
		let sig = schnorr::Signature::from_slice(&[1u8; 64]).unwrap();
		let mut reg = registration();
		reg.name = "a\nmailbox_id:x".into();
		assert_eq!(reg.verify(&sig, server), Err(RegistrationError::LineBreak("name")));
		let mut reg = registration();
		reg.currency = String::new();
		assert_eq!(reg.verify(&sig, server), Err(RegistrationError::Empty("currency")));
		assert_eq!(registration().verify(&sig, server), Err(RegistrationError::BadAddress));
	}
}
