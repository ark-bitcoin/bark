use bitcoin::constants::ChainHash;
use bitcoin::Network;
pub use lightning::offers::offer::{Offer, Amount as OfferAmount};
pub use lightning::offers::invoice::Bolt12Invoice;

use std::str::FromStr;
use std::{fmt, io};

use bitcoin::Amount;
use bitcoin::bech32::{encode_to_fmt, EncodeError, Hrp, NoChecksum, primitives::decode::CheckedHrpstring};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use lightning::offers::parse::Bolt12ParseError;
use lightning::util::ser::Writeable;
use lightning_invoice::Bolt11Invoice;

use serde::{Deserialize, Serialize};

use bitcoin_ext::P2TR_DUST;

use crate::ProtocolDecodingError;
use crate::{musig, util, ProtocolEncoding, encode::{WriteExt, ReadExt}};
use crate::util::SECP;

const BECH32_BOLT12_INVOICE_HRP: &str = "lni";

/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;


/// A 32-byte secret preimage used for HTLC-based payments.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Preimage([u8; 32]);
impl_byte_newtype!(Preimage, 32);

impl Preimage {
	/// Generate a new random preimage.
	pub fn random() -> Preimage {
		Preimage(rand::random())
	}
}

/// The hash of a [Preimage], used to identify HTLC-based payments.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PaymentHash([u8; 32]);
impl_byte_newtype!(PaymentHash, 32);

impl From<sha256::Hash> for PaymentHash {
	fn from(hash: sha256::Hash) -> Self {
		PaymentHash(hash.to_byte_array())
	}
}

impl From<Preimage> for PaymentHash {
	fn from(preimage: Preimage) -> Self {
		PaymentHash::from_preimage(preimage)
	}
}

impl From<lightning::types::payment::PaymentHash> for PaymentHash {
	fn from(hash: lightning::types::payment::PaymentHash) -> Self {
		PaymentHash(hash.0)
	}
}

impl PaymentHash {
	pub fn from_preimage(preimage: Preimage) -> PaymentHash {
		sha256::Hash::hash(preimage.as_ref()).into()
	}

	/// Converts this PaymentHash into a `bitcoin::hashes::sha256::Hash`.
	pub fn to_sha256_hash(&self) -> bitcoin::hashes::sha256::Hash {
		bitcoin::hashes::sha256::Hash::from_slice(&self.0)
			.expect("PaymentHash must be 32 bytes, which is always valid for sha256::Hash")
	}
}

/// Build taproot spend info to build a VTXO to enable lightning send
///
/// This related to the [VtxoPolicy::ServerHtlcSend] policy.
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. The Server can use this path to revoke the HTLC if payment
/// failed
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, if it knows the preimage. Server can use this path if Alice
/// tries to spend using 3rd path.
///
/// 3. The other leaf allows Alice to spend the HTLC after its expiry
/// and with a delay. Alice must use this path if the server fails to
/// provide the preimage and refuse to revoke the HTLC. It will either
/// force the Server to reveal the preimage (by spending using 2nd path)
/// or give Alice her money back.
pub fn server_htlc_send_taproot(
	payment_hash: PaymentHash,
	server_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32,
) -> TaprootSpendInfo {
	let server_branch = util::hash_delay_sign(
		payment_hash.to_sha256_hash(), exit_delta, server_pubkey.x_only_public_key().0,
	);
	let user_branch = util::delay_timelock_sign(
		2 * exit_delta, htlc_expiry, user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, server_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, server_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}

/// Build taproot spend info to build a VTXO for Alice lightning receive
///
/// This related to the [VtxoPolicy::ServerHtlcRecv] policy.
///
/// This build a taproot with 3 clauses:
/// 1. The keyspend path allows Alice and Server to collaborate to spend
/// the HTLC. This is the expected path to be used. Server should only
/// accept to collaborate if Alice reveals the preimage.
///
/// 2. One leaf of the tree allows Server to spend the HTLC after the
/// expiry, with an exit delta delay. Server can use this path if Alice
/// tries to spend the HTLC using the 3rd path after the HTLC expiry
///
/// 3. The other leaf of the tree allows Alice to spend the HTLC if she
/// knows the preimage, but with a greater exit delta delay than Server.
/// Alice must use this path if she revealed the preimage but Server
/// refused to collaborate using the 1rst path.
pub fn server_htlc_receive_taproot(
	payment_hash: PaymentHash,
	server_pubkey: PublicKey,
	user_pubkey: PublicKey,
	exit_delta: u16,
	htlc_expiry: u32,
) -> TaprootSpendInfo {
	let server_branch =
		util::delay_timelock_sign(exit_delta, htlc_expiry, server_pubkey.x_only_public_key().0);
	let user_branch = util::hash_delay_sign(
		payment_hash.to_sha256_hash(),
		2 * exit_delta,
		user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, server_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, server_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}


#[derive(Debug, Clone)]
pub enum PaymentStatus {
	Pending,
	Complete,
	Failed,
}

impl fmt::Display for PaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

/// Enum to represent either a bolt11 or bolt12 invoice
///
/// Used in [`LightningPaymentDetails`] to represent the invoice to pay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Invoice {
	Bolt11(Bolt11Invoice),
	#[serde(with = "crate::encode::serde")]
	Bolt12(Bolt12Invoice),
}

#[derive(Debug, thiserror::Error)]
#[error("cannot parse invoice")]
pub struct InvoiceParseError;

impl FromStr for Invoice {
	type Err = InvoiceParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if let Ok(bolt11) = Bolt11Invoice::from_str(s) {
			Ok(Invoice::Bolt11(bolt11))
		} else if let Ok(bolt12) = Bolt12Invoice::from_str(s) {
			Ok(Invoice::Bolt12(bolt12))
		} else {
			Err(InvoiceParseError)
		}
	}
}

#[derive(Debug, thiserror::Error)]
#[error("invalid invoice signature: {0}")]
pub struct CheckSignatureError(pub String);

impl Invoice {
	pub fn into_bolt11(self) -> Option<Bolt11Invoice> {
		match self {
			Invoice::Bolt11(invoice) => Some(invoice),
			Invoice::Bolt12(_) => None
		}
	}

	pub fn payment_hash(&self) -> PaymentHash {
		match self {
			Invoice::Bolt11(invoice) => PaymentHash::from(*invoice.payment_hash().as_byte_array()),
			Invoice::Bolt12(invoice) => PaymentHash::from(invoice.payment_hash()),
		}
	}

	pub fn network(&self) -> Network {
		match self {
			Invoice::Bolt11(invoice) => invoice.network(),
			Invoice::Bolt12(invoice) => match invoice.chain() {
				ChainHash::BITCOIN => Network::Bitcoin,
				ChainHash::TESTNET3 => Network::Testnet,
				ChainHash::TESTNET4 => Network::Testnet4,
				ChainHash::SIGNET => Network::Signet,
				ChainHash::REGTEST => Network::Regtest,
				_ => panic!("unsupported network"),
			},
		}
	}

	pub fn amount_milli_satoshis(&self) -> Option<u64> {
		match self {
			Invoice::Bolt11(invoice) => invoice.amount_milli_satoshis(),
			Invoice::Bolt12(invoice) => invoice.amount_milli_satoshis(),
		}
	}

	pub fn check_signature(&self) -> Result<(), CheckSignatureError> {
		match self {
			Invoice::Bolt11(invoice) => invoice
				.check_signature()
				.map_err(|e| CheckSignatureError(e.to_string())),
			Invoice::Bolt12(invoice) => invoice.check_signature(),
		}
	}
}

impl fmt::Display for Invoice {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Invoice::Bolt11(invoice) => write!(f, "{}", invoice.to_string()),
			Invoice::Bolt12(invoice) => encode_to_fmt::<NoChecksum, _>(
				f,
				Hrp::parse("lni").unwrap(),
				&invoice.bytes(),
			)
			.map_err(|e| match e {
				EncodeError::Fmt(e) => e,
				_ => fmt::Error {},
			}),
		}
	}
}

pub trait Bolt12InvoiceExt: Sized {
	fn payment_hash(&self) -> PaymentHash;
	fn amount_milli_satoshis(&self) -> Option<u64>;
	fn check_signature(&self) -> Result<(), CheckSignatureError>;
	fn bytes(&self) -> Vec<u8>;
	fn from_bytes(bytes: &[u8]) -> Result<Self, Bolt12ParseError>;
	fn validate_issuance(&self, offer: Offer) -> Result<(), CheckSignatureError>;
	fn from_str(s: &str) -> Result<Bolt12Invoice, Bolt12ParseError>;
}

impl Bolt12InvoiceExt for Bolt12Invoice {
	fn payment_hash(&self) -> PaymentHash { PaymentHash::from(self.payment_hash()) }

	fn amount_milli_satoshis(&self) -> Option<u64> {
		Some(self.amount_msats())
	}

	fn check_signature(&self) -> Result<(), CheckSignatureError> {
		let message = Message::from_digest(self.signable_hash());
		let signature = self.signature();

		if let Some(pubkey) = self.issuer_signing_pubkey() {
			Ok(SECP.verify_schnorr(&signature, &message, &pubkey.into())
				.map_err(|_| CheckSignatureError("invalid signature".to_string()))?)
		} else {
			Err(CheckSignatureError("no pubkey on offer, cannot verify signature".to_string()))
		}
	}

	fn bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		self.write(&mut bytes).expect("Writing into a Vec is infallible");
		bytes
	}

	fn from_bytes(bytes: &[u8]) -> Result<Self, Bolt12ParseError> {
		Bolt12Invoice::try_from(bytes.to_vec())
	}

	fn validate_issuance(&self, offer: Offer) -> Result<(), CheckSignatureError> {
		if self.issuer_signing_pubkey() != offer.issuer_signing_pubkey() {
			Err(CheckSignatureError("public keys mismatch".to_string()))
		} else {
			Ok(())
		}
	}

	fn from_str(s: &str) -> Result<Self, Bolt12ParseError> {
		let dec = CheckedHrpstring::new::<NoChecksum>(&s)?;
		if dec.hrp().to_lowercase() != BECH32_BOLT12_INVOICE_HRP {
			return Err(Bolt12ParseError::InvalidBech32Hrp);
		}

		let data = dec.byte_iter().collect::<Vec<_>>();
		Bolt12Invoice::try_from(data)
	}
}

impl<T: Bolt12InvoiceExt> ProtocolEncoding for T {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.emit_slice(&self.bytes())
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut bytes = Vec::new();
		reader.read_slice(&mut bytes)?;
		Self::from_bytes(&bytes).map_err(|e| ProtocolDecodingError::invalid(format!("{:?}", e)))
	}
}
