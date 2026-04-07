use bitcoin::constants::ChainHash;
pub use lightning::offers::invoice::Bolt12Invoice;
pub use lightning_invoice::Bolt11Invoice;
pub use lightning::offers::offer::{Amount as OfferAmount, Offer};

use std::fmt;
use std::borrow::Borrow;
use std::str::FromStr;

use bitcoin::{Amount, Network};
use bitcoin::bech32::{encode_to_fmt, EncodeError, Hrp, NoChecksum, primitives::decode::CheckedHrpstring};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Message;
use lightning::offers::parse::Bolt12ParseError;
use lightning::util::ser::Writeable;

use bitcoin_ext::{AmountExt, P2TR_DUST};

use crate::SECP;

const BECH32_BOLT12_INVOICE_HRP: &str = "lni";

/// The minimum fee we consider for an HTLC transaction.
pub const HTLC_MIN_FEE: Amount = P2TR_DUST;

pub const PREIMAGE_SIZE: usize = 32;
pub const PAYMENT_HASH_SIZE: usize = 32;

/// A 32-byte secret preimage used for HTLC-based payments.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Preimage([u8; PREIMAGE_SIZE]);
impl_byte_newtype!(Preimage, PREIMAGE_SIZE);

impl Preimage {
	/// Generate a new random preimage.
	pub fn random() -> Preimage {
		Preimage(rand::random())
	}

	/// Hashes the preimage into the payment hash
	pub fn compute_payment_hash(&self) -> PaymentHash {
		sha256::Hash::hash(self.as_ref()).into()
	}
}

/// The hash of a [Preimage], used to identify HTLC-based payments.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PaymentHash([u8; PAYMENT_HASH_SIZE]);
impl_byte_newtype!(PaymentHash, PAYMENT_HASH_SIZE);

impl From<sha256::Hash> for PaymentHash {
	fn from(hash: sha256::Hash) -> Self {
		PaymentHash(hash.to_byte_array())
	}
}

impl From<Preimage> for PaymentHash {
	fn from(preimage: Preimage) -> Self {
		preimage.compute_payment_hash()
	}
}

impl From<lightning::types::payment::PaymentHash> for PaymentHash {
	fn from(hash: lightning::types::payment::PaymentHash) -> Self {
		PaymentHash(hash.0)
	}
}

impl<'a> From<&'a Bolt11Invoice> for PaymentHash {
	fn from(i: &'a Bolt11Invoice) -> Self {
		(*i.payment_hash()).into()
	}
}

impl From<Bolt11Invoice> for PaymentHash {
	fn from(i: Bolt11Invoice) -> Self {
		(&i).into()
	}
}

impl PaymentHash {
	/// Converts this PaymentHash into a [sha256::Hash].
	pub fn to_sha256_hash(&self) -> sha256::Hash {
		sha256::Hash::from_byte_array(self.0)
	}
}

/// Trait to capture any type that is associated with a Lightning payment hash
pub trait AsPaymentHash {
	/// Get the payment hash associated with this item
	// NB names "as_payment_hash" to avoid collision with the native "payment_hash" methods
	fn as_payment_hash(&self) -> PaymentHash;
}

impl AsPaymentHash for PaymentHash {
	fn as_payment_hash(&self) -> PaymentHash { *self }
}

impl AsPaymentHash for Preimage {
	fn as_payment_hash(&self) -> PaymentHash { self.compute_payment_hash() }
}

impl AsPaymentHash for Bolt11Invoice {
	fn as_payment_hash(&self) -> PaymentHash { PaymentHash::from(*self.payment_hash()) }
}

impl AsPaymentHash for Bolt12Invoice {
	fn as_payment_hash(&self) -> PaymentHash { self.payment_hash().into() }
}

impl AsPaymentHash for Invoice {
	fn as_payment_hash(&self) -> PaymentHash {
	    match self {
			Invoice::Bolt11(i) => AsPaymentHash::as_payment_hash(i),
			Invoice::Bolt12(i) => AsPaymentHash::as_payment_hash(i),
		}
	}
}

impl<'a, T: AsPaymentHash> AsPaymentHash for &'a T {
	fn as_payment_hash(&self) -> PaymentHash {
		AsPaymentHash::as_payment_hash(*self)
	}
}

#[derive(Debug, Clone)]
pub enum PaymentStatus {
	Pending,
	Success(Preimage),
	Failed,
}

impl fmt::Display for PaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
	}
}

/// Enum to represent either a lightning [Bolt11Invoice] or a [Bolt12Invoice].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Invoice {
	Bolt11(Bolt11Invoice),
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

impl From<Bolt11Invoice> for Invoice {
	fn from(invoice: Bolt11Invoice) -> Self {
		Invoice::Bolt11(invoice)
	}
}

impl From<Bolt12Invoice> for Invoice {
	fn from(invoice: Bolt12Invoice) -> Self {
		Invoice::Bolt12(invoice)
	}
}

impl<'a> TryFrom<&'a str> for Invoice {
	type Error = <Invoice as FromStr>::Err;
	fn try_from(invoice: &'a str) -> Result<Self, Self::Error> {
	    FromStr::from_str(invoice)
	}
}

impl TryFrom<String> for Invoice {
	type Error = <Invoice as FromStr>::Err;
	fn try_from(invoice: String) -> Result<Self, Self::Error> {
	    FromStr::from_str(&invoice)
	}
}

impl serde::Serialize for Invoice {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(self)
	}
}

impl<'de> serde::Deserialize<'de> for Invoice {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Invoice;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a lightning invoice")
			}
			fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				Invoice::from_str(v).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}


#[derive(Debug, thiserror::Error)]
#[error("invoice amount mismatch: invoice={invoice}, user={user}")]
pub enum CheckAmountError {
	#[error("invalid user amount: invoice={invoice}, user={user}")]
	InvalidUserAmount { invoice: Amount, user: Amount },
	#[error("offer currency is not supported: {amount:?}")]
	UnsupportedCurrency { amount: OfferAmount },
	#[error("user amount required")]
	UserAmountRequired,
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

	/// Get the amount to be paid. It checks both user and invoice
	/// equality if both are provided, else it tries to return one
	/// of them, or returns an error if neither are provided.
	pub fn get_payment_amount(
		&self,
		user_amount: Option<Amount>,
	) -> Result<Amount, CheckAmountError> {
		match self {
			Invoice::Bolt11(invoice) => invoice.get_payment_amount(user_amount),
			Invoice::Bolt12(invoice) => invoice.get_payment_amount(user_amount),
		}
	}

	pub fn amount_msat(&self) -> Option<u64> {
		match self {
			Invoice::Bolt11(invoice) => invoice.amount_milli_satoshis(),
			Invoice::Bolt12(invoice) => Some(invoice.amount_msats()),
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

/// Get the amount to be paid. It checks both user and invoice
/// equality if both are provided, else it tries to return one
/// of them, or returns an error if neither are provided.
fn get_invoice_payment_amount(invoice_amount: Option<Amount>, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
	match (invoice_amount, user_amount) {
		(Some(invoice_amount), Some(user_amount)) => {
			// NB: If provided, the user amount must be at least the invoice amount
			// and we allow up to 2x the invoice amount, as specified in BOLT 4
			if user_amount >= invoice_amount && user_amount <= invoice_amount * 2 {
				return Ok(user_amount);
			}

			return Err(CheckAmountError::InvalidUserAmount {
				invoice: invoice_amount,
				user: user_amount,
			});
		}
		(Some(invoice_amount), None) => {
			return Ok(invoice_amount);
		}
		(None, Some(user_amount)) => {
			return Ok(user_amount);
		}
		(None, None) => {
			return Err(CheckAmountError::UserAmountRequired);
		}
	}
}

/// Extension trait for the [Bolt11Invoice] type
pub trait Bolt11InvoiceExt: Borrow<Bolt11Invoice> {
	/// Get the amount to be paid. It checks both user and invoice
	/// equality if both are provided, else it tries to return one
	/// of them, or returns an error if neither are provided.
	fn get_payment_amount(&self, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
		let invoice_amount = self.borrow().amount_milli_satoshis()
			.map(Amount::from_msat_ceil);

		get_invoice_payment_amount(invoice_amount, user_amount)
	}
}

impl Bolt11InvoiceExt for Bolt11Invoice {}

/// Extension trait for the [Bolt12Invoice] type
pub trait Bolt12InvoiceExt: Borrow<Bolt12Invoice> {
	fn payment_hash(&self) -> PaymentHash { PaymentHash::from(self.borrow().payment_hash()) }

	/// Get the amount to be paid. It checks both user and invoice
	/// equality if both are provided, else it tries to return one
	/// of them, or returns an error if neither are provided.
	fn get_payment_amount(&self, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
		let invoice_amount = Amount::from_msat_ceil(self.borrow().amount_msats());
		get_invoice_payment_amount(Some(invoice_amount), user_amount)
	}

	fn check_signature(&self) -> Result<(), CheckSignatureError> {
		let message = Message::from_digest(self.borrow().signable_hash());
		let signature = self.borrow().signature();

		let pubkey = self.borrow().signing_pubkey();
		SECP.verify_schnorr(&signature, &message, &pubkey.into())
			.map_err(|_| CheckSignatureError("invalid signature".to_string()))
	}

	fn bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		self.borrow().write(&mut bytes).expect("Writing into a Vec is infallible");
		bytes
	}

	fn from_bytes(bytes: &[u8]) -> Result<Bolt12Invoice, Bolt12ParseError> {
		Bolt12Invoice::try_from(bytes.to_vec())
	}

	fn validate_issuance(&self, offer: &Offer) -> Result<(), CheckSignatureError> {
		if let Some(issuer_signing_pubkey) = offer.issuer_signing_pubkey() {
			if issuer_signing_pubkey != self.borrow().signing_pubkey() {
				return Err(CheckSignatureError("public keys mismatch".to_string()));
			}

			self.check_signature()
		} else {
			for offer_path in offer.paths() {
				let final_hop_pk = offer_path.blinded_hops().last()
					.map(|hop| hop.blinded_node_id);

				match final_hop_pk {
					Some(final_hop_pk) if final_hop_pk == self.borrow().signing_pubkey() => {
						return self.check_signature();
					}
					_ => {}
				}
			}

			Err(CheckSignatureError("public keys mismatch".to_string()))
		}
	}

	fn from_str(s: &str) -> Result<Bolt12Invoice, Bolt12ParseError> {
		let dec = CheckedHrpstring::new::<NoChecksum>(&s)?;
		if dec.hrp().to_lowercase() != BECH32_BOLT12_INVOICE_HRP {
			return Err(Bolt12ParseError::InvalidBech32Hrp);
		}

		let data = dec.byte_iter().collect::<Vec<_>>();
		Bolt12Invoice::try_from(data)
	}
}

impl Bolt12InvoiceExt for Bolt12Invoice {}

#[cfg(test)]
mod test {
	use super::*;

	use hex_conservative::FromHex;
	use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
	use lightning::blinded_path::BlindedHop;
	use lightning::blinded_path::payment::{BlindedPayInfo, BlindedPaymentPath};
	use lightning::ln::channelmanager::PaymentId;
	use lightning::ln::inbound_payment::ExpandedKey;
	use lightning::offers::nonce::Nonce;
	use lightning::offers::invoice_request::InvoiceRequest;
	use lightning::offers::offer::OfferBuilder;
	use lightning::sign::EntropySource;
	use lightning::types::features::BlindedHopFeatures;

	struct FixedEntropy;

	impl EntropySource for FixedEntropy {
		fn get_secure_random_bytes(&self) -> [u8; 32] { [42; 32] }
	}

	fn pubkey(byte: u8) -> bitcoin::secp256k1::PublicKey {
		let secp = Secp256k1::new();
		bitcoin::secp256k1::PublicKey::from_secret_key(
			&secp,
			&SecretKey::from_slice(&[byte; 32]).unwrap(),
		)
	}

	fn payment_paths() -> Vec<BlindedPaymentPath> {
		vec![BlindedPaymentPath::from_blinded_path_and_payinfo(
			pubkey(40),
			pubkey(41),
			vec![
				BlindedHop { blinded_node_id: pubkey(43), encrypted_payload: vec![0; 43] },
				BlindedHop { blinded_node_id: pubkey(44), encrypted_payload: vec![0; 44] },
			],
			BlindedPayInfo {
				fee_base_msat: 1,
				fee_proportional_millionths: 1_000,
				cltv_expiry_delta: 42,
				htlc_minimum_msat: 100,
				htlc_maximum_msat: 1_000_000_000_000,
				features: BlindedHopFeatures::empty(),
			},
		)]
	}

	#[test]
	fn offer_with_signing_pubkey_validate_invoice() {
		let secp = Secp256k1::new();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy;
		let nonce = Nonce::from_entropy_source(&entropy);

		// Recipient (offer issuer) keys
		let recipient_keys = Keypair::from_secret_key(
			&secp,
			&SecretKey::from_slice(&[43; 32]).unwrap(),
		);

		// Build the offer
		let offer = OfferBuilder::new(recipient_keys.public_key())
			.amount_msats(1_000_000)
			.build()
			.unwrap();

		assert_eq!(offer.amount(), Some(OfferAmount::Bitcoin { amount_msats: 1_000_000 }));
		assert_eq!(offer.issuer_signing_pubkey(), Some(recipient_keys.public_key()));

		// Build an invoice request from the offer
		let payment_id = PaymentId([1; 32]);
		let invoice_request = offer
			.request_invoice(&expanded_key, nonce, &secp, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		assert_eq!(invoice_request.issuer_signing_pubkey(), Some(recipient_keys.public_key()));

		// Build and sign the invoice from the request
		let payment_hash = lightning::types::payment::PaymentHash([99; 32]);
		let unsigned_invoice = invoice_request
			.respond_with(payment_paths(), payment_hash)
			.unwrap()
			.build()
			.unwrap();

		let invoice = unsigned_invoice
			.sign(|msg: &lightning::offers::invoice::UnsignedBolt12Invoice| {
				Ok(secp.sign_schnorr_no_aux_rand(msg.as_ref().as_digest(), &recipient_keys))
			})
			.unwrap();

		// Verify the invoice
		assert_eq!(invoice.payment_hash(), payment_hash);
		assert_eq!(invoice.amount_msats(), 1_000_000);
		assert_eq!(
			invoice.issuer_signing_pubkey(),
			Some(recipient_keys.public_key()),
		);

		let amount = invoice.get_payment_amount(None).unwrap();
		assert_eq!(amount, Amount::from_sat(1_000));

		invoice.check_signature().unwrap();
		invoice.validate_issuance(&offer).unwrap();
	}

	#[test]
	fn offer_no_signing_pubkey_validate_invoice() {
		// An offer with no issuer signing pubkey
		let offer_str = "lno1pqpzwyq2qe3k7enxv4j3pjgrrwzv24nmzfjypx2a8m264ws9vht3uxp5vpypnluuzl67n4waq78syn2tdngnvypje2da9t4emyq25n29m84dszkfggehf3z35uj56pmxqgp5vfme44926w23gc282xn3pp0j7y8pc7je8e8qxrhmtwrjrnj4kzcqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjnrlnqdqf52q7jwgcnxgnuseav37nvs0zn06dyfs79hk7uk8lrxuqzqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
		// An invoice request built from the offer above
		let invoice_request_hex = "00208f483020855be2127df9a1b25963afbb633c183d06d3223cf31942a059fb861b080227100a06636f6666656510c9031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07660203462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0020000000000000000000000000000000000000000000000000000000000000000002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3370020000000000000000000000000000000000000000000000000000000000000000052022710582103d084805e2f4c2bcf5188e40e7baec8b8680a1554da028b3d4c25e8969869fbe5f0401404f55082e4499ad85ac9cef739909f61243800ba31e2718bd5e40f08b05be22181ec91a4ccdf8c2cbb1feae62a62cda13ea069ca0134add34b215e6019bc33";
		// An invoice to return to invoice request emitter, still with no issuer signing pubkey
		let invoice_hex = "00208f483020855be2127df9a1b25963afbb633c183d06d3223cf31942a059fb861b080227100a06636f6666656510c9031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07660203462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0020000000000000000000000000000000000000000000000000000000000000000002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3370020000000000000000000000000000000000000000000000000000000000000000052022710582103d084805e2f4c2bcf5188e40e7baec8b8680a1554da028b3d4c25e8969869fbe5a0c9031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07660203462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0020000000000000000000000000000000000000000000000000000000000000000002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33700200000000000000000000000000000000000000000000000000000000000000000a21c00000001000003e8002a0000000000000064000000e8d4a510000000a40469d570dfa820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa022710b02102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337f0408f1efd3aafd2b200bb740b16b2311487312da67520b9d2977335074e27db8c8cdba9ea1c45f89f1c345ace60c48c1cd8cc149c184851cbc58d8221be4794db7b";
		// An invoice issued for another offer
		let other_offer_invoice_hex = "00202aa648ba07b96455928d4908f851c9e7f4bc1c4b44896ffa952bd116db27873e080213880a0374656110c90362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a0203f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b0020000000000000000000000000000000000000000000000000000000000000000002989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f0020000000000000000000000000000000000000000000000000000000000000000052021388582103d9f3787be32e810bc0a72ebb252160b76da09c9adba45ee62aa94f048c8f12e1a0c90362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f703f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a0203f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b0020000000000000000000000000000000000000000000000000000000000000000002989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f00200000000000000000000000000000000000000000000000000000000000000000a21c00000001000003e8002a0000000000000064000000e8d4a510000000a40469d5f147a820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaa021388b02102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6ff0407e645ece0602cddf966b5fcb99cf0829ca3952f5a2401d2c063be0e7895944d61409774afdea389c7486e5eadc74666347307f251444f9ea34f6eb2538848e65";
		// An invoice issued from offer, with one additional path not leading to offer's node
		let extra_path_invoice_hex = "00208f483020855be2127df9a1b25963afbb633c183d06d3223cf31942a059fb861b080227100a06636f6666656510c9031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07660203462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0020000000000000000000000000000000000000000000000000000000000000000002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3370020000000000000000000000000000000000000000000000000000000000000000052022710582103d084805e2f4c2bcf5188e40e7baec8b8680a1554da028b3d4c25e8969869fbe5a0fd0192031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07660203462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b0020000000000000000000000000000000000000000000000000000000000000000002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe3370020000000000000000000000000000000000000000000000000000000000000000003ff8adab52623bcb2717fc71d7edc6f55e98396e6c234dff01f307a12b2af1c9903d793631af7aa0e709439dd47fc001acd0b0727670b6670ea528ac83cb0127f4a0202a8397a935f0dfceba6ba9618f6451ef4d80637abf4e6af2669fbc9de6a8fd2ac002000000000000000000000000000000000000000000000000000000000000000000257eb3638f51f4dc5c8d5a7324b47df99e816cfcc5b5eb1245bc8c98029f9e67400200000000000000000000000000000000000000000000000000000000000000000a23800000001000003e8002a0000000000000064000000e8d4a51000000000000001000003e8002a0000000000000064000000e8d4a510000000a40469d5f704a820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa022710b02102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337f04050faf92c0ac2aebd997ca25cee63f5b3186ef8a7e4dc977289f77130acb37894cc5fd48fb9875335f445b30359892f04954fe2b6623507aca7d403ebcc4ec938";

		// Parse the offer
		let offer = offer_str.parse::<Offer>().unwrap();
		assert_eq!(offer.issuer_signing_pubkey(), None);
		assert_eq!(offer.paths().len(), 1, "offer should have blinded paths");

		// Last blinded hop keypair (the recipient behind the blinded path)
		let secp = Secp256k1::new();
		let recipient_secret = SecretKey::from_slice(&[0x03; 32]).unwrap();
		let recipient_keys = Keypair::from_secret_key(&secp, &recipient_secret);
		assert_eq!(
			recipient_keys.public_key().to_string(),
			"02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
		);

		// Parse the invoice request
		let invoice_request_bytes = Vec::from_hex(invoice_request_hex).unwrap();
		let invoice_request = InvoiceRequest::try_from(invoice_request_bytes).unwrap();
		assert_eq!(invoice_request.issuer_signing_pubkey(), None);
		assert_eq!(invoice_request.paths().len(), 1, "offer should have blinded paths");

		// Parse the invoice
		let invoice_bytes = Vec::from_hex(invoice_hex).unwrap();
		let invoice = Bolt12Invoice::try_from(invoice_bytes).unwrap();

		assert_eq!(invoice.amount_msats(), 10_000);
		assert_eq!(invoice.payment_hash(), lightning::types::payment::PaymentHash([0xaa; 32]));

		// Validate the invoice was issued for this offer and verify its signature
		invoice.validate_issuance(&offer).unwrap();
		invoice.check_signature().unwrap();

		// Parse the other invoice
		let invoice_bytes = Vec::from_hex(other_offer_invoice_hex).unwrap();
		let invoice = Bolt12Invoice::try_from(invoice_bytes).unwrap();

		let err = invoice.validate_issuance(&offer).unwrap_err();
		assert!(err.to_string().contains("public keys mismatch"), "{:?}", err);

		// Parse the extra path invoice
		let invoice_bytes = Vec::from_hex(extra_path_invoice_hex).unwrap();
		let invoice = Bolt12Invoice::try_from(invoice_bytes).unwrap();

		// Validate the invoice was issued for this offer and verify its signature
		invoice.validate_issuance(&offer).unwrap();
		invoice.check_signature().unwrap();
	}
}
