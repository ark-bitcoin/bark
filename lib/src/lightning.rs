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
use bitcoin::secp256k1::{Message, PublicKey};
use bitcoin::taproot::TaprootSpendInfo;
use lightning::offers::parse::Bolt12ParseError;
use lightning::util::ser::Writeable;

use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight, P2TR_DUST};

use crate::{musig, scripts, SECP};

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

	/// Hashes the preimage into the payment hash
	pub fn compute_payment_hash(&self) -> PaymentHash {
		sha256::Hash::hash(self.as_ref()).into()
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
	/// Converts this PaymentHash into a `bitcoin::hashes::sha256::Hash`.
	pub fn to_sha256_hash(&self) -> bitcoin::hashes::sha256::Hash {
		bitcoin::hashes::sha256::Hash::from_slice(&self.0)
			.expect("PaymentHash must be 32 bytes, which is always valid for sha256::Hash")
	}
}

/// Construct taproot spending information for a VTXO that enables outgoing
/// Lightning payments. This relates to the [crate::VtxoPolicy::ServerHtlcSend]
/// policy.
///
/// This will build a taproot with 3 clauses:
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
	exit_delta: BlockDelta,
	htlc_expiry: BlockHeight,
) -> TaprootSpendInfo {
	let server_branch = scripts::hash_delay_sign(
		payment_hash.to_sha256_hash(), exit_delta, server_pubkey.x_only_public_key().0,
	);
	let user_branch = scripts::delay_timelock_sign(
		2 * exit_delta, htlc_expiry, user_pubkey.x_only_public_key().0,
	);

	let combined_pk = musig::combine_keys([user_pubkey, server_pubkey]);
	bitcoin::taproot::TaprootBuilder::new()
		.add_leaf(1, server_branch).unwrap()
		.add_leaf(1, user_branch).unwrap()
		.finalize(&SECP, combined_pk).unwrap()
}

/// Construct taproot spending information for a VTXO that enables incoming
/// Lightning payments. This relates to the [crate::VtxoPolicy::ServerHtlcRecv]
/// policy.
///
/// This will build a taproot with 3 clauses:
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
	exit_delta: BlockDelta,
	htlc_expiry_delta: BlockDelta,
	htlc_expiry: BlockHeight,
) -> TaprootSpendInfo {
	let server_branch =
		scripts::delay_timelock_sign(exit_delta, htlc_expiry, server_pubkey.x_only_public_key().0);
	let user_branch = scripts::hash_delay_sign(
		payment_hash.to_sha256_hash(),
		exit_delta + htlc_expiry_delta,
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

	/// See [get_invoice_final_amount] for more details.
	pub fn get_final_amount(&self, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
		match self {
			Invoice::Bolt11(invoice) => invoice.get_final_amount(user_amount),
			Invoice::Bolt12(invoice) => invoice.get_final_amount(user_amount),
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
fn get_invoice_final_amount(invoice_amount: Option<Amount>, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
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
pub trait Bolt11InvoiceExt: Borrow<Bolt11Invoice> {
	/// See [get_invoice_final_amount] for more details.
	fn get_final_amount(&self, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
		let invoice_amount = self.borrow().amount_milli_satoshis()
			.map(Amount::from_msat_ceil);

		get_invoice_final_amount(invoice_amount, user_amount)
	}
}

impl Bolt11InvoiceExt for Bolt11Invoice {}

pub trait Bolt12InvoiceExt: Borrow<Bolt12Invoice> {
	fn payment_hash(&self) -> PaymentHash { PaymentHash::from(self.borrow().payment_hash()) }

	/// See [get_invoice_final_amount] for more details.
	fn get_final_amount(&self, user_amount: Option<Amount>) -> Result<Amount, CheckAmountError> {
		let invoice_amount = Amount::from_msat_ceil(self.borrow().amount_msats());
		get_invoice_final_amount(Some(invoice_amount), user_amount)
	}

	fn check_signature(&self) -> Result<(), CheckSignatureError> {
		let message = Message::from_digest(self.borrow().signable_hash());
		let signature = self.borrow().signature();

		if let Some(pubkey) = self.borrow().issuer_signing_pubkey() {
			Ok(SECP.verify_schnorr(&signature, &message, &pubkey.into())
				.map_err(|_| CheckSignatureError("invalid signature".to_string()))?)
		} else {
			Err(CheckSignatureError("no pubkey on offer, cannot verify signature".to_string()))
		}
	}

	fn bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::new();
		self.borrow().write(&mut bytes).expect("Writing into a Vec is infallible");
		bytes
	}

	fn from_bytes(bytes: &[u8]) -> Result<Bolt12Invoice, Bolt12ParseError> {
		Bolt12Invoice::try_from(bytes.to_vec())
	}

	fn validate_issuance(&self, offer: Offer) -> Result<(), CheckSignatureError> {
		if self.borrow().issuer_signing_pubkey() != offer.issuer_signing_pubkey() {
			Err(CheckSignatureError("public keys mismatch".to_string()))
		} else {
			Ok(())
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
