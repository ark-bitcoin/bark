//! BIP 321 payment URI parser and serializer.
//!
//! Implements the `bitcoin:` URI scheme defined in
//! [BIP 321](https://bips.dev/321/) for encoding payment instructions in
//! clickable links and QR codes.
//!
//! # URI format
//!
//! ```text
//! bitcoin:<address>?amount=<btc>&label=<text>&message=<text>
//! ```
//!
//! The on-chain address is optional when at least one alternative payment
//! instruction is present in query parameters (e.g. `lightning=`, `lno=`,
//! `sp=`).
//!
//! # Standard payment instructions
//!
//! The following query parameters are defined in BIP 321 and handled
//! natively: `lightning` (BOLT 11), `lno` (BOLT 12), `sp` (BIP 352
//! Silent Payments), `pay` (BIP 351), and `bc`/`tb` (segwit address
//! HRPs). All of these may appear multiple times.
//!
//! # Required parameters
//!
//! Parameters prefixed with `req-` signal that a wallet **must** understand
//! them to process the URI. Unknown `req-` parameters cause parsing to fail
//! unless an [`ExtensionHandler`] claims support for them.
//!
//! # Extension mechanism
//!
//! Implement [`ExtensionHandler`] to teach the parser about parameters
//! beyond the BIP 321 standard set (e.g. `pj=` for Payjoin, or
//! wallet-specific custom params).

mod error;
mod extension;

pub use error::Bip321Error;
pub use extension::{ExtensionHandler, NoExtensions};

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};
use std::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{Address, Amount, Denomination, Network, NetworkKind};
use bitcoin_ext::AddressExt;
use lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// RFC 3986 unreserved characters that do NOT need encoding.
/// Everything else in `NON_ALPHANUMERIC` gets percent-encoded.
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~');

const REQUIRED_PREFIX: &str = "req-";

/// A value paired with the BIP 321 `req-` flag.
///
/// When [`required`](Self::required) is `true`, the parameter carries
/// mandatory semantics — a wallet that does not understand it **must**
/// reject the entire URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldWithAttributes<T: Clone> {
	field: T,
	required: bool,
}

impl<T: Clone> FieldWithAttributes<T> {
	/// Create a new field with the given value and required flag.
	pub fn new(field: T, required: bool) -> Self {
		Self { field, required }
	}

	/// Returns a reference to the wrapped value.
	pub fn inner(&self) -> &T {
		&self.field
	}

	/// Consumes self and returns the wrapped value.
	pub fn into_inner(self) -> T {
		self.field
	}

	/// Whether this parameter was marked as required (`req-` prefix).
	pub fn required(&self) -> bool {
		self.required
	}
}

/// Proof-of-Payment configuration from the `pop=` or `req-pop=` parameter.
///
/// After payment, the wallet should:
/// 1. Percent-decode the URI prefix
/// 2. Append the payment instruction key (or `"onchain"`)
/// 3. Append `=`
/// 4. Append the payment information (hex-encoded transaction or preimage)
/// 5. Open the resulting URI
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopConfig {
	uri_prefix: String,
	required: bool,
	safe: bool,
}

/// Schemes that are not safe to open from PoP URIs.
const UNSAFE_POP_SCHEMES: &[&str] = &[
	"javascript:", "http:", "https:",
	"file:", "mailto:", "ftp:", "wss:",
	"ws:", "ssh:", "tel:", "data:", "blob:",
];

impl PopConfig {
	/// Create a new PoP configuration, validating the scheme.
	pub fn new(uri_prefix: String, required: bool) -> Result<Self, Bip321Error> {
		let lower = uri_prefix.to_ascii_lowercase();

		let mut safe = true;
		for scheme in UNSAFE_POP_SCHEMES {
			if lower.starts_with(scheme) {
				safe = false;
			}
		}

		if !safe && required {
			return Err(Bip321Error::RequiredUnsafePopScheme(uri_prefix));
		}

		Ok(Self { uri_prefix, required, safe })
	}

	/// The decoded URI prefix.
	pub fn uri_prefix(&self) -> &str {
		&self.uri_prefix
	}

	/// Whether this PoP parameter was required (`req-pop`).
	pub fn required(&self) -> bool {
		self.required
	}

	/// Whether this PoP parameter is safe to open from a PoP URI.
	pub fn safe(&self) -> bool {
		self.safe
	}

	/// Build the final callback URI after a payment.
	///
	/// `source_key` is the payment method key (e.g. `"onchain"`,
	/// `"lightning"`). `payment_info` is the hex-encoded payment data.
	pub fn build_callback(&self, source_key: &str, payment_info: &str) -> String {
		format!("{}{}={}", self.uri_prefix, source_key, payment_info)
	}
}

/// A parsed BIP 321 `bitcoin:` payment URI.
///
/// Standard fields (`address`, `amount`, `label`, `message`, `pop`) and
/// standard payment instructions (`lightning`, `lno`, `sp`, `pay`, `bc`,
/// `tb`) are stored directly. Additional parameters beyond the BIP 321
/// spec are handled by the generic `E: ExtensionHandler`. Any remaining
/// unknown non-required parameters end up in [`custom`](Self::custom).
///
/// Parse via [`FromStr`] and serialize back with [`Display`](fmt::Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip321Uri<E: ExtensionHandler = NoExtensions> {
	address: Option<Address<NetworkChecked>>,
	amount: Option<Amount>,
	label: Option<String>,
	message: Option<String>,

	/// Proof-of-Payment configuration.
	pop: Option<PopConfig>,

	/// Core additional payment instructions.
	lightning: Vec<FieldWithAttributes<Bolt11Invoice>>,
	lno: Vec<FieldWithAttributes<Offer>>,
	sp: Vec<FieldWithAttributes<String>>,
	pay: Vec<FieldWithAttributes<String>>,
	bc: Vec<FieldWithAttributes<Address<NetworkChecked>>>,
	tb: Vec<FieldWithAttributes<Address<NetworkChecked>>>,

	/// Optional extension handler to support more query parameters.
	extensions: E,

	/// Query parameters that are not part of the BIP 321 standard
	/// nor handled by the extension handler.
	custom: HashMap<String, Vec<FieldWithAttributes<String>>>,
}

impl<E: ExtensionHandler> Bip321Uri<E> {
	/// Create an empty URI. Call setters and then [`validate`](Self::validate).
	pub fn new() -> Self {
		Self {
			address: None,
			amount: None,
			label: None,
			message: None,

			pop: None,

			lightning: Vec::new(),
			lno: Vec::new(),
			sp: Vec::new(),
			pay: Vec::new(),
			bc: Vec::new(),
			tb: Vec::new(),

			extensions: E::default(),

			custom: HashMap::new(),
		}
	}

	/// Get the on-chain address set in the URI.
	pub fn address(&self) -> Option<&Address<NetworkChecked>> {
		self.address.as_ref()
	}

	/// Set the on-chain address in the URI.
	pub fn set_address(&mut self, address: Address<NetworkUnchecked>) -> Result<(), Bip321Error> {
		let address = address.require_network(Network::Bitcoin)
			.map_err(|_| Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main })?;
		self.address = Some(address);
		Ok(())
	}

	/// Get the amount set in the URI.
	pub fn amount(&self) -> Option<&Amount> {
		self.amount.as_ref()
	}

	/// Set the amount in the URI.
	pub fn set_amount(&mut self, amount: Amount) -> Result<(), Bip321Error> {
		if amount == Amount::ZERO {
			return Err(Bip321Error::AmountZero);
		}
		self.amount = Some(amount);
		Ok(())
	}

	/// Get the label set in the URI.
	pub fn label(&self) -> Option<&String> {
		self.label.as_ref()
	}

	/// Set the label in the URI.
	pub fn set_label(&mut self, label: String) {
		self.label = Some(label);
	}

	/// Get the message set in the URI.
	pub fn message(&self) -> Option<&String> {
		self.message.as_ref()
	}

	/// Set the message in the URI.
	pub fn set_message(&mut self, message: String) {
		self.message = Some(message);
	}

	/// Get the PoP configuration set in the URI.
	pub fn pop(&self) -> Option<&PopConfig> {
		self.pop.as_ref()
	}

	/// Set the PoP configuration in the URI.
	pub fn set_pop(&mut self, pop: PopConfig) {
		self.pop = Some(pop);
	}

	/// Get the Lightning invoices set in the URI.
	pub fn lightning(&self) -> &[FieldWithAttributes<Bolt11Invoice>] {
		&self.lightning
	}

	/// Push a Lightning invoice to the URI.
	pub fn push_lightning(&mut self, invoice: Bolt11Invoice, required: bool) {
		self.lightning.push(FieldWithAttributes::new(invoice, required));
	}

	/// Clear the Lightning invoices from the URI.
	pub fn clear_lightning(&mut self) {
		self.lightning.clear();
	}

	/// Get the LNO offers set in the URI.
	pub fn lno(&self) -> &[FieldWithAttributes<Offer>] {
		&self.lno
	}

	/// Push a Lightning offer to the URI.
	pub fn push_lno(&mut self, offer: Offer, required: bool) {
		self.lno.push(FieldWithAttributes::new(offer, required));
	}

	/// Clear the Lightning offers from the URI.
	pub fn clear_lno(&mut self) {
		self.lno.clear();
	}

	/// Get the Silent Payments set in the URI.
	pub fn sp(&self) -> &[FieldWithAttributes<String>] {
		&self.sp
	}

	/// Push a Silent Payment to the URI.
	pub fn push_sp(&mut self, sp: String, required: bool) {
		self.sp.push(FieldWithAttributes::new(sp, required));
	}

	/// Clear the Silent Payments from the URI.
	pub fn clear_sp(&mut self) {
		self.sp.clear();
	}

	/// Get the bip351 private payment instructions set in the URI.
	pub fn pay(&self) -> &[FieldWithAttributes<String>] {
		&self.pay
	}

	/// Push a bip351 private payment instruction to the URI.
	pub fn push_pay(&mut self, pay: String, required: bool) {
		self.pay.push(FieldWithAttributes::new(pay, required));
	}

	/// Clear the bip351 private payment instructions from the URI.
	pub fn clear_pay(&mut self) {
		self.pay.clear();
	}

	/// Get the mainnet bitcoin addresses set in the URI.
	pub fn bc(&self) -> &[FieldWithAttributes<Address<NetworkChecked>>] {
		&self.bc
	}

	/// Push a mainnet bitcoin address to the URI.
	pub fn push_bc(&mut self, bc: Address<NetworkUnchecked>, required: bool) -> Result<(), Bip321Error> {
		if !bc.is_valid_for_network(Network::Bitcoin) {
			return Err(Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main });
		}
		self.bc.push(FieldWithAttributes::new(bc.assume_checked(), required));
		Ok(())
	}

	/// Clear the mainnet bitcoin addresses from the URI.
	pub fn clear_bc(&mut self) {
		self.bc.clear();
	}

	/// Get the test bitcoin addresses set in the URI.
	pub fn tb(&self) -> &[FieldWithAttributes<Address<NetworkChecked>>] {
		&self.tb
	}

	/// Push a test bitcoin address to the URI.
	pub fn push_tb(&mut self, tb: Address<NetworkUnchecked>, required: bool) -> Result<(), Bip321Error> {
		if tb.is_valid_for_network(Network::Bitcoin) {
			return Err(Bip321Error::NetworkKindMismatch { expected: NetworkKind::Test });
		}
		self.tb.push(FieldWithAttributes::new(tb.assume_checked(), required));
		Ok(())
	}

	/// Clear the test bitcoin addresses from the URI.
	pub fn clear_tb(&mut self) {
		self.tb.clear();
	}

	/// Get the extension handler set in the URI.
	pub fn extensions(&self) -> &E {
		&self.extensions
	}

	/// Get a mutable reference to the extension handler set in the URI.
	pub fn extensions_mut(&mut self) -> &mut E {
		&mut self.extensions
	}

	/// Get the custom parameters set in the URI.
	pub fn custom(&self) -> &HashMap<String, Vec<FieldWithAttributes<String>>> {
		&self.custom
	}

	/// Whether any standard payment instruction is present.
	pub fn has_payment_instruction(&self) -> bool {
		!self.lightning.is_empty()
			|| !self.lno.is_empty()
			|| !self.sp.is_empty()
			|| !self.pay.is_empty()
			|| !self.bc.is_empty()
			|| !self.tb.is_empty()
	}

	/// Enforce BIP 321 invariants:
	/// - At least one payment destination (address, payment instruction,
	///   or extension) must exist.
	pub fn validate(&self) -> Result<(), Bip321Error> {
		if self.address.is_none()
			&& !self.has_payment_instruction()
			&& self.extensions.is_empty()
		{
			return Err(Bip321Error::NoPaymentDestination);
		}
		Ok(())
	}
}

impl<E: ExtensionHandler> Default for Bip321Uri<E> {
	fn default() -> Self {
		Self::new()
	}
}

/// Case-insensitive prefix strip.
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
	if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
		Some(&s[prefix.len()..])
	} else {
		None
	}
}

/// Percent-decode a query parameter value to a String.
fn percent_decode(value: &str) -> Result<String, Bip321Error> {
	let decoded = percent_decode_str(value)
		.decode_utf8()
		.map_err(|e| Bip321Error::Utf8Error(e))?;
	Ok(decoded.into_owned())
}

impl<E: ExtensionHandler> FromStr for Bip321Uri<E> {
	type Err = Bip321Error;

	fn from_str(input: &str) -> Result<Self, Self::Err> {
		let input = input.trim();
		const SCHEME: &str = "bitcoin:";

		if input.len() < SCHEME.len() {
			return Err(Bip321Error::TooShort);
		}
		if !input[..SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
			return Err(Bip321Error::InvalidScheme);
		}

		let body = &input[SCHEME.len()..];
		let (address_str, query_str) = {
			let mut split = body.splitn(2, '?');
			(split.next().unwrap(), split.next())
		};

		let mut uri = Bip321Uri::<E>::new();

		if !address_str.is_empty() {
			let addr = Address::from_str(address_str)
				.map_err(|_| Bip321Error::InvalidAddress(address_str.to_string()))?;
			let addr = addr.require_network(Network::Bitcoin)
				.map_err(|_| Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main })?;
			uri.address = Some(addr);
		}

		if let Some(qs) = query_str {
			if !qs.is_empty() {
				// Track seen singleton keys for duplicate detection
				let mut seen_keys = HashSet::new();

				for param in qs.split('&') {
					if param.is_empty() {
						continue;
					}

					let (raw_key, raw_value) = {
						let mut split = param.splitn(2, '=');
						let key = split.next()
							.ok_or_else(|| Bip321Error::MalformedParam(param.to_string()))?;
						let value = split.next()
							.ok_or_else(|| Bip321Error::MalformedParam(param.to_string()))?;
						(key, value)
					};

					// Determine if req- prefixed, and get the base key
					let (required, base_key) =
						match strip_prefix_ignore_case(raw_key, REQUIRED_PREFIX) {
							Some(stripped) => (true, stripped),
							None => (false, raw_key),
						};

					let base_key_lower = base_key.to_ascii_lowercase();

					// NB: the req- prefix is intentionally not stored for
					// amount, label, and message. Every BIP 321 parser must
					// understand these fields, so req- carries no additional
					// semantics for them.
					match base_key_lower {
						key if key == "amount" => {
							if !seen_keys.insert(key) {
								return Err(Bip321Error::DuplicateParam("amount".into()));
							}

							if raw_value.contains(',') {
								return Err(Bip321Error::MalformedParam(param.to_string()));
							}
							let amount = Amount::from_str_in(raw_value, Denomination::Bitcoin)
								.map_err(|_| {
									Bip321Error::MalformedParam(param.to_string())
								})?;
							if amount == Amount::ZERO {
								return Err(Bip321Error::AmountZero);
							}
							uri.amount = Some(amount);
						}
						key if key == "label" => {
							if !seen_keys.insert(key) {
								return Err(Bip321Error::DuplicateParam("label".into()));
							}

							let decoded = percent_decode(raw_value)?;
							uri.label = Some(decoded);
						}
						key if key == "message" => {
							if !seen_keys.insert(key) {
								return Err(Bip321Error::DuplicateParam("message".into()));
							}

							let decoded = percent_decode(raw_value)?;
							uri.message = Some(decoded);
						}
						key if key == "pop" => {
							if !seen_keys.insert(key) {
								return Err(Bip321Error::DuplicateParam("pop".into()));
							}

							let decoded = percent_decode(raw_value)?;
							let pop = PopConfig::new(decoded, required)?;
							uri.pop = Some(pop);
						}
						// Standard payment instructions (may appear multiple times)
						key if key == "lightning" => {
							let invoice = Bolt11Invoice::from_str(&raw_value)
								.map_err(|e| Bip321Error::PaymentInstructionParseError {
									key: key.to_string(), error: e.to_string(),
								})?;
							uri.lightning.push(FieldWithAttributes::new(invoice, required));
						}
						key if key == "lno" => {
							let offer = Offer::from_str(&raw_value)
								.map_err(|e| Bip321Error::PaymentInstructionParseError {
									key: key.to_string(), error: format!("{:?}", e),
								})?;
							uri.lno.push(FieldWithAttributes::new(offer, required));
						}
						key if key == "sp" => {
							uri.sp.push(FieldWithAttributes::new(raw_value.to_string(), required));
						}
						key if key == "pay" => {
							uri.pay.push(FieldWithAttributes::new(raw_value.to_string(), required));
						}
						key if key == "bc" => {
							let address = Address::from_str(&raw_value)
								.map_err(|e| Bip321Error::PaymentInstructionParseError {
									key: key.to_string(), error: e.to_string(),
								})?;
							let address = address.require_network(Network::Bitcoin)
								.map_err(|_| Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main })?;
							uri.bc.push(FieldWithAttributes::new(address, required));
						}
						key if key == "tb" => {
							let address = Address::from_str(&raw_value)
								.map_err(|e| Bip321Error::PaymentInstructionParseError {
									key: key.to_string(), error: e.to_string(),
								})?;
							if address.is_valid_for_network(Network::Bitcoin) {
								return Err(Bip321Error::NetworkKindMismatch { expected: NetworkKind::Test });
							}
							uri.tb.push(FieldWithAttributes::new(
								address.assume_checked(), required,
							));
						}
						_ => {
							// Try the extension handler first
							let decoded = percent_decode(raw_value)?;
							let handled = uri.extensions.handle_param(
								&base_key_lower,
								&decoded,
								required,
							)?;

							if !handled {
								// Unknown parameter
								if required {
									return Err(Bip321Error::UnsupportedRequiredParam(
										base_key_lower.clone(),
									));
								}
								// Store as custom (unknown non-required params)
								uri.custom.entry(base_key_lower.clone()).or_insert_with(Vec::new).push(
									FieldWithAttributes::new(decoded, false),
								);
							}
						}
					}
				}
			}
		}

		// ── Validate: must have at least one payment destination ─────
		if uri.address.is_none()
			&& !uri.has_payment_instruction()
			&& uri.extensions.is_empty()
		{
			return Err(Bip321Error::NoPaymentDestination);
		}

		Ok(uri)
	}
}

fn write_query_param(f: &mut String, key: &str, value: &str, required: bool) -> fmt::Result {
	let separator = if f.is_empty() { "" } else { "&" };
	let required_prefix = if required { "req-" } else { "" };
	write!(f, "{}{}{}", separator, required_prefix, key)?;
	write!(f, "={}", utf8_percent_encode(value, QUERY_ENCODE_SET))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("uri is not fully uppercasable")]
pub struct NotUppercasable;

impl<E: ExtensionHandler> Bip321Uri<E> {
	/// Whether every component of the URI is case-insensitive, so the whole
	/// string can be upper-cased without changing its meaning. This is false
	/// when the URI carries human-readable text (`label`, `message`), a
	/// case-sensitive `pop` prefix or custom parameter, or a base58
	/// (P2PKH/P2SH) address.
	fn is_fully_uppercasable(&self) -> bool {
		self.label.is_none()
			&& self.message.is_none()
			&& self.pop.is_none()
			&& self.custom.is_empty()
			&& self.address.as_ref().map_or(true, |a| a.is_uppercasable())
			&& self.bc.iter().all(|f| f.inner().is_uppercasable())
			&& self.tb.iter().all(|f| f.inner().is_uppercasable())
	}

	/// Serializes the URI as an all-uppercase `bitcoin:` URI string.
	///
	/// Only possible if the URI contains exclusively case-insensitive (bech32, etc.) components
	/// such that converting to uppercase will not change the meaning.
	///
	/// Returns [`None`] if the URI contains any case-sensitive components (see
	/// [`is_fully_uppercasable`](Self::is_fully_uppercasable)), since uppercasing would change
	/// the semantics. In that case, callers may fall back to [`Display`](Self::to_string).
	pub fn checked_uppercase(&self) -> Option<String> {
		if self.is_fully_uppercasable() {
			Some(self.to_string().to_uppercase())
		} else {
			None
		}
	}
}

impl<E: ExtensionHandler> fmt::Display for Bip321Uri<E> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "bitcoin:")?;

		if let Some(addr) = &self.address {
			write!(f, "{}", addr)?;
		}

		let mut query_buf = String::new();

		// amount
		if let Some(amount_field) = &self.amount {
			let value = amount_field.to_string_in(Denomination::Bitcoin);
			write_query_param(&mut query_buf, "amount", &value, false)?;
		}

		// label
		if let Some(label) = &self.label {
			write_query_param(&mut query_buf, "label", label, false)?;
		}

		// message
		if let Some(message) = &self.message {
			write_query_param(&mut query_buf, "message", message, false)?;
		}

		// pop
		if let Some(pop) = &self.pop {
			write_query_param(&mut query_buf, "pop", &pop.uri_prefix, pop.required())?;
		}

		// standard payment instructions
		for field in &self.lightning {
			write_query_param(&mut query_buf, "lightning", &field.inner().to_string(), field.required())?;
		}
		for field in &self.lno {
			write_query_param(&mut query_buf, "lno", &field.inner().to_string(), field.required())?;
		}
		for field in &self.sp {
			write_query_param(&mut query_buf, "sp", &field.inner(), field.required())?;
		}
		for field in &self.pay {
			write_query_param(&mut query_buf, "pay", &field.inner(), field.required())?;
		}
		for field in &self.bc {
			write_query_param(&mut query_buf, "bc", &field.inner().to_string(), field.required())?;
		}
		for field in &self.tb {
			write_query_param(&mut query_buf, "tb", &field.inner().to_string(), field.required())?;
		}

		// extension parameters
		for (key, value) in self.extensions.serialize_params() {
			write_query_param(&mut query_buf, &key, &value, false)?;
		}

		// custom parameters (sorted for determinism)
		let mut custom_sorted: Vec<_> = self.custom.iter().collect();
		custom_sorted.sort_by_key(|(k, _)| (*k).clone());
		for (key, values) in custom_sorted {
			let mut values_sorted = values.clone();
			values_sorted.sort_by_key(|v| v.inner().clone());
			for val_field in values_sorted.iter() {
				write_query_param(&mut query_buf, &key, &val_field.inner(), val_field.required())?;
			}
		}

		if !query_buf.is_empty() {
			write!(f, "?{}", query_buf)?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse_no_ext(s: &str) -> Result<Bip321Uri<NoExtensions>, Bip321Error> {
		Bip321Uri::<NoExtensions>::from_str(s)
	}

	#[test]
	fn just_address() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
		assert!(uri.address.is_some());
		assert!(uri.amount.is_none());
		assert!(uri.label.is_none());
		assert!(uri.message.is_none());
		assert!(uri.pop.is_none());
	}

	#[test]
	fn address_with_label() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr")
		.unwrap();
		assert_eq!(uri.label().unwrap(), "Luke-Jr");
	}

	#[test]
	fn address_with_amount_and_label() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=20.3&label=Luke-Jr")
		.unwrap();
		assert_eq!(
			uri.amount().unwrap(),
			&Amount::from_btc(20.3).unwrap()
		);
		assert_eq!(uri.label().unwrap(), "Luke-Jr");
	}

	#[test]
	fn address_with_amount_label_message() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz")
		.unwrap();
		assert_eq!(
			uri.amount().unwrap(),
			&Amount::from_btc(50.0).unwrap()
		);
		assert_eq!(uri.label().unwrap(), "Luke-Jr");
		assert_eq!(uri.message().unwrap(), "Donation for project xyz");
	}

	#[test]
	fn amount_integer() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50").unwrap();
		assert_eq!(
			uri.amount().unwrap(),
			&Amount::from_btc(50.0).unwrap()
		);
	}

	#[test]
	fn amount_decimal() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=50.00").unwrap();
		assert_eq!(
			uri.amount().unwrap(),
			&Amount::from_btc(50.0).unwrap()
		);
	}

	#[test]
	fn uppercase_scheme() {
		let uri = parse_no_ext("BITCOIN:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
		assert!(uri.address.is_some());
	}

	#[test]
	fn mixed_case_scheme() {
		let uri = parse_no_ext("BiTcOiN:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
		assert!(uri.address.is_some());
	}

	#[test]
	fn unknown_required_param_rejected() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-somethingyoudontunderstand=50")
		.unwrap_err();
		assert_eq!(
			err,
			Bip321Error::UnsupportedRequiredParam("somethingyoudontunderstand".into())
		);
	}

	#[test]
	fn unknown_non_required_param_accepted() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?somethingyoudontunderstand=50&somethingelseyoudontget=999")
		.unwrap();
		assert_eq!(
			uri.custom
				.get("somethingyoudontunderstand")
				.unwrap(),
			&[FieldWithAttributes::new("50".to_string(), false)]
		);
		assert_eq!(
			uri.custom
				.get("somethingelseyoudontget")
				.unwrap(),
			&[FieldWithAttributes::new("999".to_string(), false)]
		);
	}

	#[test]
	fn unknown_multiple_params_accepted() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?somethingyoudontunderstand=50&somethingyoudontunderstand=60")
		.unwrap();
		assert_eq!(
			uri.custom
				.get("somethingyoudontunderstand")
				.unwrap(),
			&[
				FieldWithAttributes::new("50".to_string(), false),
				FieldWithAttributes::new("60".to_string(), false),
			]
		);
	}

	#[test]
	fn reject_duplicate_label() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr&label=Matt")
		.unwrap_err();
		assert_eq!(err, Bip321Error::DuplicateParam("label".into()));
	}

	#[test]
	fn reject_duplicate_amount() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=42&amount=10")
		.unwrap_err();
		assert_eq!(err, Bip321Error::DuplicateParam("amount".into()));
	}

	#[test]
	fn reject_duplicate_message() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?message=hello&message=world")
		.unwrap_err();
		assert_eq!(err, Bip321Error::DuplicateParam("message".into()));
	}

	#[test]
	fn reject_duplicate_pop() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=myapp%3a&pop=otherapp%3a")
		.unwrap_err();
		assert_eq!(err, Bip321Error::DuplicateParam("pop".into()));
	}

	#[test]
	fn reject_zero_amount() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0").unwrap_err();
		assert_eq!(err, Bip321Error::AmountZero);
	}

	#[test]
	fn reject_comma_in_amount() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1,000").unwrap_err();
		assert_eq!(err, Bip321Error::MalformedParam("amount=1,000".to_string()));
	}

	#[test]
	fn reject_empty_uri() {
		let err = parse_no_ext("bitcoin:").unwrap_err();
		assert_eq!(err, Bip321Error::NoPaymentDestination);
	}

	#[test]
	fn reject_empty_uri_with_trailing_question() {
		let err = parse_no_ext("bitcoin:?").unwrap_err();
		assert_eq!(err, Bip321Error::NoPaymentDestination);
	}

	#[test]
	fn reject_wrong_scheme() {
		let err = parse_no_ext("litecoin:addr123").unwrap_err();
		assert_eq!(err, Bip321Error::InvalidScheme);
	}

	#[test]
	fn reject_too_short() {
		let err = parse_no_ext("bit").unwrap_err();
		assert_eq!(err, Bip321Error::TooShort);
	}

	#[test]
	fn pop_basic() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=initiatingapp%3A")
		.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "initiatingapp:");
		assert!(!pop.required());
	}

	#[test]
	fn pop_required() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-pop=initiatingapp%3A")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "initiatingapp:");
		assert!(pop.required());
		assert!(pop.safe());
	}

	#[test]
	fn pop_forbidden_http() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=http%3A%2F%2Fevil.com")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "http://evil.com");
		assert!(!pop.required());
		assert!(!pop.safe());
	}

	#[test]
	fn pop_forbidden_https() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=https%3A%2F%2Fevil.com")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "https://evil.com");
		assert!(!pop.required());
		assert!(!pop.safe());
	}

	#[test]
	fn pop_forbidden_javascript() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=javascript%3Aalert(1)")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "javascript:alert(1)");
		assert!(!pop.required());
		assert!(!pop.safe());
	}

	#[test]
	fn pop_forbidden_file() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=file%3Aalert(1)")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "file:alert(1)");
		assert!(!pop.required());
		assert!(!pop.safe());
	}

	#[test]
	fn pop_forbidden_mailto() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=mailto%3Aalert(1)")
			.unwrap();
		let pop = uri.pop().unwrap();
		assert_eq!(pop.uri_prefix(), "mailto:alert(1)");
		assert!(!pop.required());
		assert!(!pop.safe());
	}

	#[test]
	fn reject_required_unsafe_pop() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-pop=javascript%3Aalert(1)")
			.unwrap_err();
		assert_eq!(err, Bip321Error::RequiredUnsafePopScheme("javascript:alert(1)".into()));
	}

	#[test]
	fn pop_callback_build() {
		let pop = PopConfig::new("initiatingapp:".to_string(), false).unwrap();
		let callback = pop.build_callback("onchain", "deadbeef");
		assert_eq!(callback, "initiatingapp:onchain=deadbeef");
	}

	#[test]
	fn label_with_spaces_and_special_chars() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=caf%C3%A9%20%26%20more%20%3D%20fun")
		.unwrap();
		assert_eq!(uri.label().unwrap(), "café & more = fun");
	}

	#[test]
	fn message_with_unicode() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?message=%E4%B8%96%E7%95%8C")
		.unwrap();
		assert_eq!(uri.message().unwrap(), "世界");
	}

	#[test]
	fn value_containing_equals() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=hello=world")
		.unwrap();
		assert_eq!(uri.label().unwrap(), "hello=world");
	}

	#[test]
	fn empty_value() {
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=").unwrap();
		assert_eq!(uri.label().unwrap(), "");
	}

	#[test]
	fn param_without_equals_is_malformed() {
		let err = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?foo").unwrap_err();
		assert!(matches!(err, Bip321Error::MalformedParam(_)));
	}

	#[test]
	fn bech32_address() {
		let uri = parse_no_ext("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap();
		assert!(uri.address.is_some());
	}

	#[test]
	fn roundtrip_address_only() {
		let parsed = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
		let serialized = parsed.to_string();
		let reparsed = parse_no_ext(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}

	#[test]
	fn roundtrip_with_amount_label_message() {
		let parsed = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1.5&label=Test%20Label&message=Hello%20World").unwrap();
		let serialized = parsed.to_string();
		let reparsed = parse_no_ext(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}

	#[test]
	fn roundtrip_with_special_chars_in_label() {
		let parsed = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=caf%C3%A9%20%26%20more%20%3D%20fun").unwrap();
		let serialized = parsed.to_string();
		let reparsed = parse_no_ext(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}

	#[test]
	fn roundtrip_with_pop() {
		let parsed = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pop=initiatingapp%3A").unwrap();
		let serialized = parsed.to_string();
		let reparsed = parse_no_ext(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}

	#[test]
	fn builder_basic() {
		let mut uri = Bip321Uri::<NoExtensions>::new();
		let addr = Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
		uri.set_address(addr).unwrap();
		uri.set_amount(Amount::from_btc(1.0).unwrap()).unwrap();
		uri.set_label("Test".to_string());
		uri.validate().unwrap();

		let s = uri.to_string();
		assert!(s.starts_with("bitcoin:"));
		assert!(s.contains("amount=1"));
		assert!(s.contains("label=Test"));
	}

	#[test]
	fn builder_reject_zero_amount() {
		let mut uri = Bip321Uri::<NoExtensions>::new();
		let err = uri.set_amount(Amount::ZERO).unwrap_err();
		assert_eq!(err, Bip321Error::AmountZero);
	}

	#[test]
	fn builder_reject_no_destination() {
		let uri = Bip321Uri::<NoExtensions>::new();
		let err = uri.validate().unwrap_err();
		assert_eq!(err, Bip321Error::NoPaymentDestination);
	}

	fn parse(s: &str) -> Result<Bip321Uri, Bip321Error> {
		Bip321Uri::from_str(s)
	}

	// ── Payment instruction tests ───────────────────────────────────

	#[test]
	fn lightning_with_fallback() {
		let input = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc";
		let uri = parse(&input).unwrap();
		assert!(uri.address.is_some());
		assert_eq!(uri.lightning().len(), 1);
	}

	#[test]
	fn bc_only() {
		let input = "bitcoin:?bc=bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
		let uri = parse(&input).unwrap();
		assert!(uri.address.is_none());
		assert_eq!(uri.bc().len(), 1);
	}

	#[test]
	fn tb_only() {
		let input = "bitcoin:?tb=tb1qghfhmd4zh7ncpmxl3qzhmq566jk8ckq4gafnmg";
		let uri = parse(&input).unwrap();
		assert!(uri.address.is_none());
		assert_eq!(uri.tb().len(), 1);
	}

	#[test]
	fn lno_only() {
		let input = "bitcoin:?lno=lno1pqpzwyq2qe3k7enxv4j3pjgrrwzv24nmzfjypx2a8m264ws9vht3uxp5vpypnluuzl67n4waq78syn2tdngnvypje2da9t4emyq25n29m84dszkfggehf3z35uj56pmxqgp5vfme44926w23gc282xn3pp0j7y8pc7je8e8qxrhmtwrjrnj4kzcqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjnrlnqdqf52q7jwgcnxgnuseav37nvs0zn06dyfs79hk7uk8lrxuqzqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
		let uri = parse(&input).unwrap();
		assert!(uri.address.is_none());
		assert_eq!(uri.lno().len(), 1);
	}

	#[test]
	fn sp_only() {
		let input = "bitcoin:?sp=sp1qsilentpayment";
		let uri = parse(input).unwrap();
		assert!(uri.address.is_none());
		assert_eq!(uri.sp()[0].inner(), "sp1qsilentpayment");
	}

	#[test]
	fn pay_only() {
		let input = "bitcoin:?pay=paynym1abc";
		let uri = parse(input).unwrap();
		assert!(uri.address.is_none());
		assert_eq!(uri.pay()[0].inner(), "paynym1abc");
	}

	#[test]
	fn required_lightning_accepted() {
		let input = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc";
		let uri = parse(&input).unwrap();
		assert_eq!(uri.lightning().len(), 1);
		assert!(uri.lightning()[0].required());
	}

	#[test]
	fn lightning_roundtrip() {
		let input = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc&lno=lno1pqpzwyq2qe3k7enxv4j3pjgrrwzv24nmzfjypx2a8m264ws9vht3uxp5vpypnluuzl67n4waq78syn2tdngnvypje2da9t4emyq25n29m84dszkfggehf3z35uj56pmxqgp5vfme44926w23gc282xn3pp0j7y8pc7je8e8qxrhmtwrjrnj4kzcqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqjnrlnqdqf52q7jwgcnxgnuseav37nvs0zn06dyfs79hk7uk8lrxuqzqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
		let parsed = parse(&input).unwrap();
		let serialized = parsed.to_string();
		let reparsed = parse(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}

	#[test]
	fn multiple_sp_params() {
		let input = "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?sp=sp1first&sp=sp1second";
		let uri = parse(input).unwrap();
		assert_eq!(uri.sp().len(), 2);
		assert_eq!(uri.sp()[0].inner(), "sp1first");
		assert_eq!(uri.sp()[1].inner(), "sp1second");
	}

	// ── Network validation ──────────────────────────────────────────

	#[test]
	fn reject_testnet_address_in_body() {
		let err = parse_no_ext("bitcoin:tb1qghfhmd4zh7ncpmxl3qzhmq566jk8ckq4gafnmg")
			.unwrap_err();
		assert_eq!(err, Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main });
	}

	#[test]
	fn reject_malformed_lightning_invoice() {
		let err = parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?lightning=notaninvoice").unwrap_err();
		assert!(matches!(err, Bip321Error::PaymentInstructionParseError { .. }));
	}

	#[test]
	fn reject_malformed_lno_offer() {
		let err = parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?lno=notanoffer").unwrap_err();
		assert!(matches!(err, Bip321Error::PaymentInstructionParseError { .. }));
	}

	#[test]
	fn reject_testnet_address_in_bc() {
		let err = parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?bc=tb1qghfhmd4zh7ncpmxl3qzhmq566jk8ckq4gafnmg").unwrap_err();
		assert_eq!(err, Bip321Error::NetworkKindMismatch { expected: NetworkKind::Main });
	}

	#[test]
	fn reject_mainnet_address_in_tb() {
		let err = parse("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?tb=bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").unwrap_err();
		assert_eq!(err, Bip321Error::NetworkKindMismatch { expected: NetworkKind::Test });
	}

	// ── Uppercase rendering ──────────────────────────────────────────

	#[test]
	fn uppercase_segwit_address_and_amount() {
		let uri = parse_no_ext("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=1.5").unwrap();
		let up = uri.checked_uppercase().unwrap();
		assert_eq!(
			up,
			"BITCOIN:BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ?AMOUNT=1.5",
		);
		// upper-cased URI must parse back to an equal URI
		assert_eq!(parse_no_ext(&up).unwrap(), uri);
	}

	#[test]
	fn uppercase_errors_for_base58_address() {
		// base58 addresses are case-sensitive, so the URI can't be upper-cased.
		let uri = parse_no_ext("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1").unwrap();
		assert!(uri.checked_uppercase().is_none());
	}

	#[test]
	fn uppercase_errors_with_label_and_message() {
		// human-readable text can't be upper-cased without changing it.
		let uri = parse_no_ext(
			"bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?label=Coffee%20Order&message=Thanks",
		).unwrap();
		assert!(uri.checked_uppercase().is_none());
	}

	#[test]
	fn uppercase_lightning_roundtrips() {
		let input = "bitcoin:?lightning=lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc";
		let uri = parse(input).unwrap();
		let up = uri.checked_uppercase().unwrap();
		assert!(up.starts_with("BITCOIN:?LIGHTNING=LNBC"), "{}", up);
		assert_eq!(parse(&up).unwrap(), uri);
	}
}
