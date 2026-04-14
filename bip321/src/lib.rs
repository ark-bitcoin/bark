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
use std::fmt;
use std::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{Address, Amount, Denomination, Network, NetworkKind};
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

/// Percent-encode a string for use as a query parameter value.
fn percent_encode(value: &str) -> String {
	utf8_percent_encode(value, QUERY_ENCODE_SET).to_string()
}

/// Write a parameter key with optional `req-` prefix.
fn param_key(base: &str, required: bool) -> String {
	if required {
		format!("{}{}", REQUIRED_PREFIX, base)
	} else {
		base.to_string()
	}
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
