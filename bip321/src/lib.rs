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

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

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
