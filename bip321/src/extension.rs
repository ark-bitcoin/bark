use std::fmt;

use crate::Bip321Error;

/// Trait for handling query parameters beyond the standard BIP 321 set.
///
/// The core parser already handles `amount`, `label`, `message`, `pop`,
/// `lightning`, `lno`, `sp`, `pay`, `bc`, and `tb`. Implement this trait
/// to add support for additional parameters (e.g. `pj=` for Payjoin, or
/// wallet-specific custom params).
pub trait ExtensionHandler: Default + Clone + PartialEq + Eq + fmt::Debug {
	/// Process a query parameter.
	///
	/// `key` is the parameter name with any `req-` prefix already stripped.
	/// `value` is the percent-decoded value. `required` indicates whether
	/// the original key had a `req-` prefix.
	///
	/// Return `Ok(true)` if the parameter was handled, `Ok(false)` if not
	/// recognized, or `Err` on parse failure.
	fn handle_param(
		&mut self,
		key: &str,
		value: &str,
		required: bool,
	) -> Result<bool, Bip321Error>;

	/// Whether any extension parameters have been collected.
	fn is_empty(&self) -> bool;

	/// Append extension parameters to the serialization output.
	///
	/// Each entry should be `(key, value)` where `key` may include the
	/// `req-` prefix if needed. The crate will handle percent-encoding
	/// the values, so raw/decoded values should be returned
	fn serialize_params(&self) -> Vec<(String, String)>;
}

/// No-op extension handler for wallets that only need BIP 321 support.
///
/// Unknown non-required parameters are stored in the URI's `custom` map.
/// Unknown required parameters cause a parse error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoExtensions;

impl ExtensionHandler for NoExtensions {
	fn handle_param(
		&mut self,
		_key: &str,
		_value: &str,
		_required: bool,
	) -> Result<bool, Bip321Error> {
		Ok(false)
	}

	fn is_empty(&self) -> bool {
		true
	}

	fn serialize_params(&self) -> Vec<(String, String)> {
		Vec::new()
	}
}
