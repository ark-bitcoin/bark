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

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use crate::{Bip321Error, Bip321Uri, ExtensionHandler, FieldWithAttributes};

	const MAINNET_P2PKH: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

	#[derive(Debug, Clone, Default, PartialEq, Eq)]
	struct DummyExt {
		value: Option<FieldWithAttributes<String>>,
	}

	impl ExtensionHandler for DummyExt {
		fn handle_param(
			&mut self,
			key: &str,
			value: &str,
			required: bool,
		) -> Result<bool, Bip321Error> {
			if key == "dummy" {
				self.value = Some(FieldWithAttributes::new(value.to_string(), required));
				Ok(true)
			} else {
				Ok(false)
			}
		}

		fn is_empty(&self) -> bool {
			self.value.is_none()
		}

		fn serialize_params(&self) -> Vec<(String, String)> {
			match &self.value {
				Some(v) => {
					let key = if v.required() { "req-dummy" } else { "dummy" };
					vec![(key.to_string(), v.inner().clone())]
				}
				None => Vec::new(),
			}
		}
	}

	#[test]
	fn extension_handler_claims_param() {
		let input = format!("bitcoin:{}?dummy=hello", MAINNET_P2PKH);
		let uri = Bip321Uri::<DummyExt>::from_str(&input).unwrap();
		let ext = uri.extensions();
		assert!(!ext.is_empty());
		assert_eq!(ext.value.as_ref().unwrap().inner(), "hello");
	}

	#[test]
	fn extension_only_satisfies_validation() {
		let input = "bitcoin:?dummy=hello";
		let uri = Bip321Uri::<DummyExt>::from_str(input).unwrap();
		assert!(uri.address.is_none());
		assert!(!uri.extensions().is_empty());
	}

	#[test]
	fn extension_roundtrip() {
		let input = format!("bitcoin:{}?dummy=hello", MAINNET_P2PKH);
		let parsed = Bip321Uri::<DummyExt>::from_str(&input).unwrap();
		let serialized = parsed.to_string();
		let reparsed = Bip321Uri::<DummyExt>::from_str(&serialized).unwrap();
		assert_eq!(parsed, reparsed);
	}
}