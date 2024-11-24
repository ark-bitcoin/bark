
#![allow(unused)]

/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod hex {
	use bitcoin::hex::{DisplayHex, FromHex};
	use serde::de::Error;
	use serde::{Deserializer, Serializer};

	pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&b.to_lower_hex_string())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
		let hex_str: String = ::serde::Deserialize::deserialize(d)?;
		Ok(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?)
	}

	pub mod opt {
		use bitcoin::hex::{DisplayHex, FromHex};
		use serde::de::Error;
		use serde::{Deserializer, Serializer};

		pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
			match *b {
				None => s.serialize_none(),
				Some(ref b) => s.serialize_str(&b.to_lower_hex_string()),
			}
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
			let hex_str: String = ::serde::Deserialize::deserialize(d)?;
			Ok(Some(FromHex::from_hex(&hex_str).map_err(D::Error::custom)?))
		}
	}
}
