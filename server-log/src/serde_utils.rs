
#![allow(unused)]

use serde::de::Error;
use serde::{Deserializer, Deserialize, Serializer};


/// A module used for serde serialization of bytes in hexadecimal format.
///
/// The module is compatible with the serde attribute.
pub mod hex {
	use super::*;
	use bitcoin::hex::{DisplayHex, FromHex};

	pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(&b.as_hex())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
		let hex: &str = serde::Deserialize::deserialize(d)?;
		Ok(FromHex::from_hex(hex).map_err(D::Error::custom)?)
	}

	pub mod opt {
		use super::*;

		pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
			match *b {
				None => s.serialize_none(),
				Some(ref b) => s.collect_str(&b.as_hex()),
			}
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
			let hex: Option<&str> = serde::Deserialize::deserialize(d)?;
			Ok(hex.map(|s| FromHex::from_hex(s).map_err(D::Error::custom)).transpose()?)
		}
	}
}

pub mod duration {
	use super::*;

	use std::time::Duration;

	pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(&humantime::format_duration(*duration))
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
		let s = <&str>::deserialize(d)?;
		humantime::parse_duration(s).map_err(serde::de::Error::custom)
	}
}

pub mod duration_millis {
	use super::*;

	use std::time::Duration;
	use serde::{Serializer, Deserializer};

	pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_u64(duration.as_millis() as u64)
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
		let millis = u64::deserialize(d)?;
		Ok(Duration::from_millis(millis))
	}
}

pub mod fee_rate {
	use serde::{Deserialize, Deserializer, Serializer};
	use bitcoin::FeeRate;
	use bitcoin_ext::FeeRateExt;

	pub fn serialize<S: Serializer>(v: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_u64(v.to_sat_per_kvb())
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FeeRate, D::Error> {
		let sat_kvb = u64::deserialize(d)?;
		Ok(FeeRate::from_sat_per_kvb_ceil(sat_kvb))
	}
}
