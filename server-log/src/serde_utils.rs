
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

pub mod trace_id {
	use super::*;
	use crate::TraceId;
	use bitcoin::hex::{DisplayHex, FromHex};

	pub fn serialize<S: Serializer>(b: &TraceId, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(b)
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<TraceId, D::Error> {
		let hex_str: &str = serde::Deserialize::deserialize(d)?;
		Ok(TraceId::from_hex(hex_str).map_err(D::Error::custom)?)
	}

	pub mod opt {
		use super::*;

		pub fn serialize<S: Serializer>(b: &Option<TraceId>, s: S) -> Result<S::Ok, S::Error> {
			match *b {
				None => s.serialize_none(),
				Some(ref b) => s.collect_str(b),
			}
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<TraceId>, D::Error> {
			let hex: Option<&str> = serde::Deserialize::deserialize(d)?;
			Ok(hex.map(|s| TraceId::from_hex(s).map_err(D::Error::custom)).transpose()?)
		}
	}
}
