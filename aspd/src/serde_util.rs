
use std::fmt;
use std::borrow::Cow;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};


/// Wrapping a byte array to be serialized as bytes.
pub struct Bytes<'a>(pub Cow<'a, [u8]>);

impl<'a> Serialize for Bytes<'a> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_bytes(self.0.as_ref())
	}
}

impl<'de> Deserialize<'de> for Bytes<'de> {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;

		impl<'de> de::Visitor<'de> for Visitor {
			type Value = Bytes<'de>;

			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
				f.write_str("just some bytes")
			}

			fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
				Ok(Bytes(Cow::Borrowed(v)))
			}

			fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
				Ok(Bytes(Cow::Owned(v.to_vec())))
			}
		}
		d.deserialize_bytes(Visitor)
	}
}

pub mod uri {
	use super::*;

	use tonic::transport::Uri;

	pub fn serialize<S: Serializer>(a: &Uri, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(a)
	}

	pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Uri, D::Error> {
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Uri;

			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
				f.write_str("a URI")
			}

			fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
				Uri::from_str(v).map_err(E::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}

pub mod duration {
	use super::*;

	use std::time::Duration;

	pub fn serialize<S: Serializer>(duration: &Duration, s: S) -> Result<S::Ok, S::Error> {
		s.collect_str(&humantime::format_duration(*duration))
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
		let s = String::deserialize(d)?;
		humantime::parse_duration(&s).map_err(serde::de::Error::custom)
	}
}

pub mod fee_rate {
	use super::*;

	use bitcoin::FeeRate;

	pub fn serialize<S: Serializer>(fee_rate: &FeeRate, s: S) -> Result<S::Ok, S::Error> {
		let sat_per_kwu = fee_rate.to_sat_per_kwu();
		s.collect_str(&format_args!("{}sat/kwu", sat_per_kwu))
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FeeRate, D::Error> {
		let ret = String::deserialize(d)?;
		if let Some(stripped) = ret.strip_suffix("sat/vb") {
			if let Ok(number) = stripped.trim().parse::<u64>() {
				let fr = FeeRate::from_sat_per_vb(number);
				if fr.is_some() {
					return Ok(fr.unwrap());
				}
			}
		} else if let Some(stripped) = ret.strip_suffix("sat/kwu") {
			if let Ok(number) = stripped.trim().parse::<u64>() {
				return Ok(FeeRate::from_sat_per_kwu(number));
			}
		}

		Err(serde::de::Error::custom("Failed to parse FeeRate in sat/kwu or sat/vb"))
	}
}
