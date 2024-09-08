

use std::fmt;
use std::str::FromStr;

use serde::{de, Deserializer, Serializer};

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
