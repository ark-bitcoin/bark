use serde::{Deserialize, Deserializer, Serializer};

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