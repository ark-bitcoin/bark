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

pub mod fee_rate_sats_per_kvb {
	use serde::{Deserialize, Deserializer, Serializer};
	use bitcoin::FeeRate;
	use bitcoin_ext::FeeRateExt;

	pub fn serialize<S>(v: &Option<FeeRate>, s: S) -> Result<S::Ok, S::Error>
	where S: Serializer {
		match v {
			Some(fr) => s.serialize_some(&fr.to_sat_per_kvb()),
			None => s.serialize_none(),
		}
	}

	pub fn deserialize<'de, D>(d: D) -> Result<Option<FeeRate>, D::Error>
	where D: Deserializer<'de> {
		let opt = Option::<u64>::deserialize(d)?;
		Ok(opt.map(FeeRate::from_sat_per_kvb_ceil))
	}
}
