//! Serde helpers.

/// Serializes an `Option<Vec<Amount>>` as a list of sat values.
pub mod opt_amount_vec_sat {
	use bitcoin::Amount;
	use serde::{Deserialize, Deserializer, Serialize, Serializer};

	pub fn serialize<S: Serializer>(v: &Option<Vec<Amount>>, s: S) -> Result<S::Ok, S::Error> {
		v.as_ref().map(|v| v.iter().map(|a| a.to_sat()).collect::<Vec<_>>()).serialize(s)
	}

	pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<Amount>>, D::Error> {
		Ok(Option::<Vec<u64>>::deserialize(d)?
			.map(|v| v.into_iter().map(Amount::from_sat).collect()))
	}
}
