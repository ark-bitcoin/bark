
pub mod encodable {
	//! Module to bytes- or hex-encode bitcoin objects using the bitcoin encoding
	//!
	//! It is not recommended to use this for types that already have a string-based
	//! serde encoding like `PublicKey` or the hashes like `Txid`.

	use std::fmt;
	use std::borrow::Cow;
	use std::marker::PhantomData;

	use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

	use bitcoin::consensus::encode::{self, Decodable, Encodable};

	struct SerWrapper<'a, T>(&'a T);

	impl<'a, T: Encodable> Serialize for SerWrapper<'a, T> {
		fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
			if s.is_human_readable() {
				s.serialize_str(&encode::serialize_hex(&self.0))
			} else {
				s.serialize_bytes(&encode::serialize(&self.0))
			}
		}
	}

	struct DeWrapper<T>(T);

	impl<'de, T: Decodable> Deserialize<'de> for DeWrapper<T> {
		fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
			if d.is_human_readable() {
				let s = <Cow<'de, str>>::deserialize(d)?;
				Ok(DeWrapper(encode::deserialize_hex(s.as_ref())
					.map_err(serde::de::Error::custom)?))
			} else {
				let b = <Cow<'de, [u8]>>::deserialize(d)?;
				Ok(DeWrapper(encode::deserialize(b.as_ref())
					.map_err(serde::de::Error::custom)?))
			}
		}
	}

	pub fn serialize<T, S>(v: &T, s: S) -> Result<S::Ok, S::Error>
	where
		T: Encodable + Clone,
		S: Serializer,
	{
		SerWrapper(v).serialize(s)
	}

	pub fn deserialize<'d, T: Decodable, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
		Ok(DeWrapper::<T>::deserialize(d)?.0)
	}

	pub mod vec {
		use super::*;

		pub fn serialize<T: Encodable, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(v.len()))?;
			for item in v {
				ser::SerializeSeq::serialize_element(&mut seq, &SerWrapper(item))?;
			}
			ser::SerializeSeq::end(seq)
		}

		pub fn deserialize<'d, T: Decodable, D: Deserializer<'d>>(d: D) -> Result<Vec<T>, D::Error> {
			struct Visitor<T>(PhantomData<T>);

			impl<'de, T: Decodable> de::Visitor<'de> for Visitor<T> {
				type Value = Vec<T>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a vector of bitcoin-encoded objects")
				}

				fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
					let mut ret = Vec::with_capacity(seq.size_hint().unwrap_or_default());
					while let Some(v) = seq.next_element::<DeWrapper<T>>()? {
						ret.push(v.0);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor(PhantomData))
		}
	}

	pub mod cow {
		use super::*;

		pub fn serialize<'a, T, S>(v: &Cow<'a, T>, s: S) -> Result<S::Ok, S::Error>
		where
			T: Encodable + Clone,
			S: Serializer,
		{
			SerWrapper(v.as_ref()).serialize(s)
		}

		pub fn deserialize<'d, T, D>(d: D) -> Result<Cow<'static, T>, D::Error>
		where
			T: Decodable + Clone,
			D: Deserializer<'d>,
		{
			Ok(Cow::Owned(DeWrapper::<T>::deserialize(d)?.0))
		}
	}
}


#[cfg(test)]
mod test {
	use bitcoin::Transaction;

	#[test]
	fn test_serde_encodable() {
		let hex = "0200000000010151d0aa3be0ee0a27b2400f1eb9ddc692aace09c5d197475bceca711e0ba7ce320000000000ffffffff03ca2f03000000000022512043445259f5c414ce3fb6bd43d7caf8048f410351818fe4f0a26f95d010f653b7791b08000000000022512043445259f5c414ce3fb6bd43d7caf8048f410351818fe4f0a26f95d010f653b74a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001408abb6b9c0a21c90d3b42e059f94536588b1a99288abfdb79bbcfd548f7e3bb105e52c5cd8cff388679df825a7d5f93004dd416b81cfa0af1c814df79d381994c00000000";
		let tx = bitcoin::consensus::encode::deserialize_hex::<Transaction>(&hex).unwrap();
		let raw = bitcoin::consensus::encode::serialize(&tx);
		assert_eq!(raw.len(), 248);

		#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
		struct S {
			#[serde(with = "crate::serde::encodable")]
			tx: Transaction,
		}

		let s = S { tx };
		let json = serde_json::to_string(&s).unwrap();
		assert_eq!(json.len(), 505);
		assert_eq!(json, "{\"tx\":\"0200000000010151d0aa3be0ee0a27b2400f1eb9ddc692aace09c5d197475bceca711e0ba7ce320000000000ffffffff03ca2f03000000000022512043445259f5c414ce3fb6bd43d7caf8048f410351818fe4f0a26f95d010f653b7791b08000000000022512043445259f5c414ce3fb6bd43d7caf8048f410351818fe4f0a26f95d010f653b74a010000000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001408abb6b9c0a21c90d3b42e059f94536588b1a99288abfdb79bbcfd548f7e3bb105e52c5cd8cff388679df825a7d5f93004dd416b81cfa0af1c814df79d381994c00000000\"}");

		let s_from_json = serde_json::from_str(&json).unwrap();
		assert_eq!(s, s_from_json);

		let rmp = rmp_serde::to_vec(&s).unwrap();
		assert_eq!(rmp.len(), 251);
		let s_from_rmp = rmp_serde::from_slice(&rmp).unwrap();
		assert_eq!(s, s_from_rmp);

		let nrmp = rmp_serde::to_vec_named(&s).unwrap();
		assert_eq!(nrmp.len(), 254);
		let s_from_nrmp = rmp_serde::from_slice(&nrmp).unwrap();
		assert_eq!(s, s_from_nrmp);
	}
}

