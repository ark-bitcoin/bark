
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

	pub mod opt {
		use super::*;

		pub fn serialize<T, S>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error>
		where
			T: Encodable + Clone,
			S: Serializer,
		{
			match v {
				None => s.serialize_none(),
				Some(v) => SerWrapper(v).serialize(s),
			}
		}

		pub fn deserialize<'d, T, D>(d: D) -> Result<Option<T>, D::Error>
		where
			T: Decodable,
			D: Deserializer<'d>,
		{
			Ok(Option::<DeWrapper<T>>::deserialize(d)?.map(|v| v.0))
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

pub mod psbt {
	//! Module to bytes- or hex-encode a [Psbt] using the BIP-174 encoding.
	//!
	//! A PSBT has an encoding of its own rather than the consensus one, so
	//! [super::encodable] cannot serve it.

	use std::borrow::Cow;

	use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

	use bitcoin::Psbt;
	use bitcoin::hex::FromHex;

	struct SerWrapper<'a>(&'a Psbt);

	impl<'a> Serialize for SerWrapper<'a> {
		fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
			if s.is_human_readable() {
				s.serialize_str(&self.0.serialize_hex())
			} else {
				s.serialize_bytes(&self.0.serialize())
			}
		}
	}

	struct DeWrapper(Psbt);

	impl<'de> Deserialize<'de> for DeWrapper {
		fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
			let bytes = if d.is_human_readable() {
				let hex = <Cow<'de, str>>::deserialize(d)?;
				Vec::<u8>::from_hex(hex.as_ref()).map_err(de::Error::custom)?
			} else {
				<Cow<'de, [u8]>>::deserialize(d)?.into_owned()
			};
			Ok(DeWrapper(Psbt::deserialize(&bytes).map_err(de::Error::custom)?))
		}
	}

	pub fn serialize<S: Serializer>(v: &Psbt, s: S) -> Result<S::Ok, S::Error> {
		SerWrapper(v).serialize(s)
	}

	pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Psbt, D::Error> {
		Ok(DeWrapper::deserialize(d)?.0)
	}

	pub mod opt {
		use super::*;

		pub fn serialize<S: Serializer>(v: &Option<Psbt>, s: S) -> Result<S::Ok, S::Error> {
			match v {
				None => s.serialize_none(),
				Some(v) => SerWrapper(v).serialize(s),
			}
		}

		pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Option<Psbt>, D::Error> {
			Ok(Option::<DeWrapper>::deserialize(d)?.map(|v| v.0))
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

	#[test]
	fn test_serde_psbt() {
		// `witness_utxo` is set so the round-trip covers a per-input map, not just
		// the global one.
		let mut unsigned = bitcoin::Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
			input: vec![bitcoin::TxIn::default()],
			output: vec![bitcoin::TxOut {
				value: bitcoin::Amount::from_sat(1_000),
				script_pubkey: bitcoin::ScriptBuf::new_op_return(&[0u8; 4]),
			}],
		};
		unsigned.input[0].witness = bitcoin::Witness::new();
		let mut psbt = bitcoin::Psbt::from_unsigned_tx(unsigned).unwrap();
		psbt.inputs[0].witness_utxo = Some(bitcoin::TxOut {
			value: bitcoin::Amount::from_sat(2_000),
			script_pubkey: bitcoin::ScriptBuf::new_op_return(&[1u8; 4]),
		});

		#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
		struct S {
			#[serde(with = "crate::serde::psbt")]
			psbt: bitcoin::Psbt,
			#[serde(with = "crate::serde::psbt::opt")]
			opt: Option<bitcoin::Psbt>,
			#[serde(with = "crate::serde::psbt::opt")]
			none: Option<bitcoin::Psbt>,
		}

		let s = S { psbt: psbt.clone(), opt: Some(psbt), none: None };

		// Human-readable formats get hex, binary formats get the raw BIP-174 bytes.
		let json = serde_json::to_string(&s).unwrap();
		assert!(json.contains(&s.psbt.serialize_hex()), "{json}");
		assert_eq!(s, serde_json::from_str(&json).unwrap());

		let rmp = rmp_serde::to_vec(&s).unwrap();
		assert!(rmp.len() < json.len(), "binary encoding should beat hex");
		assert_eq!(s, rmp_serde::from_slice(&rmp).unwrap());

		let nrmp = rmp_serde::to_vec_named(&s).unwrap();
		assert_eq!(s, rmp_serde::from_slice(&nrmp).unwrap());
	}
}
