
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

pub mod string {
	//! generic way to serialize a type using it's [fmt::Display] and [str::FromStr] impl

	use std::marker::PhantomData;

	use super::*;

	struct RefWrapper<'a, T>(&'a T);

	impl<'a, T: fmt::Display> Serialize for RefWrapper<'a, T> {
		fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
		    serializer.collect_str(&self.0)
		}
	}

	struct OwnedWrapper<T>(T);

	impl<'de, T> Deserialize<'de> for OwnedWrapper<T>
	where
		T: FromStr,
		T::Err: fmt::Display,
	{
		fn deserialize<D>(d: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
		{
			struct Visitor<T>(PhantomData<T>);

			impl<'de, T> de::Visitor<'de> for Visitor<T>
			where
				T: FromStr,
				T::Err: fmt::Display,
			{
				type Value = OwnedWrapper<T>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a stringable object")
				}

				fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
					Ok(OwnedWrapper(T::from_str(s).map_err(serde::de::Error::custom)?))
				}
			}
			d.deserialize_str(Visitor(PhantomData))
		}
	}

	pub fn serialize<T, S>(v: &T, s: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		s.collect_str(v)
	}

	pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
	where
		D: Deserializer<'de>,
		T: FromStr,
		T::Err: fmt::Display,
	{
		Ok(OwnedWrapper::deserialize(d)?.0)
	}

	pub mod vec {
		use std::marker::PhantomData;

		use serde::ser::SerializeSeq;

		use super::*;

		pub fn serialize<T, S>(v: &[T], s: S) -> Result<S::Ok, S::Error>
		where
			T: fmt::Display,
			S: Serializer,
		{
			let mut seq = s.serialize_seq(Some(v.len()))?;
			for i in v {
				seq.serialize_element(&RefWrapper(i))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, T, D>(d: D) -> Result<Vec<T>, D::Error>
		where
			D: Deserializer<'de>,
			T: FromStr,
			T::Err: fmt::Display,
		{
			struct Visitor<T>(PhantomData<T>);

			impl<'de, T> de::Visitor<'de> for Visitor<T>
			where
				T: FromStr,
				T::Err: fmt::Display,
			{
				type Value = Vec<T>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a sequence of stringable objects")
				}

				fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
				    where
				        A: de::SeqAccess<'de>, {
					let mut ret = Vec::with_capacity(seq.size_hint().unwrap_or_default());
					while let Some(i) = seq.next_element::<OwnedWrapper<T>>()? {
						ret.push(i.0);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor(PhantomData))
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
		struct Visitor;

		impl<'de> de::Visitor<'de> for Visitor {
			type Value = Duration;

			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
				f.write_str("a duration")
			}

			fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
				humantime::parse_duration(s).map_err(serde::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
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
		struct Visitor;

		impl<'de> de::Visitor<'de> for Visitor {
			type Value = FeeRate;

			fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
				f.write_str("a fee rate")
			}

			fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
				if let Some(stripped) = s.strip_suffix("sat/vb") {
					if let Ok(number) = stripped.trim().parse::<u64>() {
						let fr = FeeRate::from_sat_per_vb(number);
						if fr.is_some() {
							return Ok(fr.unwrap());
						}
					}
				} else if let Some(stripped) = s.strip_suffix("sat/kwu") {
					if let Ok(number) = stripped.trim().parse::<u64>() {
						return Ok(FeeRate::from_sat_per_kwu(number));
					}
				}

				Err(serde::de::Error::custom("Failed to parse FeeRate in sat/kwu or sat/vb"))
			}
		}
		d.deserialize_str(Visitor)
	}
}
