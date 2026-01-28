//!
//! Definitions of protocol encodings.
//!


use std::borrow::Cow;
use std::{fmt, io, mem};

use bitcoin::hashes::{sha256, Hash};
// We use bitcoin::io::{Read, Write} here but we shouldn't have to.
// I created this issue in the hope that rust-bitcoin fixes this nuisance:
//  https://github.com/rust-bitcoin/rust-bitcoin/issues/4530
use bitcoin::secp256k1::{self, schnorr, PublicKey, XOnlyPublicKey};
use secp256k1_musig::musig;


/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Error occuring during protocol decoding.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolDecodingError {
	#[error("I/O error: {0}")]
	Io(#[from] io::Error),
	#[error("invalid protocol encoding: {message}")]
	Invalid {
		message: String,
		#[source]
		source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
	},
	#[error("{0}")]
	OversizedVector(#[from] OversizedVectorError),
}

impl ProtocolDecodingError {
	/// Create a new [ProtocolDecodingError::Invalid] with the given message.
	pub fn invalid(message: impl fmt::Display) -> Self {
		Self::Invalid {
			message: message.to_string(),
			source: None,
		}
	}

	/// Create a new [ProtocolDecodingError::Invalid] with the given message and source error.
	pub fn invalid_err<E>(source: E, message: impl fmt::Display) -> Self
	where
		E: std::error::Error + Send + Sync + 'static,
	{
		Self::Invalid {
			message: message.to_string(),
			source: Some(Box::new(source)),
		}
	}
}

impl From<bitcoin::consensus::encode::Error> for ProtocolDecodingError {
	fn from(e: bitcoin::consensus::encode::Error) -> Self {
		match e {
			bitcoin::consensus::encode::Error::Io(e) => Self::Io(e.into()),
			e => Self::invalid_err(e, "bitcoin protocol decoding error"),
		}
	}
}

impl From<bitcoin::io::Error> for ProtocolDecodingError {
	fn from(e: bitcoin::io::Error) -> Self {
	    Self::Io(e.into())
	}
}

/// Trait for encoding objects according to the bark protocol encoding.
pub trait ProtocolEncoding: Sized {
	/// Encode the object into the writer.
	//TODO(stevenroose) return nb of bytes written like bitcoin::consensus::Encodable does?
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error>;

	/// Decode the object from the writer.
	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError>;

	/// Serialize the object into a byte vector.
	fn serialize(&self) -> Vec<u8> {
		let mut buf = Vec::new();
		self.encode(&mut buf).expect("buffers don't produce I/O errors");
		buf
	}

	/// Deserialize object from the given byte slice.
	fn deserialize(mut byte_slice: &[u8]) -> Result<Self, ProtocolDecodingError> {
		Self::decode(&mut byte_slice)
	}

	/// Serialize the object to a lowercase hex string.
	fn serialize_hex(&self) -> String {
		use hex_conservative::Case::Lower;
		let mut buf = String::new();
		let mut writer = hex_conservative::display::HexWriter::new(&mut buf, Lower);
		self.encode(&mut writer).expect("no I/O errors for buffers");
		buf
	}

	/// Deserialize object from hex slice.
	fn deserialize_hex(hex_str: &str) -> Result<Self, ProtocolDecodingError> {
		let mut iter = hex_conservative::HexToBytesIter::new(hex_str).map_err(|e| {
			ProtocolDecodingError::Io(io::Error::new(io::ErrorKind::InvalidData, e))
		})?;
		Self::decode(&mut iter)
	}
}

/// Utility trait to write some primitive values into our encoding format.
pub trait WriteExt: io::Write {
	/// Write an 8-bit unsigned integer in little-endian.
	fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
		self.write_all(&v.to_le_bytes())
	}

	/// Write a 16-bit unsigned integer in little-endian.
	fn emit_u16(&mut self, v: u16) -> Result<(), io::Error> {
		self.write_all(&v.to_le_bytes())
	}

	/// Write a 32-bit unsigned integer in little-endian.
	fn emit_u32(&mut self, v: u32) -> Result<(), io::Error> {
		self.write_all(&v.to_le_bytes())
	}

	/// Write a 64-bit unsigned integer in little-endian.
	fn emit_u64(&mut self, v: u64) -> Result<(), io::Error> {
		self.write_all(&v.to_le_bytes())
	}

	/// Write the entire slice to the writer.
	fn emit_slice(&mut self, slice: &[u8]) -> Result<(), io::Error> {
		self.write_all(slice)
	}

	/// Write a value in compact size aka "VarInt" encoding.
	fn emit_compact_size(&mut self, value: impl Into<u64>) -> Result<usize, io::Error> {
		let value = value.into();
		match value {
			0..=0xFC => {
				self.emit_u8(value as u8)?;
				Ok(1)
			},
			0xFD..=0xFFFF => {
				self.emit_u8(0xFD)?;
				self.emit_u16(value as u16)?;
				Ok(3)
			},
			0x10000..=0xFFFFFFFF => {
				self.emit_u8(0xFE)?;
				self.emit_u32(value as u32)?;
				Ok(5)
			},
			_ => {
				self.emit_u8(0xFF)?;
				self.emit_u64(value)?;
				Ok(9)
			},
		}
	}
}

impl<W: io::Write + ?Sized> WriteExt for W {}

/// Utility trait to read some primitive values into our encoding format.
pub trait ReadExt: io::Read {
	/// Read an 8-bit unsigned integer in little-endian.
	fn read_u8(&mut self) -> Result<u8, io::Error> {
		let mut buf = [0; 1];
		self.read_exact(&mut buf[..])?;
		Ok(u8::from_le_bytes(buf))
	}

	/// Read a 16-bit unsigned integer in little-endian.
	fn read_u16(&mut self) -> Result<u16, io::Error> {
		let mut buf = [0; 2];
		self.read_exact(&mut buf[..])?;
		Ok(u16::from_le_bytes(buf))
	}

	/// Read a 32-bit unsigned integer in little-endian.
	fn read_u32(&mut self) -> Result<u32, io::Error> {
		let mut buf = [0; 4];
		self.read_exact(&mut buf[..])?;
		Ok(u32::from_le_bytes(buf))
	}

	/// Read a 64-bit unsigned integer in little-endian.
	fn read_u64(&mut self) -> Result<u64, io::Error> {
		let mut buf = [0; 8];
		self.read_exact(&mut buf[..])?;
		Ok(u64::from_le_bytes(buf))
	}

	/// Read from the reader to fill the entire slice.
	fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), io::Error> {
		self.read_exact(slice)
	}

	/// Read a byte array
	fn read_byte_array<const N: usize>(&mut self) -> Result<[u8; N], io::Error> {
		let mut ret = [0u8; N];
		self.read_exact(&mut ret)?;
		Ok(ret)
	}

	/// Read a value in compact size aka "VarInt" encoding.
	fn read_compact_size(&mut self) -> Result<u64, io::Error> {
		match self.read_u8()? {
			0xFF => {
				let x = self.read_u64()?;
				if x < 0x1_0000_0000 { // I.e., would have fit in a `u32`.
					Err(io::Error::new(io::ErrorKind::InvalidData, "non-minimal varint"))
				} else {
					Ok(x)
				}
			},
			0xFE => {
				let x = self.read_u32()?;
				if x < 0x1_0000 { // I.e., would have fit in a `u16`.
					Err(io::Error::new(io::ErrorKind::InvalidData, "non-minimal varint"))
				} else {
					Ok(x as u64)
				}
			},
			0xFD => {
				let x = self.read_u16()?;
				if x < 0xFD { // Could have been encoded as a `u8`.
					Err(io::Error::new(io::ErrorKind::InvalidData, "non-minimal varint"))
				} else {
					Ok(x as u64)
				}
			},
			n => Ok(n as u64),
		}
	}
}

impl<R: io::Read + ?Sized> ReadExt for R {}


impl ProtocolEncoding for PublicKey {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.serialize())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut buf = [0; secp256k1::constants::PUBLIC_KEY_SIZE];
		r.read_slice(&mut buf[..])?;
		PublicKey::from_slice(&buf).map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "invalid public key")
		})
	}
}

impl ProtocolEncoding for XOnlyPublicKey {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.serialize())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut buf = [0; 32];
		r.read_slice(&mut buf[..])?;
		XOnlyPublicKey::from_slice(&buf).map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "invalid x-only public key")
		})
	}
}

impl ProtocolEncoding for Option<sha256::Hash> {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		if let Some(h) = self {
			w.emit_u8(1)?;
			w.emit_slice(&h.as_byte_array()[..])
		} else {
			w.emit_u8(0)
		}
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let first = r.read_u8()?;
		if first == 0 {
			Ok(None)
		} else if first == 1 {
			let mut buf = [0u8; 32];
			r.read_slice(&mut buf)?;
			Ok(Some(sha256::Hash::from_byte_array(buf)))
		} else {
			Err(ProtocolDecodingError::invalid("invalid optional hash prefix byte"))
		}
	}
}

impl ProtocolEncoding for Option<PublicKey> {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		if let Some(pk) = self {
			w.emit_slice(&pk.serialize())
		} else {
			w.emit_u8(0)
		}
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let first = r.read_u8()?;
		if first == 0 {
			Ok(None)
		} else {
			let mut pk = [first; secp256k1::constants::PUBLIC_KEY_SIZE];
			r.read_slice(&mut pk[1..])?;
			Ok(Some(PublicKey::from_slice(&pk).map_err(|e| {
				ProtocolDecodingError::invalid_err(e, "invalid public key")
			})?))
		}
	}
}

impl ProtocolEncoding for schnorr::Signature {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.serialize())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut buf = [0; secp256k1::constants::SCHNORR_SIGNATURE_SIZE];
		r.read_slice(&mut buf[..])?;
		schnorr::Signature::from_slice(&buf).map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "invalid schnorr signature")
		})
	}
}

impl ProtocolEncoding for Option<schnorr::Signature> {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		if let Some(sig) = self {
			w.emit_slice(&sig.serialize())
		} else {
			w.emit_slice(&[0; secp256k1::constants::SCHNORR_SIGNATURE_SIZE])
		}
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut buf = [0; secp256k1::constants::SCHNORR_SIGNATURE_SIZE];
		r.read_slice(&mut buf[..])?;
		if buf == [0; secp256k1::constants::SCHNORR_SIGNATURE_SIZE] {
			Ok(None)
		} else {
			Ok(Some(schnorr::Signature::from_slice(&buf).map_err(|e| {
				ProtocolDecodingError::invalid_err(e, "invalid schnorr signature")
			})?))
		}
	}
}

impl ProtocolEncoding for sha256::Hash {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self[..])
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let mut buf = [0; sha256::Hash::LEN];
		r.read_exact(&mut buf[..])?;
		Ok(sha256::Hash::from_byte_array(buf))
	}
}

impl ProtocolEncoding for musig::PublicNonce {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
	    w.emit_slice(&self.serialize())
	}
	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self::from_byte_array(&r.read_byte_array()?).map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "invalid musig public nonce")
		})?)
	}
}

impl ProtocolEncoding for musig::PartialSignature {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
	    w.emit_slice(&self.serialize())
	}
	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self::from_byte_array(&r.read_byte_array()?).map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "invalid musig public nonce")
		})?)
	}
}

/// A macro to implement our [ProtocolEncoding] for a rust-bitcoin type that
/// implements their `consensus::Encodable/Decodable` traits.
macro_rules! impl_bitcoin_encode {
	($name:ty) => {
		impl ProtocolEncoding for $name {
			fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
				let mut wrapped = bitcoin::io::FromStd::new(w);
				bitcoin::consensus::Encodable::consensus_encode(self, &mut wrapped)?;
				Ok(())
			}

			fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
				let mut wrapped = bitcoin::io::FromStd::new(r);
				let ret = bitcoin::consensus::Decodable::consensus_decode(&mut wrapped)?;
				Ok(ret)
			}
		}
	};
}

impl_bitcoin_encode!(bitcoin::BlockHash);
impl_bitcoin_encode!(bitcoin::OutPoint);
impl_bitcoin_encode!(bitcoin::TxOut);

impl ProtocolEncoding for bitcoin::taproot::TapTweakHash {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_slice(&self.to_byte_array())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		Ok(Self::from_byte_array(r.read_byte_array().map_err(|e| {
			ProtocolDecodingError::invalid_err(e, "TapTweakHash must be 32 bytes")
		})?))
	}
}

impl<'a, T: ProtocolEncoding + Clone> ProtocolEncoding for Cow<'a, T> {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
	    ProtocolEncoding::encode(self.as_ref(), writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
	    Ok(Cow::Owned(ProtocolEncoding::decode(reader)?))
	}
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("requested to allocate a vector above our limit: requested={requested}, max={max}")]
pub struct OversizedVectorError {
	/// requested number of elements
	pub requested: usize,
	/// maximum number of elements
	pub max: usize,
}

impl OversizedVectorError {
	/// Check if allocating the requested number of items is allowed
	pub fn check<T>(requested: usize) -> Result<(), Self> {
		let max = MAX_VEC_SIZE / mem::size_of::<T>();
		if requested > max {
			Err(Self { requested, max })
		} else {
			Ok(())
		}
	}
}

/// A wrapper around a `Vec<T>` for any `T` with [ProtocolEncoding] that can be safely
/// encoded and decoded using a CompactSize length prefix
///
/// Max allocation size is protected to `MAX_VEC_SIZE`.
#[derive(Debug, Clone)]
pub struct LengthPrefixedVector<'a, T: Clone> {
	inner: Cow<'a, [T]>,
}

impl<'a, T: Clone> LengthPrefixedVector<'a, T> {
	/// Create a new [LengthPrefixedVector] wrapping the slice
	pub fn new(buf: &'a [T]) -> Self {
		Self { inner: Cow::Borrowed(buf) }
	}

	/// Unwrap into inner vector
	pub fn into_inner(self) -> Vec<T> {
		self.inner.into_owned()
	}
}

impl<'a, T: ProtocolEncoding + Clone> ProtocolEncoding for LengthPrefixedVector<'a, T> {
	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		w.emit_compact_size(self.inner.as_ref().len() as u64)?;
		for item in self.inner.as_ref() {
			item.encode(w)?;
		}
		Ok(())
	}

	fn decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, ProtocolDecodingError> {
		let count = r.read_compact_size()? as usize;
		OversizedVectorError::check::<T>(count)?;

		let mut buf = Vec::with_capacity(count);
		for _ in 0..count {
			buf.push(ProtocolEncoding::decode(r)?);
		}

		Ok(LengthPrefixedVector {
			inner: Cow::Owned(buf),
		})
	}
}


pub mod serde {
	//! Module that helps to encode [ProtocolEncoding] objects with serde.
	//!
	//! By default, the objects will be encoded as bytes for regular serializers,
	//! and as hex for human-readable serializers.
	//!
	//! Can be used as follows:
	//! ```no_run
	//! # use ark::Vtxo;
	//! # use serde::{Serialize, Deserialize};
	//! #[derive(Serialize, Deserialize)]
	//! struct SomeStruct {
	//! 	#[serde(with = "ark::encode::serde")]
	//! 	single: Vtxo,
	//! 	#[serde(with = "ark::encode::serde::vec")]
	//! 	multiple: Vec<Vtxo>,
	//! }
	//! ```

	use std::fmt;
	use std::borrow::Cow;
	use std::marker::PhantomData;

	use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

	use super::ProtocolEncoding;

	struct SerWrapper<'a, T>(&'a T);

	impl<'a, T: ProtocolEncoding> Serialize for SerWrapper<'a, T> {
		fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
			if s.is_human_readable() {
				s.serialize_str(&self.0.serialize_hex())
			} else {
				s.serialize_bytes(&self.0.serialize())
			}
		}
	}

	struct DeWrapper<T>(T);

	impl<'de, T: ProtocolEncoding> Deserialize<'de> for DeWrapper<T> {
		fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
			if d.is_human_readable() {
				let s = <Cow<'de, str>>::deserialize(d)?;
				Ok(DeWrapper(ProtocolEncoding::deserialize_hex(s.as_ref())
					.map_err(serde::de::Error::custom)?))
			} else {
				let b = <Cow<'de, [u8]>>::deserialize(d)?;
				Ok(DeWrapper(ProtocolEncoding::deserialize(b.as_ref())
					.map_err(serde::de::Error::custom)?))
			}
		}
	}

	pub fn serialize<T: ProtocolEncoding, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
		SerWrapper(v).serialize(s)
	}

	pub fn deserialize<'d, T: ProtocolEncoding, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
		Ok(DeWrapper::<T>::deserialize(d)?.0)
	}

	pub mod vec {
		use super::*;

		pub fn serialize<T: ProtocolEncoding, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(v.len()))?;
			for item in v {
				ser::SerializeSeq::serialize_element(&mut seq, &SerWrapper(item))?;
			}
			ser::SerializeSeq::end(seq)
		}

		pub fn deserialize<'d, T: ProtocolEncoding, D: Deserializer<'d>>(d: D) -> Result<Vec<T>, D::Error> {
			struct Visitor<T>(PhantomData<T>);

			impl<'de, T: ProtocolEncoding> de::Visitor<'de> for Visitor<T> {
				type Value = Vec<T>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a vector of objects implementing ProtocolEncoding")
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

		use std::borrow::Cow;

		pub fn serialize<'a, T, S>(v: &Cow<'a, T>, s: S) -> Result<S::Ok, S::Error>
		where
			T: ProtocolEncoding + Clone,
			S: Serializer,
		{
			SerWrapper(v.as_ref()).serialize(s)
		}

		pub fn deserialize<'d, T, D>(d: D) -> Result<Cow<'static, T>, D::Error>
		where
			T: ProtocolEncoding + Clone,
			D: Deserializer<'d>,
		{
			Ok(Cow::Owned(DeWrapper::<T>::deserialize(d)?.0))
		}

		pub mod vec {
			use super::*;

			use std::borrow::Cow;

			pub fn serialize<'a, T, S>(v: &Cow<'a, [T]>, s: S) -> Result<S::Ok, S::Error>
			where
				T: ProtocolEncoding + Clone,
				S: Serializer,
			{
				let mut seq = s.serialize_seq(Some(v.len()))?;
				for item in v.as_ref().iter() {
					ser::SerializeSeq::serialize_element(&mut seq, &SerWrapper(item))?;
				}
				ser::SerializeSeq::end(seq)
			}

			pub fn deserialize<'d, T, D>(d: D) -> Result<Cow<'static, [T]>, D::Error>
			where
				T: ProtocolEncoding + Clone,
				D: Deserializer<'d>,
			{
				struct Visitor<T>(PhantomData<T>);

				impl<'de, T: ProtocolEncoding + Clone + 'static> de::Visitor<'de> for Visitor<T> {
					type Value = Cow<'static, [T]>;

					fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
						f.write_str("a vector of objects implementing ProtocolEncoding")
					}

					fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
						let mut ret = Vec::with_capacity(seq.size_hint().unwrap_or_default());
						while let Some(v) = seq.next_element::<DeWrapper<T>>()? {
							ret.push(v.0);
						}
						Ok(ret.into())
					}
				}
				d.deserialize_seq(Visitor(PhantomData))
			}
		}
	}
}


#[cfg(test)]
mod test {
	use bitcoin::hex::DisplayHex;
	use bitcoin::secp256k1::{self, Keypair};

	use crate::SECP;
	use super::*;


	#[test]
	fn option_pubkey() {
		let key = Keypair::new(&SECP, &mut secp256k1::rand::thread_rng());
		let pk = key.public_key();

		println!("pk: {}", pk);

		println!("serialize option: {}",
			<Option<PublicKey> as ProtocolEncoding>::serialize(&Some(pk)).as_hex(),
		);

		assert_eq!(pk,
			ProtocolEncoding::deserialize(&ProtocolEncoding::serialize(&pk)).unwrap(),
		);

		assert_eq!(Some(pk),
			ProtocolEncoding::deserialize(&ProtocolEncoding::serialize(&Some(pk))).unwrap(),
		);

		assert_eq!(None,
			<Option<PublicKey> as ProtocolEncoding>::deserialize(
				&ProtocolEncoding::serialize(&Option::<PublicKey>::None),
			).unwrap(),
		);

	}
}
