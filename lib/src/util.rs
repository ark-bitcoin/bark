
/// Implement a bunch of useful traits for any newtype around 32 bytes.
macro_rules! impl_byte_newtype {
	($name:ident, $n:expr) => {
		impl std::fmt::Debug for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				std::fmt::Display::fmt(self, f)
			}
		}

		impl std::fmt::Display for $name {
			fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				let case = $crate::bitcoin::hex::Case::Lower;
				$crate::bitcoin::hex::fmt_hex_exact!(f, $n, &self.0, case)
			}
		}

		impl std::str::FromStr for $name {
			type Err = bitcoin::hashes::hex::HexToArrayError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				$crate::bitcoin::hex::FromHex::from_hex(s).map($name)
			}
		}

		impl From<[u8; $n]> for $name {
			fn from(inner: [u8; $n]) -> Self {
				$name(inner)
			}
		}

		impl From<$name> for [u8; $n] {
			fn from(p: $name) -> Self {
				p.0
			}
		}

		impl std::convert::TryFrom<&[u8]> for $name {
			type Error = std::array::TryFromSliceError;

			fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
				<&[u8; $n]>::try_from(slice).map(|arr| $name(*arr))
			}
		}

		impl TryFrom<Vec<u8>> for $name {
			type Error = std::array::TryFromSliceError;

			fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
				$name::try_from(vec.as_slice())
			}
		}

		impl AsRef<[u8]> for $name {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		impl<'a> $crate::bitcoin::hex::DisplayHex for &'a $name {
			type Display = <&'a [u8; $n] as $crate::bitcoin::hex::DisplayHex>::Display;

			fn as_hex(self) -> Self::Display {
				$crate::bitcoin::hex::DisplayHex::as_hex(&self.0)
			}
		}

		impl serde::Serialize for $name {
			fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
				if s.is_human_readable() {
					s.collect_str(self)
				} else {
					s.serialize_bytes(self.as_ref())
				}
			}
		}

		impl<'de> serde::Deserialize<'de> for $name {
			fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
				struct Visitor;
				impl<'de> serde::de::Visitor<'de> for Visitor {
					type Value = $name;
					fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
						write!(f, concat!("a ", stringify!($name)))
					}
					fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
						TryFrom::try_from(v).map_err(serde::de::Error::custom)
					}
					fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
						std::str::FromStr::from_str(v).map_err(serde::de::Error::custom)
					}
				}

				if d.is_human_readable() {
					d.deserialize_str(Visitor)
				} else {
					d.deserialize_bytes(Visitor)
				}
			}
		}

		impl $name {
			/// Convert into underlying byte array.
			pub fn to_byte_array(self) -> [u8; $n] {
				self.0
			}

			/// Create from byte slice.
			pub fn from_slice(slice: &[u8]) -> Result<Self, std::array::TryFromSliceError> {
				Self::try_from(slice)
			}

			/// Convert into a byte vector.
			pub fn to_vec(&self) -> Vec<u8> {
				self.0.to_vec()
			}
		}
	};
}
