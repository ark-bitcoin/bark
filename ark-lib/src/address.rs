
use std::fmt;
use std::str::FromStr;

use bitcoin::bech32::{self, ByteIterExt, Fe32IterExt};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;


/// The human-readable part for mainnet addresses.
const HRP_MAINNET: bech32::Hrp = bech32::Hrp::parse_unchecked("ark");

/// The human-readable part for test addresses.
const HRP_TESTNET: bech32::Hrp = bech32::Hrp::parse_unchecked("tark");

/// Address version 0 used for pubkey addressing in bark.
const VERSION_PUBKEY: bech32::Fe32 = bech32::Fe32::Q;


/// Identifier for an Ark server as used in addresses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArkId([u8; 4]);
impl_byte_newtype!(ArkId, 4);

impl ArkId {
	/// Create a new [ArkId] from a server pubkey.
	pub fn from_server_pubkey(server_pubkey: PublicKey) -> ArkId {
		let mut buf = [0u8; 4];
		let hash = sha256::Hash::hash(&server_pubkey.serialize());
		buf[0..4].copy_from_slice(&hash[0..4]);
		ArkId(buf)
	}

	/// Check whether the given server pubkey matches this [ArkId].
	pub fn is_for_server(&self, server_pubkey: PublicKey) -> bool {
		*self == ArkId::from_server_pubkey(server_pubkey)
	}
}

impl From<PublicKey> for ArkId {
	fn from(pk: PublicKey) -> Self {
	    ArkId::from_server_pubkey(pk)
	}
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
	testnet: bool,
	ark_id: ArkId,
	pubkey: PublicKey,
}

impl Address {
	pub fn new(
		ark_id: impl Into<ArkId>,
		user_pubkey: PublicKey,
	) -> Address {
		Self::new_v0_pubkey(ark_id, user_pubkey, false)
	}

	pub fn new_testnet(
		ark_id: impl Into<ArkId>,
		user_pubkey: PublicKey,
	) -> Address {
		Self::new_v0_pubkey(ark_id, user_pubkey, true)
	}

	pub fn new_v0_pubkey(
		ark_id: impl Into<ArkId>,
		user_pubkey: PublicKey,
		testnet: bool,
	) -> Address {
		Address {
			testnet: testnet,
			ark_id: ark_id.into(),
			pubkey: user_pubkey,
		}
	}

	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	pub fn ark_id(&self) -> ArkId {
		self.ark_id
	}

	pub fn user_pubkey(&self) -> PublicKey {
		self.pubkey
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let hrp = if self.testnet {
			HRP_TESTNET
		} else {
			HRP_MAINNET
		};

		let ver = VERSION_PUBKEY;
		let payload = self.ark_id.to_byte_array().into_iter()
			.chain(self.pubkey.serialize().into_iter());

		let chars = [ver].into_iter().chain(payload.bytes_to_fes())
			.with_checksum::<bech32::Bech32m>(&hrp)
			.chars();

		// this write code is borrowed from bech32 crate
		const BUF_LENGTH: usize = 128;
		let mut buf = [0u8; BUF_LENGTH];
		let mut pos = 0;
		for c in chars {
			buf[pos] = c as u8;
			pos += 1;

			if pos == BUF_LENGTH {
				let s = core::str::from_utf8(&buf).expect("we only write ASCII");
				f.write_str(s)?;
				pos = 0;
			}
		}

		let s = core::str::from_utf8(&buf[..pos]).expect("we only write ASCII");
		f.write_str(s)?;
		Ok(())
	}
}

impl fmt::Debug for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	    fmt::Display::fmt(self, f)
	}
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum ParseAddressError {
	#[error("bech32m decoding error: {0}")]
	Bech32(bech32::DecodeError),
	#[error("invalid HRP: '{0}'")]
	Hrp(bech32::Hrp),
	#[error("invalid version: '{version}'")]
	UnknownVersion {
		version: bech32::Fe32,
	},
	#[error("invalid address")]
	Invalid(&'static str),
}

impl From<bech32::primitives::decode::UncheckedHrpstringError> for ParseAddressError {
	fn from(e: bech32::primitives::decode::UncheckedHrpstringError) -> Self {
	    Self::Bech32(e.into())
	}
}

impl From<bech32::primitives::decode::ChecksumError> for ParseAddressError {
	fn from(e: bech32::primitives::decode::ChecksumError) -> Self {
	    Self::Bech32(bech32::DecodeError::Checksum(e))
	}
}

/// Fills the entire slice from the iterator.
///
/// Returns an error if there were not enough bytes to fill the slice.
fn slice_from_iter(buf: &mut [u8], iter: &mut impl Iterator<Item = u8>) -> Result<(), ()> {
	for e in buf.iter_mut() {
		*e = iter.next().ok_or(())?;
	}
	Ok(())
}

impl FromStr for Address {
	type Err = ParseAddressError;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let raw = bech32::primitives::decode::UncheckedHrpstring::new(s)?;

		let testnet = if raw.hrp() == HRP_MAINNET {
			false
		} else if raw.hrp() == HRP_TESTNET {
			true
		} else {
			return Err(ParseAddressError::Hrp(raw.hrp()));
		};

		let checked = raw.validate_and_remove_checksum::<bech32::Bech32m>()?;
		// NB this unused generic is fixed in next version of bech32 crate
		let mut iter = checked.fe32_iter::<std::iter::Empty<u8>>();
		let ver = iter.next().ok_or(ParseAddressError::Invalid("empty address"))?;
		let mut bytes = iter.fes_to_bytes();

		if ver != VERSION_PUBKEY {
			return Err(ParseAddressError::UnknownVersion { version: ver });
		}

		let ark_id = {
			let mut buf = [0u8; 4];
			slice_from_iter(&mut buf[..], &mut bytes)
				.map_err(|_| ParseAddressError::Invalid("not enough bytes"))?;
			ArkId(buf)
		};

		let pubkey = {
			let mut buf = [0u8; 33];
			slice_from_iter(&mut buf[..], &mut bytes)
				.map_err(|_| ParseAddressError::Invalid("not enough bytes"))?;
			PublicKey::from_slice(&buf)
				.map_err(|_| ParseAddressError::Invalid("invalid public key"))?
		};

		if !bytes.next().is_none() {
			return Err(ParseAddressError::Invalid("too many bytes"));
		}

		Ok(Address { testnet, ark_id, pubkey })
	}
}


#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_versions() {
		//! because [Fe32] doesn't expose a const from u8 constructor,
		//! we use the character in the definition, but it's annoying that
		//! it requires knowledge of the alphabet to know which numerical value
		//! it has. that's why we enforce it here
		assert_eq!(VERSION_PUBKEY, bech32::Fe32::try_from(0u8).unwrap());
	}

	#[test]
	fn address_roundtrip() {
		let ark = PublicKey::from_str("02037188bdd7579a0cd0b22a51110986df1ea08e30192658fe0e219590e4a723d3").unwrap();
		let usr = PublicKey::from_str("02f4e17f14d87ab6bed46f0b4128428d3d01cd592161b273784e38b50272462c46").unwrap();

		let addr = Address::new(ark, usr);
		let str = addr.to_string();
		assert_eq!(str, "ark1qwh9vsmcz7nsh79xc02mta4r0pdqjss5d85qu6kfpvxe8x7zw8z6syujx93rqu9qmu5");

		println!("{:?}", addr.ark_id);
		let parsed = Address::from_str(&str).unwrap();
		assert_eq!(parsed, addr);

		assert_eq!(parsed.ark_id, ArkId::from_server_pubkey(ark));
		assert_eq!(parsed.pubkey, usr);

		let test = Address::new_testnet(ark, usr);
		let str = test.to_string();
		assert_eq!(str, "tark1qwh9vsmcz7nsh79xc02mta4r0pdqjss5d85qu6kfpvxe8x7zw8z6syujx93rqk0xhc6");
		let parsed = Address::from_str(&str).unwrap();
		assert_eq!(parsed, test);
	}
}
