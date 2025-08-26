
use std::{fmt, io};
use std::str::FromStr;

use bitcoin::bech32::{self, ByteIterExt, Fe32IterExt};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;

use crate::{ProtocolDecodingError, ProtocolEncoding, VtxoPolicy};
use crate::encode::{ReadExt, WriteExt};


/// The human-readable part for mainnet addresses
const HRP_MAINNET: bech32::Hrp = bech32::Hrp::parse_unchecked("ark");

/// The human-readable part for test addresses
const HRP_TESTNET: bech32::Hrp = bech32::Hrp::parse_unchecked("tark");

/// Address version 0 used for addressing in Arkade.
const VERSION_ARKADE: bech32::Fe32 = bech32::Fe32::Q;

/// Address version 1 used for policy addressing in bark.
const VERSION_POLICY: bech32::Fe32 = bech32::Fe32::P;


/// Identifier for an Ark server as used in addresses
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArkId([u8; 4]);
impl_byte_newtype!(ArkId, 4);

impl ArkId {
	/// Create a new [ArkId] from a server pubkey
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

/// Mechanism to deliver a VTXO to a user
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum VtxoDelivery {
	/// Use the built-in VTXO mailbox of the Ark server
	ServerBuiltin,
	Unknown {
		delivery_type: u8,
		data: Vec<u8>,
	},
}

/// The type byte for the "server built-in" delivery mechanism
const DELIVERY_BUILTIN: u8 = 0x00;

impl VtxoDelivery {
	/// Returns whether the VTXO delivery type is unknown
	pub fn is_unknown(&self) -> bool {
		match self {
			Self::Unknown { .. } => true,
			_ => false,
		}
	}

	/// The number of bytes required to encode this delivery
	fn encoded_length(&self) -> usize {
		match self {
			Self::ServerBuiltin => 1,
			Self::Unknown { data, .. } => 1 + data.len(),
		}
	}

	fn encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::ServerBuiltin => {
				w.emit_u8(DELIVERY_BUILTIN)?;
			},
			Self::Unknown { delivery_type, ref data } => {
				w.emit_u8(*delivery_type)?;
				w.emit_slice(data)?;
			},
		}
		Ok(())
	}

	fn decode(payload: &[u8]) -> Result<Self, ParseAddressError> {
		if payload.is_empty() {
			return Err(ParseAddressError::Eof);
		}

		match payload[0] {
			DELIVERY_BUILTIN => Ok(Self::ServerBuiltin),
			delivery_type => Ok(Self::Unknown {
				delivery_type: delivery_type,
				data: payload[1..].to_vec(),
			}),
		}
	}
}

/// An Ark address
///
/// Used to address VTXO payments in an Ark.
///
/// Example usage:
/// ```
/// let srv_pubkey = "03d2e3205d9fd8fb2d441e9c3aa5e28ac895f7aae68c209ae918e2750861e8ffc1".parse().unwrap();
/// let vtxo_pubkey = "035c4def84a9883afe60ef72b37aaf8038dd74ed3d0ab1a1f30610acccd68d1cdd".parse().unwrap();
///
/// let addr = ark::Address::builder()
/// 	.server_pubkey(srv_pubkey)
/// 	.pubkey_policy(vtxo_pubkey)
/// 	.into_address().unwrap();
///
/// assert_eq!(addr.to_string(),
/// 	"ark1pndckx4ezqqp4cn00sj5cswh7vrhh9vm647qr3ht5a57s4vdp7vrpptxv66x3ehgpqqnevf3z",
/// );
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
	testnet: bool,
	ark_id: ArkId,
	policy: VtxoPolicy,
	delivery: Vec<VtxoDelivery>,
}

impl Address {
	/// Start building an [Address]
	pub fn builder() -> Builder {
		Builder::new()
	}

	/// Create a new [Address]
	///
	/// Note that it might be more convenient to use [Address::builder] instead.
	pub fn new(
		testnet: bool,
		ark_id: impl Into<ArkId>,
		policy: VtxoPolicy,
		delivery: Vec<VtxoDelivery>,
	) -> Address {
		Address {
			testnet: testnet,
			ark_id: ark_id.into(),
			policy: policy,
			delivery: delivery,
		}
	}

	/// Whether or not this [Address] is intended to be used in a test network
	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	/// The [ArkId] of the Ark in which the user wants to be paid
	pub fn ark_id(&self) -> ArkId {
		self.ark_id
	}

	/// Check whether this [Address] matches the given server pubkey
	pub fn is_for_server(&self, server_pubkey: PublicKey) -> bool {
		self.ark_id().is_for_server(server_pubkey)
	}

	/// The VTXO policy the user wants to be paid in
	pub fn policy(&self) -> &VtxoPolicy {
		&self.policy
	}

	/// The different VTXO delivery options provided by the user
	pub fn delivery(&self) -> &[VtxoDelivery] {
		&self.delivery
	}

	/// Write the address payload to the writer
	pub fn encode_payload<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		writer.emit_slice(&self.ark_id.to_byte_array())?;

		// NB our ProtocolEncoding system is not designed to encode unknown types.
		// Therefore we have to do something a little unusual to know the sizes of
		// our subfields here.

		let mut buf = Vec::with_capacity(128); // enough to hold any policy currently
		self.policy.encode(&mut buf)?;
		writer.emit_compact_size(buf.len() as u64)?;
		writer.emit_slice(&buf[..])?;

		for delivery in &self.delivery {
			writer.emit_compact_size(delivery.encoded_length() as u64)?;
			delivery.encode(writer)?;
		}

		Ok(())
	}

	/// Read the address payload from the byte iterator
	///
	/// Returns an address straight away given the testnet indicator.
	pub fn decode_payload(
		testnet: bool,
		bytes: impl Iterator<Item = u8>,
	) -> Result<Address, ParseAddressError> {
		let mut peekable = bytes.peekable();
		let mut reader = ByteIter(&mut peekable);

		let ark_id = {
			let mut buf = [0u8; 4];
			reader.read_slice(&mut buf).map_err(|_| ParseAddressError::Eof)?;
			ArkId(buf)
		};

		let mut buf = Vec::new();
		let policy = {
			let len = reader.read_compact_size()? as usize;
			buf.resize(len, 0);
			reader.read_slice(&mut buf[..])?;
			VtxoPolicy::deserialize(&buf[..]).map_err(ParseAddressError::VtxoPolicy)?
		};

		let mut delivery = Vec::new();
		while reader.0.peek().is_some() {
			let len = reader.read_compact_size()? as usize;
			buf.resize(len, 0);
			reader.read_slice(&mut buf[..])?;
			delivery.push(VtxoDelivery::decode(&buf[..])?);
		}

		Ok(Address::new(testnet, ark_id, policy, delivery))
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let hrp = if self.testnet {
			HRP_TESTNET
		} else {
			HRP_MAINNET
		};

		let ver = VERSION_POLICY;
		let payload = {
			let mut buf = Vec::with_capacity(128);
			self.encode_payload(&mut buf).expect("buffers don't error");
			buf
		};

		let chars = [ver].into_iter().chain(payload.into_iter().bytes_to_fes())
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

/// Error parsing an [Address]
#[derive(Debug, thiserror::Error)]
pub enum ParseAddressError {
	#[error("bech32m decoding error: {0}")]
	Bech32(bech32::DecodeError),
	#[error("invalid HRP: '{0}'")]
	Hrp(bech32::Hrp),
	#[error("address ins an Arkade address and cannot be used here")]
	Arkade,
	#[error("unknown version: '{version}'")]
	UnknownVersion {
		version: bech32::Fe32,
	},
	#[error("invalid encoding: unexpected end of bytes")]
	Eof,
	#[error("invalid or unknown VTXO policy")]
	VtxoPolicy(ProtocolDecodingError),
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

impl From<io::Error> for ParseAddressError {
	fn from(e: io::Error) -> Self {
		match e.kind() {
			io::ErrorKind::UnexpectedEof => ParseAddressError::Eof,
			io::ErrorKind::InvalidData => ParseAddressError::Invalid("invalid encoding"),
			// these should never happen but in order to be safe, we catch them
			_ => {
				if cfg!(debug_assertions) {
					panic!("unexpected I/O error while parsing address: {}", e);
				}
				ParseAddressError::Invalid("unexpected I/O error")
			},
		}
	}
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

		match ver {
			VERSION_POLICY => {},
			VERSION_ARKADE => return Err(ParseAddressError::Arkade),
			_ => return Err(ParseAddressError::UnknownVersion { version: ver }),
		}

		Address::decode_payload(testnet, iter.fes_to_bytes())
	}
}

/// Error while building an [Address] using [Builder]
#[derive(Clone, Debug, thiserror::Error)]
#[error("error building address: {msg}")]
pub struct AddressBuilderError {
	msg: &'static str,
}

impl From<&'static str> for AddressBuilderError {
	fn from(msg: &'static str) -> Self {
	    AddressBuilderError { msg }
	}
}

/// Builder used to create [Address] instances
///
/// By default, when no VTXO delivery mechanism is provided by the user,
/// the builder will add the built-in [VtxoDelivery::ServerBuiltin].
/// To prevent this, use [Builder::no_delivery].
#[derive(Debug)]
pub struct Builder {
	testnet: bool,
	ark_id: Option<ArkId>,
	policy: Option<VtxoPolicy>,
	delivery: Vec<VtxoDelivery>,
	/// Do not add default built-in delivery when no delivery is sets.
	no_delivery: bool,
}

impl Builder {
	/// Create a new [Builder]
	pub fn new() -> Self {
		Self {
			testnet: false,
			ark_id: None,
			policy: None,
			delivery: Vec::new(),
			no_delivery: false,
		}
	}

	/// Set the address to be used for test networks
	///
	/// Default is false.
	pub fn testnet(mut self, testnet: bool) -> Self {
		self.testnet = testnet;
		self
	}

	/// Set the Ark server pubkey
	pub fn server_pubkey(mut self, server_pubkey: PublicKey) -> Self {
		self.ark_id = Some(ArkId::from_server_pubkey(server_pubkey));
		self
	}

	/// Set the VTXO policy
	pub fn policy(mut self, policy: VtxoPolicy) -> Self {
		self.policy = Some(policy);
		self
	}

	/// Set the VTXO policy to [VtxoPolicy::PublicKey]
	pub fn pubkey_policy(self, user_pubkey: PublicKey) -> Self {
		self.policy(VtxoPolicy::new_pubkey(user_pubkey))
	}

	/// Add the given delivery method
	pub fn delivery(mut self, delivery: VtxoDelivery) -> Self {
		self.delivery.push(delivery);
		self
	}

	/// Prevent the builder from adding the built-in delivery when no delivery is set.
	pub fn no_delivery(mut self) -> Self {
		self.no_delivery = true;
		self
	}

	/// Finish by building an [Address]
	pub fn into_address(self) -> Result<Address, AddressBuilderError> {
		Ok(Address {
			testnet: self.testnet,
			ark_id: self.ark_id.ok_or("missing ark_id")?,
			policy: self.policy.ok_or("missing policy")?,
			delivery: if self.delivery.is_empty() && !self.no_delivery {
				vec![VtxoDelivery::ServerBuiltin]
			} else {
				self.delivery
			},
		})
	}
}

/// Simple wrapper to implement [io::Read] for a byte iterator.
struct ByteIter<T>(T);

impl<T: Iterator<Item = u8>> io::Read for ByteIter<T> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let mut written = 0;
		for e in buf.iter_mut() {
			if let Some(n) = self.0.next() {
				*e = n;
				written += 1;
			} else {
				break;
			}
		}
		Ok(written)
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
		assert_eq!(VERSION_POLICY, bech32::Fe32::try_from(1u8).unwrap());
	}

	fn test_roundtrip(addr: &Address) -> Address {
		let parsed = Address::from_str(&addr.to_string()).unwrap();
		assert_eq!(parsed, *addr);
		parsed
	}

	#[test]
	fn address_roundtrip() {
		let ark = PublicKey::from_str("02037188bdd7579a0cd0b22a51110986df1ea08e30192658fe0e219590e4a723d3").unwrap();
		let ark_id = ArkId::from_server_pubkey(ark);
		let usr = PublicKey::from_str("032217b6ccba4fa98cc433abe4be1ceaf41ea61fd83fcefd27384ca4612ce19512").unwrap();
		println!("ark pk: {} (id {})", ark, ark_id);
		println!("usr pk: {}", usr);
		let policy = VtxoPolicy::new_pubkey(usr);

		// no delivery
		let addr = Address::builder()
			.server_pubkey(ark)
			.pubkey_policy(usr)
			.into_address().unwrap();
		assert_eq!(addr.to_string(), "ark1pwh9vsmezqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2yspqqjl5wpy");

		let parsed = test_roundtrip(&addr);
		assert_eq!(parsed.ark_id, ark_id);
		assert_eq!(parsed.policy, policy);
		assert_eq!(parsed.delivery.len(), 1);

		// built-in delivery
		let addr = Address::builder()
			.testnet(true)
			.server_pubkey(ark)
			.pubkey_policy(usr)
			.no_delivery()
			.into_address().unwrap();
		assert_eq!(addr.to_string(), "tark1pwh9vsmezqqpjy9akejayl2vvcse6he97rn40g84xrlvrlnhayuuyefrp9nse2ysm2x4mn");

		let parsed = test_roundtrip(&addr);
		assert_eq!(parsed.ark_id, ArkId::from_server_pubkey(ark));
		assert_eq!(parsed.policy, policy);
		assert_eq!(parsed.delivery.len(), 0);
	}
}
