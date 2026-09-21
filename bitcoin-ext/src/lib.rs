
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde as serde_crate;

pub extern crate bitcoin;

pub mod cpfp;
pub mod fee;

#[cfg(feature = "bdk")]
pub mod bdk;
#[cfg(feature = "rpc")]
pub mod rpc;
pub mod serde;

pub use mbitcoin::{
	AddressExt, AmountExt, FeeRateExt, NonStandardOutput, TaprootSpendInfoExt, KeypairExt,
	TransactionExt, TxOutExt,
};

#[path = "bitcoin.rs"]
mod mbitcoin;

use std::{fmt, ops, str::FromStr};

use bitcoin::{absolute, Amount, BlockHash, Sequence, Weight};

use serde_crate::ser::SerializeStruct;

/// The number of confirmations after which we don't expect a
/// re-org to ever happen.
pub const DEEPLY_CONFIRMED: BlockDelta = BlockDelta::new(100);

pub const P2TR_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2TR_DUST_SAT: u64 = P2TR_DUST_VB * 3;
pub const P2TR_DUST: Amount = Amount::from_sat(P2TR_DUST_SAT);

pub const P2WPKH_DUST_VB: u64 = 90;
/// 294 satoshis
pub const P2WPKH_DUST_SAT: u64 = P2WPKH_DUST_VB * 3;
pub const P2WPKH_DUST: Amount = Amount::from_sat(P2WPKH_DUST_SAT);

pub const P2PKH_DUST_VB: u64 = 182;
/// 546 satoshis
pub const P2PKH_DUST_SAT: u64 = P2PKH_DUST_VB * 3;
pub const P2PKH_DUST: Amount = Amount::from_sat(P2PKH_DUST_SAT);

pub const P2SH_DUST_VB: u64 = 180;
/// 540 satoshis
pub const P2SH_DUST_SAT: u64 = P2SH_DUST_VB * 3;
pub const P2SH_DUST: Amount = Amount::from_sat(P2SH_DUST_SAT);

pub const P2WSH_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2WSH_DUST_SAT: u64 = P2WSH_DUST_VB * 3;
pub const P2WSH_DUST: Amount = Amount::from_sat(P2WSH_DUST_SAT);

/// Witness weight of a taproot keyspend.
pub const TAPROOT_KEYSPEND_WEIGHT: Weight = Weight::from_wu(66);

/// The maximum standard tx weight
pub const MAX_TX_WEIGHT: Weight = Weight::from_wu(400_000);

/// Type representing a block height in the bitcoin blockchain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlockHeight(u32);

impl BlockHeight {
	/// The height of the genesis block.
	pub const ZERO: BlockHeight = BlockHeight(0);

	/// The maximum representable block height.
	pub const MAX: BlockHeight = BlockHeight(u32::MAX);

	/// Create a block height.
	pub const fn new(height: u32) -> BlockHeight {
		BlockHeight(height)
	}

	/// The height as a primitive integer.
	pub const fn to_u32(self) -> u32 {
		self.0
	}

	/// Add a delta to the height, saturating at [u32::MAX].
	///
	/// Also available as the `+` operator.
	pub fn add_delta(self, delta: BlockDelta) -> BlockHeight {
		BlockHeight(self.0.saturating_add(delta.to_u32()))
	}

	/// Add a delta to the height, returning [None] on overflow.
	pub fn checked_add(self, delta: BlockDelta) -> Option<BlockHeight> {
		self.0.checked_add(delta.to_u32()).map(BlockHeight)
	}

	/// Subtract another height from this one, returning the difference
	/// as a delta. Returns [None] on underflow or when the difference
	/// doesn't fit in a delta.
	pub fn checked_sub(self, other: BlockHeight) -> Option<BlockDelta> {
		self.0.checked_sub(other.0).and_then(|d| BlockDelta::try_from(d).ok())
	}

	/// The number of blocks from `other` up to this height,
	/// returning [None] if `other` is higher.
	pub fn checked_blocks_since(self, other: BlockHeight) -> Option<u32> {
		self.0.checked_sub(other.0)
	}

	/// Subtract a delta from the height, saturating at zero.
	pub fn saturating_sub(self, delta: BlockDelta) -> BlockHeight {
		BlockHeight(self.0.saturating_sub(delta.to_u32()))
	}

	/// The height as an absolute locktime.
	///
	/// Errors if the height exceeds [bitcoin::absolute::LOCK_TIME_THRESHOLD].
	pub fn to_locktime(self) -> Result<absolute::LockTime, absolute::ConversionError> {
		absolute::LockTime::from_height(self.0)
	}
}

impl fmt::Display for BlockHeight {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self.0, f)
	}
}

impl FromStr for BlockHeight {
	type Err = std::num::ParseIntError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(BlockHeight(s.parse()?))
	}
}

impl From<u32> for BlockHeight {
	fn from(v: u32) -> BlockHeight {
		BlockHeight(v)
	}
}

impl From<BlockHeight> for u32 {
	fn from(v: BlockHeight) -> u32 {
		v.0
	}
}

impl From<BlockHeight> for u64 {
	fn from(v: BlockHeight) -> u64 {
		v.0 as u64
	}
}

impl From<BlockHeight> for i64 {
	fn from(v: BlockHeight) -> i64 {
		v.0 as i64
	}
}

impl TryFrom<u64> for BlockHeight {
	type Error = std::num::TryFromIntError;

	fn try_from(v: u64) -> Result<BlockHeight, Self::Error> {
		Ok(BlockHeight(u32::try_from(v)?))
	}
}

impl TryFrom<i64> for BlockHeight {
	type Error = std::num::TryFromIntError;

	fn try_from(v: i64) -> Result<BlockHeight, Self::Error> {
		Ok(BlockHeight(u32::try_from(v)?))
	}
}

impl TryFrom<i32> for BlockHeight {
	type Error = std::num::TryFromIntError;

	fn try_from(v: i32) -> Result<BlockHeight, Self::Error> {
		Ok(BlockHeight(u32::try_from(v)?))
	}
}

/// Add a delta to the height, saturating at [u32::MAX].
impl ops::Add<BlockDelta> for BlockHeight {
	type Output = BlockHeight;

	fn add(self, rhs: BlockDelta) -> BlockHeight {
		self.add_delta(rhs)
	}
}

/// Type representing a difference between two block heights.
///
/// A delta fits in a u16, so that it can be used in a relative timelock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "u16", into = "u16")]
pub struct BlockDelta(u16);

impl BlockDelta {
	/// The zero delta.
	pub const ZERO: BlockDelta = BlockDelta(0);

	/// The maximum representable block delta.
	pub const MAX: BlockDelta = BlockDelta(u16::MAX);

	/// Create a block delta.
	pub const fn new(delta: u16) -> BlockDelta {
		BlockDelta(delta)
	}

	/// The delta as a primitive integer.
	pub const fn to_u16(self) -> u16 {
		self.0
	}

	/// The delta as a primitive integer.
	pub const fn to_u32(self) -> u32 {
		self.0 as u32
	}

	/// Add two deltas, returning [None] on overflow.
	pub fn checked_add(self, other: BlockDelta) -> Option<BlockDelta> {
		self.0.checked_add(other.0).map(BlockDelta)
	}

	/// Subtract a delta from this one, returning [None] on underflow.
	pub fn checked_sub(self, other: BlockDelta) -> Option<BlockDelta> {
		self.0.checked_sub(other.0).map(BlockDelta)
	}

	/// Subtract a delta from this one, saturating at zero.
	pub fn saturating_sub(self, other: BlockDelta) -> BlockDelta {
		BlockDelta(self.0.saturating_sub(other.0))
	}
}

impl fmt::Display for BlockDelta {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self.0, f)
	}
}

impl FromStr for BlockDelta {
	type Err = std::num::ParseIntError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(BlockDelta::new(s.parse::<u16>()?))
	}
}

impl From<u16> for BlockDelta {
	fn from(v: u16) -> BlockDelta {
		BlockDelta::new(v)
	}
}

/// The delta as a relative timelock of the same number of blocks.
impl From<BlockDelta> for Sequence {
	fn from(v: BlockDelta) -> Sequence {
		Sequence::from_height(v.0)
	}
}

impl From<BlockDelta> for u16 {
	fn from(v: BlockDelta) -> u16 {
		v.0
	}
}

impl From<BlockDelta> for u32 {
	fn from(v: BlockDelta) -> u32 {
		v.0 as u32
	}
}

impl From<BlockDelta> for u64 {
	fn from(v: BlockDelta) -> u64 {
		v.0 as u64
	}
}

impl From<BlockDelta> for i64 {
	fn from(v: BlockDelta) -> i64 {
		v.0 as i64
	}
}

impl TryFrom<u32> for BlockDelta {
	type Error = std::num::TryFromIntError;

	fn try_from(v: u32) -> Result<BlockDelta, Self::Error> {
		Ok(BlockDelta::new(u16::try_from(v)?))
	}
}

impl TryFrom<u64> for BlockDelta {
	type Error = std::num::TryFromIntError;

	fn try_from(v: u64) -> Result<BlockDelta, Self::Error> {
		Ok(BlockDelta::new(u16::try_from(v)?))
	}
}

impl TryFrom<i64> for BlockDelta {
	type Error = std::num::TryFromIntError;

	fn try_from(v: i64) -> Result<BlockDelta, Self::Error> {
		Ok(BlockDelta::new(u16::try_from(v)?))
	}
}

impl TryFrom<i32> for BlockDelta {
	type Error = std::num::TryFromIntError;

	fn try_from(v: i32) -> Result<BlockDelta, Self::Error> {
		Ok(BlockDelta::new(u16::try_from(v)?))
	}
}

/// Add two deltas, saturating at [u16::MAX].
impl ops::Add for BlockDelta {
	type Output = BlockDelta;

	fn add(self, rhs: BlockDelta) -> BlockDelta {
		BlockDelta(self.0.saturating_add(rhs.0))
	}
}

/// Multiply the delta, saturating at [u16::MAX].
impl ops::Mul<usize> for BlockDelta {
	type Output = BlockDelta;

	fn mul(self, rhs: usize) -> BlockDelta {
		let mul = usize::from(self.0).checked_mul(rhs).unwrap_or(usize::MAX);
		BlockDelta(u16::try_from(mul).unwrap_or(u16::MAX))
	}
}
/// Reference to a block in the chain
///
/// String representation is `<height>:<hash>`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockRef {
	pub height: BlockHeight,
	pub hash: BlockHash,
}

impl fmt::Display for BlockRef {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}:{}", self.height, self.hash)
	}
}

impl fmt::Debug for BlockRef {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl FromStr for BlockRef {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut parts = s.splitn(2, ':');
		Ok(BlockRef {
			height: parts.next().expect("always one part")
				.parse().map_err(|_| "invalid height")?,
			hash: parts.next().ok_or("should be <height>:<hash> string")?
				.parse().map_err(|_| "invalid hash")?,
		})
	}
}

impl serde_crate::Serialize for BlockRef {
	fn serialize<S: serde_crate::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		let mut state = s.serialize_struct("BlockRef", 2)?;
		state.serialize_field("height", &self.height)?;
		state.serialize_field("hash", &self.hash)?;
		state.end()
	}
}

impl<'de> serde_crate::Deserialize<'de> for BlockRef {
	fn deserialize<D: serde_crate::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde_crate::de::Visitor<'de> for Visitor {
			type Value = BlockRef;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a BlockRef (struct/string)")
			}
			fn visit_str<E: serde_crate::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				BlockRef::from_str(v).map_err(serde_crate::de::Error::custom)
			}
			fn visit_map<A: serde_crate::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
				let mut height = None;
				let mut hash = None;
				while let Some(key) = map.next_key::<&str>()? {
					match key {
						"height" => height = Some(map.next_value()?),
						"hash" => hash = Some(map.next_value()?),
						_ => {
							let _ = map.next_value::<serde_crate::de::IgnoredAny>()?;
						}
					}
				}
				Ok(BlockRef {
					height: height.ok_or_else(|| serde_crate::de::Error::missing_field("height"))?,
					hash: hash.ok_or_else(|| serde_crate::de::Error::missing_field("hash"))?,
				})
			}
		}
		d.deserialize_any(Visitor)
	}
}

#[cfg(feature = "bdk")]
impl From<bdk_wallet::chain::BlockId> for BlockRef {
	fn from(id: bdk_wallet::chain::BlockId) -> Self {
		Self {
			height: BlockHeight::new(id.height),
			hash: id.hash,
		}
	}
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
	Confirmed(BlockRef),
	Mempool,
	NotFound,
}

impl TxStatus {
	pub fn is_confirmed(&self) -> bool {
		match self {
			TxStatus::Confirmed(_) => true,
			_ => false,
		}
	}

	pub fn confirmed_height(&self) -> Option<BlockHeight> {
		match self {
			TxStatus::Confirmed(block_ref) => Some(block_ref.height),
			_ => None,
		}
	}

	pub fn confirmed_in(&self) -> Option<BlockRef> {
		match self {
			TxStatus::Confirmed(block_ref) => Some(*block_ref),
			_ => None,
		}
	}

	pub fn is_known(&self) -> bool {
		match self {
			TxStatus::Confirmed(..) | TxStatus::Mempool => true,
			TxStatus::NotFound => false,
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn tx_status_is_known() {
		let block = BlockRef {
			height: BlockHeight::new(42),
			hash: "000000000000000000024e0e2d3a1b03bb6e39b1e79b3b4b6e30e7bd39cd6f6f"
				.parse().unwrap(),
		};
		// A tx we can see, confirmed or not, is known.
		assert!(TxStatus::Confirmed(block).is_known());
		assert!(TxStatus::Mempool.is_known());
		// Only a tx we've never seen isn't.
		assert!(!TxStatus::NotFound.is_known());
	}
}

