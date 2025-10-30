
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde as serde_crate;

pub extern crate bitcoin;

pub mod cpfp;
pub mod fee;

#[cfg(feature = "bdk")]
pub mod bdk;
#[cfg(feature = "esplora")]
pub mod esplora;
#[cfg(feature = "rpc")]
pub mod rpc;
pub mod serde;

pub use mbitcoin::{
	AmountExt, FeeRateExt, TaprootSpendInfoExt, KeypairExt, TransactionExt, TxOutExt,
};

#[path = "bitcoin.rs"]
mod mbitcoin;

use std::{fmt, str::FromStr};

use bitcoin::{Amount, BlockHash};

/// The number of confirmations after which we don't expect a
/// re-org to ever happen.
pub const DEEPLY_CONFIRMED: BlockHeight = 100;

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
pub const TAPROOT_KEYSPEND_WEIGHT: usize = 66;

/// Type representing a block height in the bitcoin blockchain.
pub type BlockHeight = u32;
/// Type representing a block height delta
pub type BlockDelta = u16;
/// Reference to a block in the chain
///
/// String representation is "<height>:<hash>".
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
		s.collect_str(self)
	}
}

impl<'de> serde_crate::Deserialize<'de> for BlockRef {
	fn deserialize<D: serde_crate::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct Visitor;
		impl<'de> serde_crate::de::Visitor<'de> for Visitor {
			type Value = BlockRef;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "a BlockRef")
			}
			fn visit_str<E: serde_crate::de::Error>(self, v: &str) -> Result<Self::Value, E> {
				BlockRef::from_str(v).map_err(serde_crate::de::Error::custom)
			}
		}
		d.deserialize_str(Visitor)
	}
}

#[cfg(feature = "bdk")]
impl From<bdk_wallet::chain::BlockId> for BlockRef {
	fn from(id: bdk_wallet::chain::BlockId) -> Self {
		Self {
			height: id.height,
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
}

