
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde;
pub extern crate bitcoin;

pub mod cpfp;
pub mod fee;

#[cfg(feature = "bdk")]
pub mod bdk;
#[cfg(feature = "esplora")]
pub mod esplora;
#[cfg(feature = "rpc")]
pub mod rpc;

pub use mbitcoin::{
	AmountExt, FeeRateExt, TaprootSpendInfoExt, KeypairExt, TransactionExt, TxOutExt,
};

#[path = "bitcoin.rs"]
mod mbitcoin;

use std::fmt;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockRef {
	pub height: BlockHeight,
	pub hash: BlockHash,
}

impl fmt::Display for BlockRef {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Debug::fmt(self, f)
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

