
#[macro_use] extern crate lazy_static;
extern crate bitcoin as cbitcoin;

mod bitcoin;
pub mod fee;
pub mod rpc;
#[cfg(feature = "bdk")]
pub mod bdk;

use std::fmt;

#[cfg(feature = "bdk")]
use bdk_wallet::chain::BlockId;
pub use bitcoin::{AmountExt, FeeRateExt, TaprootSpendInfoExt, KeypairExt, TransactionExt, TxOutExt};
use cbitcoin::{Amount, BlockHash};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
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
impl From<BlockId> for BlockRef {
	fn from(id: BlockId) -> Self {
		Self {
			height: id.height,
			hash: id.hash,
		}
	}
}
