
#[cfg(feature = "core_rpc")]
pub mod bitcoin_core;
#[cfg(feature = "esplora_rpc")]
pub mod esplora;

use crate::{BlockHeight, BlockRef};

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
