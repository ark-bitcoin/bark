use std::collections::HashSet;

use bitcoin::{BlockHash, Txid};
use bitcoin_ext::{BlockHeight, BlockRef};
use chrono::{DateTime, Local};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlockData {
	pub block_ref: BlockRef,
	pub prev_hash: BlockHash,
	pub txids: Vec<Txid>,
	pub observed_at: DateTime<Local>,
}

/// Keeps an index of every [BlockRef] that is
/// part of the best chain. The best chain
/// has the most proof of work.
///
/// The index will contain all block hashes from
/// [BlockIndex::first()] until the current tip. Note, that
/// the block index can only support reorgs that happen
/// above [BlockIndex::first()].
///
/// When initializing the [BlockIndex] it is strongly recommended
/// to use a [BlockRef] that is sufficiently deep.
#[derive(Debug, Clone)]
pub struct BlockIndex {
	/// A vector of all blocks known by the header index.
	/// `blocks[i]` corresponds to the block at height `start_height + i`
	blocks: Vec<BlockRef>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlockInsertionError {
	PreviousBlockNotInIndex,
	BeforeStartIndex,
}

impl std::fmt::Display for BlockInsertionError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match &self {
			Self::PreviousBlockNotInIndex => write!(f, "PreviousBlockNotInIndex"),
			Self::BeforeStartIndex => write!(f, "BeforeStartIndex"),
		}
	}
}

impl std::error::Error for BlockInsertionError {
	fn description(&self) -> &str {
		match self {
			Self::PreviousBlockNotInIndex => "Previous block not in index",
			Self::BeforeStartIndex => "Block is before start-index. Reorg to deep"
		}
	}
}

impl BlockIndex {
	pub fn from_base(block: BlockRef) -> Self {
		Self {
			blocks: vec![block],
		}
	}

	pub fn tip(&self) -> BlockRef {
		*self.blocks.last().unwrap()
	}

	pub fn first(&self) -> BlockRef {
		*self.blocks.first().unwrap()
	}

	pub fn get_by_height(&self, height: BlockHeight) -> Option<BlockRef> {
		let first_height = self.first().height;
		if height < first_height {
			None
		} else if height >= first_height + self.blocks.len() as BlockHeight {
			None
		} else {
			let idx = height - first_height;
			let result = self.blocks[idx as usize];
			assert_eq!(result.height, height);
			Some(self.blocks[idx as usize])
		}
	}

	/// Tries to insert a new block to the BlockIndex.
	///
	/// The block will only be inserted if the `prev_hash` is part
	/// of the current index. This will ensure that the index
	/// as a whole will always contain a valid history from `start_index`
	/// to tip().
	///
	/// If a re-org occurs, all blocks that have been reorged out will be returned.
	///
	/// In the other case the reason for refusal is returned.
	pub fn try_insert(
		&mut self,
		block: BlockRef,
		prev_hash: BlockHash,
	) -> Result<(), BlockInsertionError> {
		// If the new block is too early it will be refused
		let first_height = self.first().height;
		if block.height <= first_height  {
			return Err(BlockInsertionError::BeforeStartIndex)
		}

		// If the new block doesn't correctly add on the chan
		// it will be refused
		if block.height > self.tip().height + 1 {
			return Err(BlockInsertionError::PreviousBlockNotInIndex)
		}

		let prev_block = self.get_by_height(block.height -1).expect("Height is in index");
		if prev_block.hash != prev_hash {
			return Err(BlockInsertionError::PreviousBlockNotInIndex)
		}

		// If the block is already indexed we continue
		// like nothing ever happened
		if let Some(indexed_block) = self.get_by_height(block.height) {
			if indexed_block == block {
				return Ok(())
			}
		}

		// Add the new block
		let drain_from = (block.height - first_height) as usize;
		self.blocks.drain(drain_from..);
		self.blocks.push(block);

		Ok(())
	}

	pub fn contains(&self, block_ref: BlockRef) -> bool {
		let first_height = self.first().height;
		if block_ref.height < first_height {
			panic!("We should never hit this code-path")
		}

		match self.get_by_height(block_ref.height) {
			Some(expected_ref) => block_ref == expected_ref,
			None => false,
		}
	}

	pub fn would_accept(&self, block_ref: BlockRef, prev_hash: BlockHash) -> bool {
		let first_height = self.first().height;
		if block_ref.height <= first_height {
			return false
		}

		if block_ref.height > first_height + self.blocks.len() as BlockHeight {
			return false
		}

		let prev_block = self.get_by_height(block_ref.height - 1).expect("Height is in index");
		if prev_block.hash != prev_hash {
			return false
		}

		return true
	}
}


#[cfg(test)]
pub mod test {

	use super::*;

	// The index doesn't really care about validity of the hashes
	pub fn dummy_block(
		fork: u8,
		height: BlockHeight,
	) -> BlockRef {
		let hash = format!("{:02x}000000000000000000000000000000000000000000000000000000{:08x}", fork, height);
		BlockRef {
			height,
			hash: hash.parse().expect("Valid BlockHash"),
		}
	}

	#[test]
	fn test_dummy_block() {
		let dummy = dummy_block(0xFF, 0xABCDEF);

		assert_eq!(dummy.height, 0xABCDEF);
		assert_eq!(
			dummy.hash.to_string(),
			"ff00000000000000000000000000000000000000000000000000000000abcdef",
		);
	}

	#[test]
	fn test_reorg() {
		// This test will do a re-org
		// Define all blocks in the A fork
		let a0 = dummy_block(0x0a, 0);
		let a1 = dummy_block(0x0a, 1);
		let a2 = dummy_block(0x0a, 2);
		let a3 = dummy_block(0x0a, 3);
		let a4 = dummy_block(0x0a, 4);

		// Define transactions in the B fork
		let b3 = dummy_block(0x0b, 3);
		let b4 = dummy_block(0x0b, 4);
		let b5 = dummy_block(0x0b, 5);

		// Create the index and add all blocks
		// from the A-fork
		let mut index = BlockIndex::from_base(a0);
		index.try_insert(a1, a0.hash).expect("Block can be added");
		index.try_insert(a2, a1.hash).expect("Block can be added");
		index.try_insert(a3, a2.hash).expect("Block can be added");
		index.try_insert(a4, a3.hash).expect("Block can be added");

		// Verify that all blocks are in the index
		assert_eq!(index.get_by_height(0).unwrap(), a0);
		assert_eq!(index.get_by_height(1).unwrap(), a1);
		assert_eq!(index.get_by_height(2).unwrap(), a2);
		assert_eq!(index.get_by_height(3).unwrap(), a3);
		assert_eq!(index.get_by_height(4).unwrap(), a4);
		assert_eq!(index.tip(), a4);

		// The B-fork will now be inserted
		// Note, that the tip will be refused
		//
		// The API-user should walk down the chain until
		// it can find a transaction that isn't in the chain
		index.try_insert(b5, b4.hash).expect_err("Block refused");
		index.try_insert(b4, b3.hash).expect_err("Block refused");
		index.try_insert(b3, a2.hash).expect("Accepted");

		// Block a3 and a4 have been forked out of the chain
		assert_eq!(index.tip(), b3, "The tip of the chain is b3");

		// We will verify the current status of the chain
		assert_eq!(index.get_by_height(0), Some(a0));
		assert_eq!(index.get_by_height(1), Some(a1));
		assert_eq!(index.get_by_height(2), Some(a2));
		assert_eq!(index.get_by_height(3), Some(b3));
		assert_eq!(index.get_by_height(4), None);
		assert_eq!(index.tip(), b3);

		// We can now complete the insertion of the full fork of b
		index.try_insert(b4, b3.hash).unwrap();
		index.try_insert(b5, b4.hash).unwrap();

		assert_eq!(index.tip(), b5);

		// Verify that the contains function works correctly
		assert!(index.contains(a0));
		assert!(index.contains(a1));
		assert!(index.contains(a2));
		assert!(index.contains(b3));
		assert!(index.contains(b4));
		assert!(index.contains(b5));

		assert!(! index.contains(a3));
		assert!(! index.contains(a4));
	}

	#[test]
	fn missing_block() {
		// A chain of three transactions
		let a0 = dummy_block(0x0a, 0);
		let a1 = dummy_block(0x0a, 1);
		let a2 = dummy_block(0x0a, 2);

		let mut index = BlockIndex::from_base(a0);
		assert!(!index.would_accept(a2, a1.hash));
		let err = index.try_insert(a2, a1.hash).expect_err("Block should be refused");
		assert_eq!(err, BlockInsertionError::PreviousBlockNotInIndex);
	}

	#[test]
	fn do_not_start_at_zero() {
		let a07 = dummy_block(0x0a, 07);
		let a08 = dummy_block(0x0a, 08);
		let a09 = dummy_block(0x0a, 09);
		let a10 = dummy_block(0x0a, 10);

		let mut index = BlockIndex::from_base(a07);
		index.get_by_height(7).expect("Can query first");
		index.try_insert(a08, a07.hash).expect("Can be inserted");
		index.try_insert(a09, a08.hash).expect("Can be inserted");
		index.try_insert(a10, a09.hash).expect("Can be inserted");

		assert_eq!(index.get_by_height(09).unwrap(), a09);
		assert_eq!(index.get_by_height(10).unwrap(), a10);
	}
}
