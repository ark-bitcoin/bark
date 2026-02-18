use anyhow::Context;
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::database::Db;

/// Identifies which process's block table to use.
///
/// Each process (captaind, watchmand) maintains its own independent block tracking
/// table to ensure that blocks inserted by one process don't affect the sync state
/// of another process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTable {
	Captaind,
	Watchmand,
}

impl BlockTable {
	/// Returns the SQL table name for this block table.
	///
	/// This is the only way to get a table name, ensuring SQL injection safety.
	fn as_str(&self) -> &'static str {
		match self {
			BlockTable::Captaind => "captaind_block",
			BlockTable::Watchmand => "watchmand_block",
		}
	}
}

impl Db {

	/// Stores a block reference (height and hash) in the database.
	///
	/// This is used by the block index to persist synced blocks.
	///
	/// # Errors
	///
	/// Returns an error if a block with the same height already exists,
	/// since height is the primary key.
	pub async fn store_block(&self, table: BlockTable, block: &BlockRef) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let query = format!(
			"INSERT INTO {} (height, hash) VALUES ($1, $2)",
			table.as_str()
		);
		let stmt = conn.prepare(&query).await?;

		conn.execute(&stmt, &[&(block.height as i64), &block.hash.to_string()]).await?;

		Ok(())
	}

	/// Removes all blocks with height strictly greater than the given height.
	///
	/// This is used during chain reorganizations to remove orphaned blocks
	/// that are no longer part of the best chain.
	pub async fn remove_blocks_above(&self, table: BlockTable, height: BlockHeight) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let query = format!(
			"DELETE FROM {} WHERE height > $1",
			table.as_str()
		);
		let stmt = conn.prepare(&query).await?;

		conn.execute(&stmt, &[&(height as i64)]).await?;
		Ok(())
	}

	/// Returns the block at the given height, if one exists.
	pub async fn get_block_by_height(&self, table: BlockTable, height: BlockHeight) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let query = format!(
			"SELECT hash FROM {} WHERE height = $1",
			table.as_str()
		);
		let stmt = conn.prepare(&query).await?;

		match conn.query_opt(&stmt, &[&(height as i64)]).await? {
			Some(row) => {
				let hash: &str = row.get::<_, &str>("hash");

				let hash = hash.parse().context("invalid block hash")?;
				Ok(Some(BlockRef { height, hash }))
			},
			None => Ok(None),
		}
	}

	pub async fn get_highest_block(&self, table: BlockTable) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let query = format!(
			"SELECT height, hash FROM {} ORDER BY height DESC LIMIT 1",
			table.as_str()
		);
		let stmt = conn.prepare(&query).await?;

		match conn.query_opt(&stmt, &[]).await? {
			Some(row) => {
				let height = row.get::<_, i64>("height") as BlockHeight;
				let hash= row.get::<_, &str>("hash");

				let hash = hash.parse().context("invalid block hash")?;
				Ok(Some(BlockRef { height, hash }))
			},
			None => Ok(None),
		}
	}

	/// Returns the block with the lowest height, if any blocks exist.
	pub async fn get_lowest_block(&self, table: BlockTable) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let query = format!(
			"SELECT height, hash FROM {} ORDER BY height ASC LIMIT 1",
			table.as_str()
		);
		let stmt = conn.prepare(&query).await?;

		match conn.query_opt(&stmt, &[]).await? {
			Some(row) => {
				let height = row.get::<_, i64>("height") as BlockHeight;
				let hash = row.get::<_, &str>("hash");
				let hash = hash.parse().context("invalid block hash")?;
				Ok(Some(BlockRef { height, hash }))
			}
			None => Ok(None),
		}
	}
}
