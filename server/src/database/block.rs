use anyhow::Context;
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::database::Db;

impl Db {

	/// Stores a block reference (height and hash) in the database.
	///
	/// This is used by the block index to persist synced blocks.
	///
	/// # Errors
	///
	/// Returns an error if a block with the same height already exists,
	/// since height is the primary key.
	pub async fn store_block(&self, block: &BlockRef) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare("
			INSERT INTO block (height, hash) VALUES ($1, $2)
		").await?;

		conn.execute(&stmt, &[&(block.height as i64), &block.hash.to_string()]).await?;

		Ok(())
	}

	/// Removes all blocks with height strictly greater than the given height.
	///
	/// This is used during chain reorganizations to remove orphaned blocks
	/// that are no longer part of the best chain.
	pub async fn remove_blocks_above(&self, height: BlockHeight) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare("
			DELETE FROM block WHERE height > $1
		").await?;

		conn.execute(&stmt, &[&(height as i64)]).await?;
		Ok(())
	}

	/// Returns the block at the given height, if one exists.
	pub async fn get_block_by_height(&self, height: BlockHeight) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare(
			"SELECT hash FROM block WHERE height = $1"
		).await?;

		match conn.query_opt(&stmt, &[&(height as i64)]).await? {
			Some(row) => {
				let hash: &str = row.get::<_, &str>("hash");

				let hash = hash.parse().context("invalid block hash")?;
				Ok(Some(BlockRef { height, hash }))
			},
			None => Ok(None),
		}
	}

	pub async fn get_highest_block(&self) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare(
			"SELECT height, hash FROM block ORDER BY height DESC LIMIT 1"
		).await?;

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
	pub async fn get_lowest_block(&self) -> anyhow::Result<Option<BlockRef>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare(
			"SELECT height, hash FROM block ORDER BY height ASC LIMIT 1"
		).await?;

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
