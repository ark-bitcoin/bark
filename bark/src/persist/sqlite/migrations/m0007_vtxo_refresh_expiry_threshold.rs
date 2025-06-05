use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0007 {}

impl Migration for Migration0007 {

	fn name(&self) -> &str {
		"Rename vtxo_refresh_threshold to vtxo_refresh_expiry_threshold"
	}

	fn to_version(&self) -> i64 { 7 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// We can't use JSONB with rusqlite, so we make do with strings
		let queries = [
			"ALTER TABLE bark_config RENAME COLUMN vtxo_refresh_threshold TO vtxo_refresh_expiry_threshold;",
		];
		for query in queries {
			conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		}
		Ok(())
	}
}
