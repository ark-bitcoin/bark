use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0008 {}

impl Migration for Migration0008 {

	fn name(&self) -> &str {
		"Add fallback_fee column to bark_config"
	}

	fn to_version(&self) -> i64 { 8 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"ALTER TABLE bark_config ADD COLUMN fallback_fee_kwu INTEGER;",
		];
		for query in queries {
			conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		}
		Ok(())
	}
}
