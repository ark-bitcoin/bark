use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0014 {}

impl Migration for Migration0014 {

	fn name(&self) -> &str {
		"drop last round synced"
	}

	fn to_version(&self) -> i64 { 14 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"DROP TABLE bark_synced_round",
		];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}


