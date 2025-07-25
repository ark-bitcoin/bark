use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0009 {}

impl Migration for Migration0009 {

	fn name(&self) -> &str {
		"Add kind column to bark_movement"
	}

	fn to_version(&self) -> i64 { 9 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"ALTER TABLE bark_movement ADD COLUMN kind TEXT NOT NULL;",
		];
		for query in queries {
			conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		}
		Ok(())
	}
}
