use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0013 {}

impl Migration for Migration0013 {

	fn name(&self) -> &str {
		"Create table to keep track of rounds"
	}

	fn to_version(&self) -> i64 { 13 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"DROP TABLE bark_ark_sync",
			"CREATE TABLE IF NOT EXISTS bark_synced_round (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				round_txid TEXT,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
		];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}

