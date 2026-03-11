
use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0026 {}

impl Migration for Migration0026 {
	fn name(&self) -> &str {
		"pending offboard tracking"
	}

	fn to_version(&self) -> i64 { 26 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE bark_pending_offboard (
				movement_id INTEGER PRIMARY KEY,
				offboard_txid TEXT NOT NULL,
				offboard_tx BLOB NOT NULL,
				vtxo_ids TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				destination TEXT NOT NULL
			);",
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}
