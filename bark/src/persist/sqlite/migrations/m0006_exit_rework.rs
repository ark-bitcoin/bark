use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0006 {}

impl Migration for Migration0006 {

	fn name(&self) -> &str {
		"Update the exit system to be a state machine"
	}

	fn to_version(&self) -> i64 { 6 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// We can't use JSONB with rusqlite, so we make do with strings
		let queries = [
			"DROP TABLE bark_exit;",
			"CREATE TABLE IF NOT EXISTS bark_exit_states (
				vtxo_id TEXT PRIMARY KEY,
				state TEXT NOT NULL,
				history TEXT NOT NULL
			);",
			"CREATE TABLE IF NOT EXISTS bark_exit_child_transactions (
				exit_id TEXT PRIMARY KEY,
				child_tx BLOB NOT NULL,
				block_hash BLOB,
				height INTEGER
			);",
		];
		for query in queries {
			conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		}
		Ok(())
	}
}
