use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0011 {}

impl Migration for Migration0011 {

	fn name(&self) -> &str {
		"Add tx_origin to bark_exit_child_transactions"
	}

	fn to_version(&self) -> i64 { 11 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// We can safely drop the table since the child transactions can just be redownloaded
		let queries = [
			"DROP TABLE bark_exit_child_transactions",
			"CREATE TABLE IF NOT EXISTS bark_exit_child_transactions (
				exit_id TEXT PRIMARY KEY,
				child_tx BLOB NOT NULL,
				tx_origin TEXT NOT NULL
			);",
		];
		for query in queries {
			conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		}
		Ok(())
	}
}