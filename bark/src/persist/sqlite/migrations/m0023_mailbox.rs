
use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0023 {}

impl Migration for Migration0023 {
	fn name(&self) -> &str {
		"mailbox checkpoint system"
	}

	fn to_version(&self) -> i64 { 23 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE bark_mailbox_checkpoint (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				checkpoint INTEGER NOT NULL,
				updated_at DATETIME NOT NULL
			);",
			"INSERT INTO bark_mailbox_checkpoint (id, checkpoint, updated_at) VALUES (1, 0, datetime('now'));"
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}

