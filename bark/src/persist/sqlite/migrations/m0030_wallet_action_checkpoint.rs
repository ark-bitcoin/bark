use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0030 {}

impl Migration for Migration0030 {
	fn name(&self) -> &str {
		"Add wallet action checkpoint table"
	}

	fn to_version(&self) -> i64 { 30 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"CREATE TABLE bark_wallet_action_checkpoint (
				id         TEXT PRIMARY KEY,
				payload    BLOB NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			)",
			(),
		).context("failed to create bark_wallet_action_checkpoint table")?;

		Ok(())
	}
}
