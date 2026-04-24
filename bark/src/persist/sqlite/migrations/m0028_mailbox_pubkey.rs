use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0028 {}

impl Migration for Migration0028 {
	fn name(&self) -> &str {
		"Add server mailbox pubkey to properties"
	}

	fn to_version(&self) -> i64 { 28 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"ALTER TABLE bark_properties ADD COLUMN server_mailbox_pubkey TEXT;",
			(),
		).context("failed to add server_mailbox_pubkey column")?;

		Ok(())
	}
}
