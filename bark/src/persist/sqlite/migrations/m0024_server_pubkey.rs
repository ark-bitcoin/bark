use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0024 {}

impl Migration for Migration0024 {
	fn name(&self) -> &str {
		"Add server pubkey to properties"
	}

	fn to_version(&self) -> i64 { 24 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Add server_pubkey column to bark_properties
		// This is nullable for backwards compatibility with existing wallets
		conn.execute(
			"ALTER TABLE bark_properties ADD COLUMN server_pubkey TEXT;",
			(),
		).context("failed to add server_pubkey column")?;

		Ok(())
	}
}
