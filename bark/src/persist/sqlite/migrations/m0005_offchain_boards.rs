use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0005 {}

impl Migration for Migration0005 {

	fn name(&self) -> &str {
		"Add table to support offchain boards with HTLCs"
	}

	fn to_version(&self) -> i64 { 5 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Rename Ready to Spendable
		let query = "CREATE TABLE bark_offchain_board (
			payment_hash BLOB NOT NULL PRIMARY KEY,
			preimage BLOB NOT NULL UNIQUE,
			serialised_payment BLOB,
			created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
		)";

		conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		Ok(())
	}
}
