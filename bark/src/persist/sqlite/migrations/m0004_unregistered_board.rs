use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0004 {}

impl Migration for Migration0004 {

	fn name(&self) -> &str {
		"Updating the VtxoState"
	}

	fn to_version(&self) -> i64 { 4 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Rename Ready to Spendable
		let query = "UPDATE bark_vtxo_state SET state = 'Spendable' WHERE state = 'Ready'";

		conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		Ok(())
	}
}
