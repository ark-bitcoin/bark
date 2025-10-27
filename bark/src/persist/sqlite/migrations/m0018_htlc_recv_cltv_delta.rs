use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0018 {}

impl Migration for Migration0018 {

	fn name(&self) -> &str {
		"Add htlc_recv_cltv_delta column to lightning receives"
	}

	fn to_version(&self) -> i64 { 18 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let query = "ALTER TABLE bark_pending_lightning_receive ADD COLUMN htlc_recv_cltv_delta INTEGER NOT NULL;";
		conn.execute(query, ()).with_context(|| "Failed to execute migration")?;
		Ok(())
	}
}
