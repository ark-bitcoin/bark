use anyhow::Context;

use rusqlite::Transaction;

use crate::db::migrations::Migration;

pub struct Migration0002 {}

impl Migration for Migration0002 {

	fn name(&self) -> &str {
		"Create config table"
	}

	fn to_version(&self) -> i64 { 2 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS config (
				id TEXT PRIMARY KEY,
				network TEXT NOT NULL,
				fingerprint TEXT NOT NULL,
				asp_address TEXT NOT NULL,
				esplora_address ,
				bitcoind_address ,
				bitcoind_cookiefile ,
				bitcoind_user ,
				bitcoind_pass ,
				vtxo_refresh_threshold INTEGER NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);"];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}
