use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0002 {}

impl Migration for Migration0002 {

	fn name(&self) -> &str {
		"Create wallet meta tables"
	}

	fn to_version(&self) -> i64 { 2 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS bark_config (
				id TEXT PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

				asp_address TEXT NOT NULL,
				esplora_address ,
				bitcoind_address ,
				bitcoind_cookiefile ,
				bitcoind_user ,
				bitcoind_pass ,
				vtxo_refresh_threshold INTEGER NOT NULL
			);",
			"CREATE TABLE IF NOT EXISTS bark_properties (
				id TEXT PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),

				network TEXT NOT NULL,
				fingerprint TEXT NOT NULL
			);"
			];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}
