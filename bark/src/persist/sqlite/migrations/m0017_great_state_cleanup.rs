use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0017 {}

impl Migration for Migration0017 {

	fn name(&self) -> &str {
		"Add unregistered board table"
	}

	fn to_version(&self) -> i64 { 17 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS bark_pending_board (
				id INTEGER PRIMARY KEY,
				vtxo_id TEXT NOT NULL REFERENCES bark_vtxo(id) ON DELETE CASCADE,
				funding_tx TEXT NOT NULL UNIQUE,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				UNIQUE (vtxo_id)
			);",
			"CREATE TABLE IF NOT EXISTS bark_pending_lightning_send (
				id INTEGER PRIMARY KEY,
				invoice TEXT NOT NULL UNIQUE,
				payment_hash TEXT NOT NULL UNIQUE,
				amount_sats INTEGER NOT NULL,
				htlc_vtxo_ids TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
		];

		for query in queries {
			conn.execute(query, ())
				.with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}

		Ok(())
	}
}
