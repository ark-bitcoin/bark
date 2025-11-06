use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0020 {}

impl Migration for Migration0020 {
	fn name(&self) -> &str {
		"No config in database"
	}

	fn to_version(&self) -> i64 { 20 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"DROP TABLE bark_pending_lightning_receive",
			"CREATE TABLE bark_pending_lightning_receive (
				payment_hash TEXT NOT NULL PRIMARY KEY,
				preimage TEXT NOT NULL UNIQUE,
				invoice TEXT NOT NULL,
				htlc_recv_cltv_delta INTEGER NOT NULL,
				htlc_vtxo_ids TEXT,
				preimage_revealed_at DATETIME,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			)",
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}

