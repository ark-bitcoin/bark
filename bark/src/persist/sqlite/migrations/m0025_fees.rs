
use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0025 {}

impl Migration for Migration0025 {
	fn name(&self) -> &str {
		"Implement fees"
	}

	fn to_version(&self) -> i64 { 25 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"ALTER TABLE bark_lightning_send ADD COLUMN fee_sats INTEGER NOT NULL DEFAULT 0;",
		];

		for query in queries {
			conn.execute(query, ())
				.with_context(|| format!("failed to execute migration query {}", query))?;
		}

		Ok(())
	}
}
