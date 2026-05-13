use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0033 {}

impl Migration for Migration0033 {
	fn name(&self) -> &str {
		"Add paid invoice fact table and backfill settled lightning sends"
	}

	fn to_version(&self) -> i64 { 33 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"CREATE TABLE bark_paid_invoice (
				payment_hash TEXT PRIMARY KEY,
				preimage     TEXT NOT NULL,
				paid_at      DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			)",
			(),
		).context("failed to create bark_paid_invoice table")?;

		// Backfill from the legacy bark_lightning_send table: any row that
		// has a preimage was a successful payment. ON CONFLICT DO NOTHING is
		// paranoia in case a wallet somehow has two rows for the same hash.
		conn.execute(
			"INSERT OR IGNORE INTO bark_paid_invoice (payment_hash, preimage, paid_at)
			 SELECT payment_hash, preimage, COALESCE(finished_at, strftime('%Y-%m-%d %H:%M:%f', 'now'))
			 FROM bark_lightning_send
			 WHERE preimage IS NOT NULL",
			(),
		).context("failed to backfill bark_paid_invoice from bark_lightning_send")?;

		Ok(())
	}
}
