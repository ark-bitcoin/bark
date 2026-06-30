use std::str::FromStr;

use anyhow::Context;
use lightning_invoice::Bolt11Invoice;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0037 {}

impl Migration for Migration0037 {
	fn name(&self) -> &str {
		"Add settled lightning receive fact table and backfill settled lightning receives"
	}

	fn to_version(&self) -> i64 { 37 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"CREATE TABLE bark_settled_lightning_receive (
				payment_hash TEXT PRIMARY KEY,
				preimage     TEXT NOT NULL,
				invoice      TEXT NOT NULL,
				amount_sat   INTEGER NOT NULL,
				settled_at   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			)",
			(),
		).context("failed to create bark_settled_lightning_receive table")?;

		let mut stmt = conn.prepare(
			"SELECT payment_hash, preimage, invoice,
				COALESCE(finished_at, created_at) AS settled_at
				FROM bark_pending_lightning_receive
				WHERE preimage_revealed_at IS NOT NULL",
		)?;
		let mut rows = stmt.query([])?;

		while let Some(row) = rows.next()? {
			let invoice = row.get::<_, String>("invoice")?;
			let settled_at = row.get::<_, String>("settled_at")?;
			let payment_hash = row.get::<_, String>("payment_hash")?;
			let preimage = row.get::<_, String>("preimage")?;

			let amount_sat = Bolt11Invoice::from_str(&invoice).ok()
				.and_then(|inv| inv.amount_milli_satoshis())
				.map(|msat| (msat / 1000) as i64)
				.unwrap_or(0);

			conn.execute(
				"INSERT OR IGNORE INTO bark_settled_lightning_receive
					(payment_hash, preimage, invoice, amount_sat, settled_at)
				VALUES (:payment_hash, :preimage, :invoice, :amount_sat, :settled_at)",
				rusqlite::named_params! {
					":payment_hash": payment_hash,
					":preimage": preimage,
					":invoice": invoice,
					":amount_sat": amount_sat,
					":settled_at": settled_at,
				},
			).context("failed to backfill bark_settled_lightning_receive row")?;
		}

		Ok(())
	}
}
