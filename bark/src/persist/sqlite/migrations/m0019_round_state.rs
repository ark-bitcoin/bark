use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0019 {}

impl Migration for Migration0019 {
	fn name(&self) -> &str {
		"No config in database"
	}

	fn to_version(&self) -> i64 { 19 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute("
			CREATE TABLE bark_round_state (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				state BLOB NOT NULL
			);
		", []).context("failed to create round_state table")?;


		conn.execute(
			"DROP VIEW round_view", [],
		).context("failed to drop round_view")?;

		conn.execute(
			"DROP VIEW vtxo_view", [],
		).context("failed to drop vtxo_view")?;
		conn.execute(
			"ALTER TABLE bark_vtxo DROP COLUMN locked_in_round_attempt_id", [],
		).context("failed to drop column locked_in_round_attempt_id")?;
		conn.execute(
			"CREATE VIEW vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_vtxo,
				v.created_at,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id;
			", [],
		).context("failed to create vtxo view")?;

		conn.execute(
			"DROP TABLE bark_round_attempt", [],
		).context("failed to drop bark_round_attempt")?;


		conn.execute(
			"CREATE TABLE bark_recovered_past_round (
				funding_txid TEXT PRIMARY KEY,
				past_round_state BLOB NOT NULL
			)", [],
		).context("failed to create recovered_past_rounds")?;

		Ok(())
	}
}

