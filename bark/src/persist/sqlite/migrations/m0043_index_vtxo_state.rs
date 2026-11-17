//! Index the VTXO state history by VTXO.
//!
//! The `vtxo_id` column of `most_recent_vtxo_state` must come from the
//! grouped CTE. SQLite then pushes a `vtxo_id` filter into the `GROUP BY` and
//! seeks the index. Otherwise a lookup of one VTXO reads the full history.

use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0043 {}

impl Migration for Migration0043 {
	fn name(&self) -> &str {
		"Index the VTXO state history by VTXO"
	}

	fn to_version(&self) -> i64 { 43 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute_batch("
			CREATE INDEX vtxo_state_vtxo_id_idx
			ON bark_vtxo_state (vtxo_id, id);

			DROP VIEW most_recent_vtxo_state;
			CREATE VIEW most_recent_vtxo_state
				(id, last_updated_at, vtxo_id, state_kind, state)
			AS
			WITH most_recent AS (
				SELECT vtxo_id, MAX(id) as id FROM bark_vtxo_state GROUP BY vtxo_id
			)
			SELECT
				most_recent.id,
				vs.created_at,
				most_recent.vtxo_id,
				vs.state_kind,
				vs.state
			FROM most_recent JOIN bark_vtxo_state as vs
				ON vs.id = most_recent.id;
		").context("failed to index bark_vtxo_state")?;

		Ok(())
	}
}
