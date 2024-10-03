use anyhow::Context;

use rusqlite::{Transaction};

use crate::db::migrations::Migration;

pub struct Migration0001 {}

impl Migration for Migration0001 {

	fn name(&self) -> &str {
		"Create initial tables"
	}

	fn to_version(&self) -> i64 { 1 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS vtxo (
				id TEXT PRIMARY KEY,
				expiry_height INTEGER,
				amount_sat INTEGER,
				raw_vtxo BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"CREATE TABLE IF NOT EXISTS vtxo_state (
				id INTEGER PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				vtxo_id TEXT REFERENCES vtxo(id),
				state TEXT
			);",
			"CREATE TABLE IF NOT EXISTS ark_sync (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sync_height INTEGER,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"CREATE TABLE IF NOT EXISTS exit (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				exit BLOB
			)",
			"
			CREATE VIEW IF NOT EXISTS most_recent_vtxo_state
				(id, last_updated_at, vtxo_id, state)
			AS
			WITH most_recent AS (SELECT MAX(id) as id FROM vtxo_state GROUP BY vtxo_id)
			SELECT
					most_recent.id,
					vs.created_at,
					vs.vtxo_id,
					vs.state
					FROM most_recent JOIN vtxo_state as vs
						ON vs.id = most_recent.id;
			","CREATE VIEW IF NOT EXISTS vtxo_view 
			AS SELECT 
				v.id,
				v.expiry_height,
				v.amount_sat,
				vs.state,
				v.raw_vtxo,
				v.created_at,
				vs.last_updated_at
			FROM vtxo as v 
			JOIN most_recent_vtxo_state as vs 
				ON v.id = vs.vtxo_id;
			"];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}
