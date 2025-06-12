use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0001 {}

impl Migration for Migration0001 {

	fn name(&self) -> &str {
		"Create initial tables"
	}

	fn to_version(&self) -> i64 { 1 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS bark_vtxo (
				id TEXT PRIMARY KEY,
				expiry_height INTEGER,
				amount_sat INTEGER,
				raw_vtxo BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"CREATE TABLE IF NOT EXISTS bark_vtxo_key (
				public_key TEXT NOT NULL PRIMARY KEY,
				keychain INTEGER NOT NULL,
				idx INTEGER NOT NULL,
				-- each index must be unique in a keychain
				UNIQUE (keychain, idx)
			);",
			"CREATE TABLE IF NOT EXISTS bark_vtxo_state (
				id INTEGER PRIMARY KEY,
				created_at DATETIME NOT NULL DEFAULT  (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				vtxo_id TEXT REFERENCES bark_vtxo(id),
				state_kind TEXT NOT NULL,
				state BLOB NOT NULL
			);",
			"CREATE TABLE IF NOT EXISTS bark_ark_sync (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sync_height INTEGER,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"CREATE TABLE IF NOT EXISTS bark_exit (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				exit BLOB
			)",
			"CREATE VIEW IF NOT EXISTS most_recent_vtxo_state
				(id, last_updated_at, vtxo_id, state_kind, state)
			AS
			WITH most_recent AS (SELECT MAX(id) as id FROM bark_vtxo_state GROUP BY vtxo_id)
			SELECT
					most_recent.id,
					vs.created_at,
					vs.vtxo_id,
					vs.state_kind,
					vs.state
					FROM most_recent JOIN bark_vtxo_state as vs
						ON vs.id = most_recent.id;
			",
			"CREATE VIEW IF NOT EXISTS vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				vs.state_kind,
				vs.state,
				v.raw_vtxo,
				v.created_at,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id;
			"];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}
