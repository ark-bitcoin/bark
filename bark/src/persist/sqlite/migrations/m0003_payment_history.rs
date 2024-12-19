use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0003 {}

impl Migration for Migration0003 {
	fn name(&self) -> &str {
		"Create tables for movement history"
	}

	fn to_version(&self) -> i64 { 3 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS movement (
				id INTEGER PRIMARY KEY,
				fees_sat INTEGER NOT NULL,
				destination TEXT,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"ALTER TABLE vtxo ADD received_in TEXT NOT NULL REFERENCES movement(id);",
			"ALTER TABLE vtxo ADD spent_in TEXT REFERENCES movement(id);",
			"CREATE VIEW IF NOT EXISTS movement_view AS
				SELECT 
					*,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', vtxo.id, 
							'amount_sat', vtxo.amount_sat
						)) FROM vtxo WHERE vtxo.spent_in = movement.id
					) AS spends,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', vtxo.id, 
							'amount_sat', vtxo.amount_sat
						)) FROM vtxo WHERE vtxo.received_in = movement.id
					) AS receives
				FROM movement
			;"];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		
		Ok(())
	}
}
