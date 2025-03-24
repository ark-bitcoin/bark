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
			"CREATE TABLE IF NOT EXISTS bark_movement (
				id INTEGER PRIMARY KEY,
				fees_sat INTEGER NOT NULL,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
			);",
			"CREATE TABLE IF NOT EXISTS bark_recipient (
				id INTEGER PRIMARY KEY,
				movement REFERENCES bark_movement(id),
				recipient TEXT NOT NULL,
				amount_sat INTEGER NOT NULL
			);",
			"ALTER TABLE bark_vtxo ADD received_in TEXT NOT NULL REFERENCES bark_movement(id);",
			"ALTER TABLE bark_vtxo ADD spent_in TEXT REFERENCES bark_movement(id);",
			"CREATE VIEW IF NOT EXISTS movement_view AS
				SELECT
					*,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', bark_vtxo.id,
							'amount_sat', bark_vtxo.amount_sat
						)) FROM bark_vtxo WHERE bark_vtxo.spent_in = bark_movement.id
					) AS spends,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'id', bark_vtxo.id,
							'amount_sat', bark_vtxo.amount_sat
						)) FROM bark_vtxo WHERE bark_vtxo.received_in = bark_movement.id
					) AS receives,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'recipient', bark_recipient.recipient,
							'amount_sat', bark_recipient.amount_sat
						)) FROM bark_recipient WHERE bark_recipient.movement = bark_movement.id
					) AS recipients
				FROM bark_movement
			;"];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}

		Ok(())
	}
}
