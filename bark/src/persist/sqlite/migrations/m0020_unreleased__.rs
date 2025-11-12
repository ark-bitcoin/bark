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

			// Movements
			"DROP TABLE bark_movement;",
			"DROP VIEW movement_view;",
			"CREATE TABLE bark_movements (
				id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
				status TEXT NOT NULL,
				subsystem_name TEXT NOT NULL,
				movement_kind TEXT NOT NULL,
				metadata TEXT,
				intended_balance INTEGER NOT NULL,
				effective_balance INTEGER NOT NULL,
				offchain_fee INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				completed_at INTEGER
			);",
			"CREATE TABLE bark_movements_sent_to (
				movement_id INTEGER NOT NULL,
				destination TEXT NOT NULL,
				amount INTEGER NOT NULL,
				FOREIGN KEY (movement_id) REFERENCES bark_movements(id) ON DELETE CASCADE
			);",
			"CREATE TABLE bark_movements_received_on (
				movement_id INTEGER NOT NULL,
				destination TEXT NOT NULL,
				amount INTEGER NOT NULL,
				FOREIGN KEY (movement_id) REFERENCES bark_movements(id) ON DELETE CASCADE
			);",
			"CREATE TABLE bark_movements_input_vtxos (
				movement_id INTEGER NOT NULL,
				vtxo_id TEXT NOT NULL,
				FOREIGN KEY (movement_id) REFERENCES bark_movements(id) ON DELETE CASCADE,
				UNIQUE(movement_id, vtxo_id)
			);",
			"CREATE TABLE bark_movements_output_vtxos (
				movement_id INTEGER NOT NULL,
				vtxo_id TEXT NOT NULL,
				FOREIGN KEY (movement_id) REFERENCES bark_movements(id) ON DELETE CASCADE,
				UNIQUE(movement_id, vtxo_id)
			);",
			"CREATE TABLE bark_movements_exited_vtxos (
				movement_id INTEGER NOT NULL,
				vtxo_id TEXT NOT NULL,
				FOREIGN KEY (movement_id) REFERENCES bark_movements(id) ON DELETE CASCADE,
				UNIQUE(movement_id, vtxo_id)
			);",
			"CREATE VIEW bark_movements_view AS
			SELECT
				m.id,
				m.status,
				m.subsystem_name,
				m.movement_kind,
				m.metadata,
				m.intended_balance,
				m.effective_balance,
				m.offchain_fee,
				m.created_at,
				m.updated_at,
				m.completed_at,
				(
					SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
						'destination', destination,
						'amount', amount
					))
					FROM bark_movements_sent_to
					WHERE movement_id = m.id
				) AS sent_to,
				(
					SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
						'destination', destination,
						'amount', amount
					))
					FROM bark_movements_received_on
					WHERE movement_id = m.id
				) AS received_on,
				(
					SELECT JSON_GROUP_ARRAY(vtxo_id)
					FROM bark_movements_input_vtxos
					WHERE movement_id = m.id
				) AS input_vtxos,
				(
					SELECT JSON_GROUP_ARRAY(vtxo_id)
					FROM bark_movements_output_vtxos
					WHERE movement_id = m.id
				) AS output_vtxos,
				(
					SELECT JSON_GROUP_ARRAY(vtxo_id)
					FROM bark_movements_exited_vtxos
					WHERE movement_id = m.id
				) AS exited_vtxos
			FROM bark_movements m;",
			"DROP TABLE bark_vtxo",
			"CREATE TABLE bark_vtxo (
				id TEXT PRIMARY KEY,
				expiry_height INTEGER,
				amount_sat INTEGER,
				raw_vtxo BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				received_in TEXT REFERENCES bark_movements(id),
				spent_in TEXT REFERENCES bark_movements(id)
			);",
			"ALTER TABLE bark_pending_board ADD COLUMN movement_id INTEGER NOT NULL;",
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}

