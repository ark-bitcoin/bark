use std::str::FromStr;

use anyhow::Context;
use rusqlite::{params, Transaction};

use ark::lightning::Invoice;

use crate::payment_method::PaymentMethod;
use super::Migration;

pub struct Migration0022 {}

impl Migration for Migration0022 {
	fn name(&self) -> &str {
		"Fix movement date fields"
	}

	fn to_version(&self) -> i64 { 22 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Convert INTEGER to DATETIME in bark_movements. We have to first remove the "ON DELETE
		// CASCADE" constraint, otherwise we'll lose VTXO/destination data.
		let movement_batch = "
				--------------------------------------------------------
				-- 1. Drop the view because we're modifying the table --
				--------------------------------------------------------

				DROP VIEW IF EXISTS bark_movements_view;

				------------------------------------------------
				-- 2. Create child tables without constraints --
				------------------------------------------------

				CREATE TABLE bark_movements_sent_to_bak AS
				SELECT * FROM bark_movements_sent_to;

				CREATE TABLE bark_movements_received_on_bak AS
				SELECT * FROM bark_movements_received_on;

				CREATE TABLE bark_movements_input_vtxos_bak AS
				SELECT * FROM bark_movements_input_vtxos;

				CREATE TABLE bark_movements_output_vtxos_bak AS
				SELECT * FROM bark_movements_output_vtxos;

				CREATE TABLE bark_movements_exited_vtxos_bak AS
				SELECT * FROM bark_movements_exited_vtxos;

				-----------------------------------------------------------------------
				-- 3. Recreate the bark_movements table with the correct date format --
				-----------------------------------------------------------------------

				CREATE TABLE bark_movements_new (
					id                INTEGER  PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
					status            TEXT     NOT NULL,
					subsystem_name    TEXT     NOT NULL,
					movement_kind     TEXT     NOT NULL,
					metadata          TEXT,
					intended_balance  INTEGER  NOT NULL,
					effective_balance INTEGER  NOT NULL,
					offchain_fee      INTEGER  NOT NULL,
					created_at        DATETIME NOT NULL,
					updated_at        DATETIME NOT NULL,
					completed_at      DATETIME
				);

				INSERT INTO bark_movements_new (
					id,
					status,
					subsystem_name,
					movement_kind,
					metadata,
					intended_balance,
					effective_balance,
					offchain_fee,
					created_at,
					updated_at,
					completed_at
				)
				SELECT
					id,
					status,
					subsystem_name,
					movement_kind,
					metadata,
					intended_balance,
					effective_balance,
					offchain_fee,
					-- Convert INTEGER unix seconds → DATETIME, otherwise keep as-is
					CASE
						WHEN typeof(created_at) = 'integer'
							THEN strftime('%Y-%m-%d %H:%M:%f', created_at, 'unixepoch')
						ELSE created_at
					END AS created_at,
					CASE
						WHEN typeof(updated_at) = 'integer'
							THEN strftime('%Y-%m-%d %H:%M:%f', updated_at, 'unixepoch')
						ELSE updated_at
					END AS updated_at,
					CASE
						WHEN completed_at IS NOT NULL AND typeof(completed_at) = 'integer'
							THEN strftime('%Y-%m-%d %H:%M:%f', completed_at, 'unixepoch')
						ELSE completed_at
					END AS completed_at
				FROM bark_movements;

				DROP TABLE bark_movements;

				ALTER TABLE bark_movements_new RENAME TO bark_movements;

				----------------------------------------------------------------
				-- 4. Recreate the child tables with a foreign key constraint --
				----------------------------------------------------------------

				DROP TABLE bark_movements_sent_to;
				CREATE TABLE bark_movements_sent_to (
					movement_id INTEGER NOT NULL REFERENCES bark_movements(id),
					destination TEXT    NOT NULL,
					amount      INTEGER NOT NULL
				);
				INSERT INTO bark_movements_sent_to
				SELECT * FROM bark_movements_sent_to_bak;
				DROP TABLE bark_movements_sent_to_bak;

				DROP TABLE bark_movements_received_on;
				CREATE TABLE bark_movements_received_on (
					movement_id INTEGER NOT NULL REFERENCES bark_movements(id),
					destination TEXT    NOT NULL,
					amount      INTEGER NOT NULL
				);
				INSERT INTO bark_movements_received_on
				SELECT * FROM bark_movements_received_on_bak;
				DROP TABLE bark_movements_received_on_bak;

				DROP TABLE bark_movements_input_vtxos;
				CREATE TABLE bark_movements_input_vtxos (
					movement_id INTEGER NOT NULL REFERENCES bark_movements(id),
					vtxo_id     TEXT    NOT NULL,
					UNIQUE(movement_id, vtxo_id)
				);
				INSERT INTO bark_movements_input_vtxos
				SELECT * FROM bark_movements_input_vtxos_bak;
				DROP TABLE bark_movements_input_vtxos_bak;

				DROP TABLE bark_movements_output_vtxos;
				CREATE TABLE bark_movements_output_vtxos (
					movement_id INTEGER NOT NULL REFERENCES bark_movements(id),
					vtxo_id     TEXT    NOT NULL,
					UNIQUE(movement_id, vtxo_id)
				);
				INSERT INTO bark_movements_output_vtxos
				SELECT * FROM bark_movements_output_vtxos_bak;
				DROP TABLE bark_movements_output_vtxos_bak;

				DROP TABLE bark_movements_exited_vtxos;
				CREATE TABLE bark_movements_exited_vtxos (
					movement_id INTEGER NOT NULL REFERENCES bark_movements(id),
					vtxo_id     TEXT    NOT NULL,
					UNIQUE(movement_id, vtxo_id)
				);
				INSERT INTO bark_movements_exited_vtxos
				SELECT * FROM bark_movements_exited_vtxos_bak;
				DROP TABLE bark_movements_exited_vtxos_bak;

				-------------------------------------------------------
				-- 5. Recreate the movement view with the new tables --
				-------------------------------------------------------

				CREATE VIEW bark_movements_view AS
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
								'destination', JSON(destination),
								'amount', amount
							))
							FROM bark_movements_sent_to
							WHERE movement_id = m.id
						) AS sent_to,
						(
							SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
								'destination', JSON(destination),
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
					FROM bark_movements m;
		";
		conn.execute_batch(movement_batch).context("failed to migrate movements")?;

		// Convert destination fields from strings to the new PaymentMethod enum.
		for table in ["bark_movements_sent_to", "bark_movements_received_on"] {
			let mut statement = conn.prepare(&format!("SELECT destination FROM {table}"))?;
			let mut rows = statement.query([])?;
			while let Some(row) = rows.next()? {
				let destination: String = row.get(0)?;

				// If the destination is already a PaymentMethod, we can skip it.
				if serde_json::from_str::<PaymentMethod>(&destination).is_ok() {
					continue;
				}

				// We should only have ark address, bitcoin address or lightning invoices right now.
				let new_destination : PaymentMethod = if let Ok(address) = ark::Address::from_str(&destination) {
					address.into()
				} else if let Ok(address) = bitcoin::Address::from_str(&destination) {
					address.into()
				} else if let Ok(invoice) = Invoice::from_str(&destination) {
					invoice.into()
				} else {
					bail!("unexpected destination type for movement: {}", destination);
				};

				// Now update the destination field.
				let query = format!("
					UPDATE {table}
					SET destination = ?1
					WHERE destination = ?2;
				");
				conn.execute(
					&query, params![&serde_json::to_string(&new_destination)?, &destination],
				).context("failed to migrate movements")?;
			}
		}

		let queries = [
			// Adding default 0 for backward compatibility
			"ALTER TABLE bark_pending_board ADD COLUMN amount_sat INTEGER NOT NULL DEFAULT 0;",
			"ALTER TABLE bark_pending_lightning_receive ADD COLUMN finished_at DATETIME;",

			// --- Store historical lightning sends with preimage ---
			// The table will now store non-pending payments too so it needs a rename.
			"ALTER TABLE bark_pending_lightning_send RENAME TO bark_lightning_send;",
			"ALTER TABLE bark_lightning_send ADD COLUMN preimage TEXT;",
			"ALTER TABLE bark_lightning_send ADD COLUMN finished_at DATETIME;",

			// Change MovementStatus::Finished to MovementStatus::Successful.
			"UPDATE bark_movements SET status = 'successful' WHERE status = 'finished'",

			// Change MovementStatus::Cancelled to MovementStatus::Canceled.
			"UPDATE bark_movements SET status = 'cancelled' WHERE status = 'canceled'",
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}
