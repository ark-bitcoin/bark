
use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0027 {}

impl Migration for Migration0027 {
	fn name(&self) -> &str {
		"split payment method destination into type and value columns"
	}

	fn to_version(&self) -> i64 { 27 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute_batch("
			------------------------------------------------------
			-- 1. Drop the view because we're modifying tables --
			------------------------------------------------------

			DROP VIEW IF EXISTS bark_movements_view;

			-------------------------------------------------------------
			-- 2. Split bark_movements_sent_to destination column      --
			-------------------------------------------------------------

			CREATE TABLE bark_movements_sent_to_new (
				movement_id      INTEGER NOT NULL REFERENCES bark_movements(id),
				destination_type  TEXT    NOT NULL,
				destination_value TEXT    NOT NULL,
				amount            INTEGER NOT NULL
			);

			INSERT INTO bark_movements_sent_to_new (
				movement_id, destination_type, destination_value, amount
			)
			SELECT movement_id,
				JSON_EXTRACT(destination, '$.type'),
				JSON_EXTRACT(destination, '$.value'),
				amount
			FROM bark_movements_sent_to;

			DROP TABLE bark_movements_sent_to;
			ALTER TABLE bark_movements_sent_to_new RENAME TO bark_movements_sent_to;

			-------------------------------------------------------------
			-- 3. Split bark_movements_received_on destination column  --
			-------------------------------------------------------------

			CREATE TABLE bark_movements_received_on_new (
				movement_id      INTEGER NOT NULL REFERENCES bark_movements(id),
				destination_type  TEXT    NOT NULL,
				destination_value TEXT    NOT NULL,
				amount            INTEGER NOT NULL
			);

			INSERT INTO bark_movements_received_on_new (
				movement_id, destination_type, destination_value, amount
			)
			SELECT movement_id,
				JSON_EXTRACT(destination, '$.type'),
				JSON_EXTRACT(destination, '$.value'),
				amount
			FROM bark_movements_received_on;

			DROP TABLE bark_movements_received_on;
			ALTER TABLE bark_movements_received_on_new RENAME TO bark_movements_received_on;

			-------------------------------------------------------
			-- 4. Recreate the movement view with new columns    --
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
							'destination_type', destination_type,
							'destination_value', destination_value,
							'amount', amount
						))
						FROM bark_movements_sent_to
						WHERE movement_id = m.id
					) AS sent_to,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'destination_type', destination_type,
							'destination_value', destination_value,
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
		").context("failed to split destination columns")?;

		Ok(())
	}
}
