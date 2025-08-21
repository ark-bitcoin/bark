use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0012 {}

impl Migration for Migration0012 {

	fn name(&self) -> &str {
		"Create table to keep track of rounds"
	}

	fn to_version(&self) -> i64 { 12 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"CREATE TABLE IF NOT EXISTS bark_round_attempt (
				id INTEGER PRIMARY KEY,
				round_seq INTEGER NOT NULL,
				attempt_seq INTEGER NOT NULL,
				status TEXT NOT NULL,
				round_txid TEXT UNIQUE,
				round_tx TEXT,
				payment_requests BLOB NOT NULL,
				offboard_requests BLOB NOT NULL,
				cosign_keys BLOB,
				secret_nonces BLOB,
				vtxos BLOB,
				vtxo_tree BLOB,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				UNIQUE(round_seq, attempt_seq)
			);",

			"ALTER TABLE bark_vtxo ADD COLUMN locked_in_round_attempt_id INTEGER REFERENCES bark_round_attempt(id);",

			"CREATE TABLE IF NOT EXISTS vtxo_forfeited_in_round (
				id INTEGER PRIMARY KEY,
				double_spend_txid TEXT,
				vtxo_id TEXT NOT NULL REFERENCES bark_vtxo(id),
				round_attempt_id INTEGER NOT NULL REFERENCES bark_round_attempt(id),
				UNIQUE(round_attempt_id, vtxo_id)
			);",

			"DROP VIEW IF EXISTS vtxo_view;",
			"CREATE VIEW vtxo_view
			AS SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_vtxo,
				v.created_at,
				v.locked_in_round_attempt_id,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id;
			",
			"CREATE VIEW IF NOT EXISTS round_view
			AS SELECT
				r.id,
				r.round_seq,
				r.attempt_seq,
				r.status,
				r.round_txid,
				r.round_tx,
				r.payment_requests,
				r.offboard_requests,
				r.cosign_keys,
				r.secret_nonces,
				r.vtxos,
				r.vtxo_tree,
				r.updated_at,
				(
					SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
					FROM bark_vtxo
					WHERE bark_vtxo.locked_in_round_attempt_id = r.id
				) AS inputs,
				(
					SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
						'round_attempt_id', f.round_attempt_id,
						'vtxo_id', f.vtxo_id,
						'double_spend_txid', f.double_spend_txid
					)) FROM vtxo_forfeited_in_round as f WHERE f.round_attempt_id = r.id
				) AS vtxo_forfeited_in_round
			FROM bark_round_attempt as r",
			"CREATE VIEW IF NOT EXISTS movement_view AS
				SELECT
					*,
					(
						SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
						FROM bark_vtxo
						WHERE bark_vtxo.spent_in = bark_movement.id
					) AS spends,
					(
						SELECT JSON_GROUP_ARRAY(hex(bark_vtxo.raw_vtxo))
						FROM bark_vtxo
						WHERE bark_vtxo.received_in = bark_movement.id
					) AS receives,
					(
						SELECT JSON_GROUP_ARRAY(JSON_OBJECT(
							'recipient', bark_recipient.recipient,
							'amount_sat', bark_recipient.amount_sat
						)) FROM bark_recipient WHERE bark_recipient.movement = bark_movement.id
					) AS recipients
				FROM bark_movement;"
			];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}
