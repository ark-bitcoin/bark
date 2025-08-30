use anyhow::Context;

use rusqlite::Transaction;

use super::Migration;

pub struct Migration0015 {}

impl Migration for Migration0015 {

	fn name(&self) -> &str {
		"Make round_seq and attempt_seq optional"
	}

	fn to_version(&self) -> i64 { 15 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"DROP VIEW IF EXISTS round_view;",
			"CREATE TABLE IF NOT EXISTS bark_round_attempt_new (
				id INTEGER PRIMARY KEY,
				round_seq INTEGER,
				attempt_seq INTEGER,
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

			"INSERT INTO bark_round_attempt_new (
				id,
				round_seq,
				attempt_seq,
				status,
				round_txid,
				round_tx,
				payment_requests,
				offboard_requests,
				cosign_keys,
				secret_nonces,
				vtxos,
				vtxo_tree,
				created_at,
				updated_at)
			SELECT
				id,
				round_seq,
				attempt_seq,
				status,
				round_txid,
				round_tx,
				payment_requests,
				offboard_requests,
				cosign_keys,
				secret_nonces,
				vtxos,
				vtxo_tree,
				created_at,
				updated_at
			FROM bark_round_attempt;",

			"DROP TABLE bark_round_attempt;",

			"ALTER TABLE bark_round_attempt_new RENAME TO bark_round_attempt;",

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
		];

		for query in queries {
			conn.execute(query, ()).with_context(|| format!("Failed to execute migration: {}", self.summary()))?;
		}
		Ok(())
	}
}

