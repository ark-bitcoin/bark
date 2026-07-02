use anyhow::Context;
use bitcoin::consensus::encode::deserialize_hex;
use rusqlite::{params, Transaction};
use serde_json::json;

use ark::board::BOARD_FUNDING_TX_VTXO_VOUT;

use super::Migration;

pub struct Migration0038 {}

impl Migration for Migration0038 {
	fn name(&self) -> &str {
		"Migrate pending boards into board wallet action checkpoints"
	}

	fn to_version(&self) -> i64 { 38 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Boards used to be tracked in `bark_pending_board` and driven by an
		// ad-hoc `sync_pending_boards`. They're now `Board` wallet actions
		// checkpointed in `bark_wallet_action_checkpoint`. Existing rows are
		// already broadcast and their vtxo is already stored, so they resume at
		// `Confirming` (never re-cosign, never re-store). The vtxo stays Locked;
		// the action transitions it out (Spendable on register, Exited on
		// salvage), and balance reporting filters by state kind, not holder, so
		// re-keying the lock holder isn't needed.
		let mut stmt = conn.prepare(
			"SELECT vtxo_id, amount_sat, funding_tx, movement_id FROM bark_pending_board",
		)?;
		let rows = stmt.query_map([], |row| Ok((
			row.get::<_, String>(0)?,
			row.get::<_, i64>(1)?,
			row.get::<_, String>(2)?,
			row.get::<_, i64>(3)?,
		)))?.collect::<Result<Vec<_>, _>>()?;
		drop(stmt);

		for (vtxo_id, amount_sat, funding_tx_hex, movement_id) in rows {
			let funding_tx: bitcoin::Transaction = deserialize_hex(&funding_tx_hex)
				.with_context(|| format!("parse funding tx for board {}", vtxo_id))?;
			let utxo = bitcoin::OutPoint::new(
				funding_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT,
			);
			// Re-derive the stable action id used by `board_action_id` (`.`
			// rather than the `txid:vout` colon, since ids double as lock keys).
			let id = format!("board.{}.{}", utxo.txid, utxo.vout);

			// Hand-build the `WalletActionCheckpoint::Board` JSON. The shapes
			// mirror the serde of each field (funding tx as consensus hex, vtxo
			// id / amount as their serde reprs); the test below round-trips this
			// against the live type to catch any drift.
			let payload = json!({
				"Board": {
					"id": id,
					"funding_tx": funding_tx_hex,
					"vtxo_id": vtxo_id,
					"amount": amount_sat,
					"movement_id": movement_id,
					"progress": { "Confirming": { "last_park_error": null } },
				}
			});
			let payload = serde_json::to_vec(&payload)
				.context("serialize migrated board checkpoint")?;

			// Validate the payload round-trips before the legacy rows are cleared,
			// so any drift rolls the migration back instead of stranding it.
			serde_json::from_slice::<crate::actions::WalletActionCheckpoint>(&payload)
				.with_context(|| format!("validate migrated board checkpoint {}", id))?;

			conn.execute(
				"INSERT INTO bark_wallet_action_checkpoint (id, payload) VALUES (?1, ?2)",
				params![id, payload],
			).context("insert migrated board checkpoint")?;
		}

		// Empty the legacy table rather than dropping it. Older bark binaries
		// still query `bark_pending_board` on startup, so the schema has to stay
		// for backward compatibility; the rows now live as checkpoints.
		conn.execute("DELETE FROM bark_pending_board", ())
			.context("clear migrated bark_pending_board rows")?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use rusqlite::Connection;

	use ark::VtxoId;

	use crate::actions::WalletActionCheckpoint;
	use crate::actions::board::Progress;
	use crate::persist::sqlite::migrations::MigrationContext;

	use bitcoin::consensus::encode::serialize_hex;

	use super::*;

	/// A minimal funding tx with a single output, matching how `board_tx`
	/// stores `funding_tx` (consensus hex).
	fn funding_tx() -> bitcoin::Transaction {
		bitcoin::Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
			input: vec![],
			output: vec![bitcoin::TxOut {
				value: bitcoin::Amount::from_sat(1_000_000),
				script_pubkey: bitcoin::ScriptBuf::new_op_return(&[0u8; 4]),
			}],
		}
	}

	#[test]
	fn migrates_pending_board_to_checkpoint() {
		let mut conn = Connection::open(":memory:").unwrap();
		let ctx = MigrationContext::new();
		ctx.do_all_migrations(&mut conn).expect("migrations apply cleanly");

		// `bark_pending_board` survives the migration (kept for backward compat);
		// seed a legacy row to exercise the conversion logic in isolation. The
		// real table references `bark_vtxo`, so relax FK enforcement to seed a
		// synthetic row without standing up a full vtxo.
		conn.pragma_update(None, "foreign_keys", false).unwrap();
		let funding_tx = funding_tx();
		let funding_tx_hex = serialize_hex(&funding_tx);
		let vtxo_id = VtxoId::from(bitcoin::OutPoint::new(funding_tx.compute_txid(), 0));
		conn.execute(
			"INSERT INTO bark_pending_board (vtxo_id, amount_sat, funding_tx, movement_id) \
			 VALUES (?1, ?2, ?3, ?4)",
			params![vtxo_id.to_string(), 1_000_000i64, funding_tx_hex, 7i64],
		).unwrap();

		let tx = conn.transaction().unwrap();
		Migration0038 {}.do_migration(&tx).unwrap();
		tx.commit().unwrap();

		let table_exists: i64 = conn.query_row(
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bark_pending_board'",
			[], |row| row.get(0),
		).unwrap();
		assert_eq!(table_exists, 1, "bark_pending_board should be kept for backward compat");
		let remaining_rows: i64 = conn.query_row(
			"SELECT count(*) FROM bark_pending_board", [], |row| row.get(0),
		).unwrap();
		assert_eq!(remaining_rows, 0, "migrated rows should be cleared from bark_pending_board");

		let utxo = bitcoin::OutPoint::new(funding_tx.compute_txid(), 0);
		let id = format!("board.{}.{}", utxo.txid, utxo.vout);
		let payload: Vec<u8> = conn.query_row(
			"SELECT payload FROM bark_wallet_action_checkpoint WHERE id = ?1",
			params![id], |row| row.get(0),
		).unwrap();
		let cp: WalletActionCheckpoint = serde_json::from_slice(&payload).unwrap();
		let board = cp.into_board().expect("checkpoint is a board");
		assert_eq!(board.id, id);
		assert_eq!(board.vtxo_id, vtxo_id);
		assert_eq!(board.movement_id.0, 7);
		assert!(matches!(board.progress, Progress::Confirming { .. }));
	}
}
