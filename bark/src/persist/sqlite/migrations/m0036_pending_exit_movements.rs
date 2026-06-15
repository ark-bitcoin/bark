use anyhow::Context;
use rusqlite::{params, Transaction};
use serde_json::Value;

use super::Migration;

pub struct Migration0036 {}

impl Migration for Migration0036 {
	fn name(&self) -> &str {
		"Revert in-progress exit movements from Successful back to Pending so the new \
		 progress code can finalize them onchain"
	}

	fn to_version(&self) -> i64 { 36 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Old builds created the exit movement in a finished `successful` state. The new
		// flow keeps it `pending` until the exit reaches `Claimed` (then `successful`) or
		// `VtxoAlreadySpent` (then `canceled`). Walk every exit row, pick out the ones
		// that haven't terminated yet, and roll their movement back to `pending`.
		let mut stmt = conn.prepare(
			"SELECT vtxo_id, state, movement_id FROM bark_exit_states \
			 WHERE movement_id IS NOT NULL",
		)?;
		let rows = stmt.query_map([], |row| Ok((
			row.get::<_, String>(0)?,
			row.get::<_, String>(1)?,
			row.get::<_, i64>(2)?,
		)))?.collect::<Result<Vec<_>, _>>()?;
		drop(stmt);

		for (vtxo_id, state_json, movement_id) in rows {
			let state: Value = serde_json::from_str(&state_json)
				.with_context(|| format!("parse exit state for vtxo {}", vtxo_id))?;
			if !is_in_progress(&state) {
				continue;
			}
			conn.execute(
				"UPDATE bark_movements SET status = 'pending', completed_at = NULL \
				 WHERE id = ?1 AND status = 'successful'",
				params![movement_id],
			)?;
		}
		Ok(())
	}
}

/// An exit is "in progress" while it hasn't reached a terminal state (`Claimed` or
/// `VtxoAlreadySpent`). Only those movements get reverted to Pending; terminal ones
/// keep whatever final status they were written with.
fn is_in_progress(state: &Value) -> bool {
	let tag = state.get("type").and_then(Value::as_str).unwrap_or("");
	!matches!(tag, "claimed" | "vtxo-already-spent")
}

#[cfg(test)]
mod test {
	use rusqlite::Connection;
	use serde_json::json;

	use crate::persist::sqlite::migrations::MigrationContext;

	use super::*;

	const EXIT_SUBSYSTEM: &str = "bark.exit";
	const EXIT_MOVEMENT_KIND: &str = "start";

	fn init(conn: &mut Connection) {
		let ctx = MigrationContext::new();
		ctx.do_all_migrations(conn).expect("migrations apply cleanly");
		conn.execute("DELETE FROM bark_exit_states", ()).unwrap();
		conn.execute("DELETE FROM bark_movements_input_vtxos", ()).unwrap();
		conn.execute("DELETE FROM bark_movements", ()).unwrap();
	}

	fn seed_exit_with_movement(
		conn: &Connection,
		vtxo_id: &str,
		state: &Value,
		status: &str,
	) -> i64 {
		conn.execute(
			"INSERT INTO bark_movements (
				status, subsystem_name, movement_kind, metadata, intended_balance,
				effective_balance, offchain_fee, created_at, updated_at, completed_at
			) VALUES (?1, ?2, ?3, '{}', -10000, -10000, 0,
				'2025-01-01 00:00:00.000', '2025-01-01 00:00:00.000', '2025-01-01 00:00:00.000')",
			params![status, EXIT_SUBSYSTEM, EXIT_MOVEMENT_KIND],
		).unwrap();
		let id: i64 = conn.query_row(
			"SELECT id FROM bark_movements ORDER BY id DESC LIMIT 1",
			[], |row| row.get(0),
		).unwrap();
		conn.execute(
			"INSERT INTO bark_movements_input_vtxos (movement_id, vtxo_id) VALUES (?1, ?2)",
			params![id, vtxo_id],
		).unwrap();
		conn.execute(
			"INSERT INTO bark_exit_states (vtxo_id, state, history, movement_id) \
			 VALUES (?1, ?2, '[]', ?3)",
			params![vtxo_id, state.to_string(), id],
		).unwrap();
		id
	}

	fn movement_status(conn: &Connection, id: i64) -> String {
		conn.query_row(
			"SELECT status FROM bark_movements WHERE id = ?1",
			params![id], |row| row.get(0),
		).unwrap()
	}

	fn completed_at(conn: &Connection, id: i64) -> Option<String> {
		conn.query_row(
			"SELECT completed_at FROM bark_movements WHERE id = ?1",
			params![id], |row| row.get(0),
		).unwrap()
	}

	fn run(conn: &mut Connection) {
		let tx = conn.transaction().unwrap();
		Migration0036 {}.do_migration(&tx).unwrap();
		tx.commit().unwrap();
	}

	/// In-progress states (Start, Processing, AwaitingDelta, Claimable, ClaimInProgress)
	/// all revert to Pending — the new progress code drives them to a terminal status.
	#[test]
	fn in_progress_movements_revert_to_pending() {
		let states = [
			json!({ "type": "start", "tip_height": 100 }),
			json!({ "type": "processing", "tip_height": 100, "transactions": [] }),
			json!({ "type": "awaiting-delta", "tip_height": 100,
			        "confirmed_block": { "height": 1, "hash": "00".repeat(32) },
			        "claimable_height": 1000 }),
			json!({ "type": "claimable", "tip_height": 100,
			        "claimable_since": { "height": 1, "hash": "00".repeat(32) },
			        "last_scanned_block": null }),
			json!({ "type": "claim-in-progress", "tip_height": 100,
			        "claimable_since": { "height": 1, "hash": "00".repeat(32) },
			        "claim_txid": "00".repeat(32) }),
		];
		for (i, state) in states.iter().enumerate() {
			let mut conn = Connection::open(":memory:").unwrap();
			init(&mut conn);
			let mid = seed_exit_with_movement(&conn, &format!("v{}", i), state, "successful");

			run(&mut conn);

			assert_eq!(movement_status(&conn, mid), "pending",
				"state {} should be reverted to pending", state["type"]);
			assert!(completed_at(&conn, mid).is_none(),
				"completed_at should be cleared for state {}", state["type"]);
		}
	}

	/// Terminal states leave the movement alone — Claimed exits keep their Successful
	/// movement, VtxoAlreadySpent would already be Canceled (new state, no old data).
	#[test]
	fn terminal_movements_are_left_alone() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let claimed = json!({
			"type": "claimed", "tip_height": 100,
			"txid": "00".repeat(32),
			"block": { "height": 1, "hash": "00".repeat(32) }
		});
		let mid = seed_exit_with_movement(&conn, "v_claimed", &claimed, "successful");

		run(&mut conn);

		assert_eq!(movement_status(&conn, mid), "successful");
	}

	/// Non-`successful` statuses (rare, but defensive) are not flipped to Pending —
	/// only the legacy Successful path gets reverted.
	#[test]
	fn already_pending_movement_unchanged() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let start = json!({ "type": "start", "tip_height": 100 });
		let mid = seed_exit_with_movement(&conn, "v_pending", &start, "pending");

		run(&mut conn);

		assert_eq!(movement_status(&conn, mid), "pending");
	}
}
