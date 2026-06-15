use anyhow::Context;
use rusqlite::{params, Transaction};
use serde_json::Value;

use super::Migration;

const EXIT_SUBSYSTEM: &str = "bark.exit";
const EXIT_MOVEMENT_KIND: &str = "start";

pub struct Migration0035 {}

impl Migration for Migration0035 {
	fn name(&self) -> &str {
		"Track exit progress on VTXO/movement: add bark_exit_states.movement_id and \
		 reconcile in-progress exits"
	}

	fn to_version(&self) -> i64 { 35 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"ALTER TABLE bark_exit_states ADD COLUMN movement_id INTEGER \
			 REFERENCES bark_movements(id)",
			(),
		).context("add movement_id column to bark_exit_states")?;

		reconcile_existing_exits(conn)?;
		Ok(())
	}
}

fn reconcile_existing_exits(conn: &Transaction) -> anyhow::Result<()> {
	// Pull every exit row so we can classify by state and update one-by-one. The number
	// of in-progress exits is bounded by user activity (typically a handful), so loading
	// the full table is fine.
	let mut stmt = conn.prepare("SELECT vtxo_id, state FROM bark_exit_states")?;
	let rows = stmt.query_map([], |row| Ok((
		row.get::<_, String>(0)?,
		row.get::<_, String>(1)?,
	)))?.collect::<Result<Vec<_>, _>>()?;
	drop(stmt);

	for (vtxo_id, state_json) in rows {
		let state: Value = serde_json::from_str(&state_json)
			.with_context(|| format!("parse exit state for vtxo {}", vtxo_id))?;
		let class = classify(&state)
			.with_context(|| format!("classify exit state for vtxo {}", vtxo_id))?;

		// Backfill the new movement_id column. A follow-up migration converts the
		// movement status itself; here we just establish the link.
		let movement_id = find_exit_movement(conn, &vtxo_id)?;
		if let Some(mid) = movement_id {
			conn.execute(
				"UPDATE bark_exit_states SET movement_id = ?1 WHERE vtxo_id = ?2",
				params![mid, vtxo_id],
			)?;
		}

		// Roll forward / back the VTXO state, but only if it's still in the
		// `Spent` slot the old code dropped it in. If anything else has touched
		// it since (unlikely but possible), leave it alone.
		//
		// In-progress exits become `Locked` rather than `Spendable`: the user already
		// committed to this exit under the old code, so we don't want a fresh coin
		// selection pass to grab the VTXO for something else before the next progress
		// tick runs. The exit movement is the natural holder. Once the new code
		// progresses the exit past broadcast, the VTXO transitions to `Exited`.
		let current_kind = current_vtxo_state_kind(conn, &vtxo_id)?;
		if current_kind.as_deref() == Some("Spent") {
			match class {
				ExitClass::LockForExit => {
					let state_json = locked_state_json(movement_id);
					insert_vtxo_state(conn, &vtxo_id, "Locked", &state_json)?;
				},
				ExitClass::MarkExitedInProgress | ExitClass::MarkExitedTerminal => {
					insert_vtxo_state(conn, &vtxo_id, "Exited", r#"{"type":"exited"}"#)?;
				},
				ExitClass::LeaveAlone => {},
			}
		}
	}

	Ok(())
}

/// Build the JSON for a `VtxoState::Locked` row. If we found the originating exit
/// movement, name it as the holder so the lock has clear provenance; otherwise leave
/// the holder `null` — that's the same "we don't yet know the owner" shape the wallet
/// uses for fresh locked VTXOs and is unambiguous to read.
fn locked_state_json(movement_id: Option<i64>) -> String {
	match movement_id {
		Some(mid) => format!(
			r#"{{"type":"locked","holder":{{"type":"movement","id":{}}}}}"#, mid,
		),
		None => r#"{"type":"locked","holder":null}"#.to_string(),
	}
}

enum ExitClass {
	/// Start, or Processing — even if every tx is broadcast, no confirmation yet — the
	/// user has committed to the exit but it's not onchain yet. Lock the VTXO to the
	/// exit movement so coin selection can't accidentally consume it before the next
	/// progress tick, and so the new code can flip it to `Exited` once a confirmation
	/// arrives.
	LockForExit,
	/// Past the confirmation threshold (>= `AwaitingDelta`) but not yet Claimed. VTXO
	/// is `Exited` and the associated movement should be Pending.
	MarkExitedInProgress,
	/// Terminal Claimed state. VTXO is `Exited`, movement was already `Successful`.
	MarkExitedTerminal,
	/// Already-spent terminal — never produced by old builds, here for completeness.
	LeaveAlone,
}

fn classify(state: &Value) -> anyhow::Result<ExitClass> {
	let obj = state.as_object().context("exit state is not a JSON object")?;
	let tag = obj.get("type").and_then(Value::as_str).context("exit state missing `type`")?;
	Ok(match tag {
		// Pre-confirmation states all map to LockForExit — the user committed to the
		// exit but nothing is committed on-chain yet, so we lock and let the new code
		// progress it forward.
		"start" | "processing" => ExitClass::LockForExit,
		"awaiting-delta" | "claimable" | "claim-in-progress" => ExitClass::MarkExitedInProgress,
		"claimed" => ExitClass::MarkExitedTerminal,
		"vtxo-already-spent" => ExitClass::LeaveAlone,
		other => anyhow::bail!("unknown exit state tag `{}`", other),
	})
}

fn find_exit_movement(conn: &Transaction, vtxo_id: &str) -> anyhow::Result<Option<i64>> {
	// Old builds created at most one EXIT-subsystem movement per VTXO at start time;
	// take the most recent in case anyone retried.
	let mut stmt = conn.prepare(
		"SELECT bm.id FROM bark_movements bm \
		 JOIN bark_movements_input_vtxos bmiv ON bmiv.movement_id = bm.id \
		 WHERE bm.subsystem_name = ?1 AND bm.movement_kind = ?2 AND bmiv.vtxo_id = ?3 \
		 ORDER BY bm.id DESC LIMIT 1",
	)?;
	let mut rows = stmt.query(params![EXIT_SUBSYSTEM, EXIT_MOVEMENT_KIND, vtxo_id])?;
	Ok(if let Some(row) = rows.next()? { Some(row.get(0)?) } else { None })
}

fn current_vtxo_state_kind(
	conn: &Transaction,
	vtxo_id: &str,
) -> anyhow::Result<Option<String>> {
	let mut stmt = conn.prepare(
		"SELECT state_kind FROM most_recent_vtxo_state WHERE vtxo_id = ?1",
	)?;
	let mut rows = stmt.query(params![vtxo_id])?;
	Ok(if let Some(row) = rows.next()? { Some(row.get(0)?) } else { None })
}

fn insert_vtxo_state(
	conn: &Transaction,
	vtxo_id: &str,
	state_kind: &str,
	state_json: &str,
) -> anyhow::Result<()> {
	conn.execute(
		"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state) VALUES (?1, ?2, ?3)",
		params![vtxo_id, state_kind, state_json.as_bytes()],
	)?;
	Ok(())
}

#[cfg(test)]
mod test {
	use rusqlite::Connection;
	use serde_json::json;

	use crate::persist::sqlite::migrations::MigrationContext;

	use super::*;

	fn init(conn: &mut Connection) {
		// Apply every prior migration so we have a realistic schema (including the
		// `bark_movements`, `bark_exit_states`, and `bark_vtxo_state` shapes) — then
		// reset the migration counter so we can call our migration directly.
		let ctx = MigrationContext::new();
		ctx.do_all_migrations(conn).expect("migrations apply cleanly");
		conn.execute("DELETE FROM bark_exit_states", ()).unwrap();
		conn.execute("DELETE FROM bark_movements_input_vtxos", ()).unwrap();
		conn.execute("DELETE FROM bark_movements", ()).unwrap();
		conn.execute("DELETE FROM bark_vtxo_state", ()).unwrap();
		conn.execute("DELETE FROM bark_vtxo", ()).unwrap();
		// Drop the movement_id column we just added so we can re-run the migration.
		// SQLite supports DROP COLUMN since 3.35.
		conn.execute("ALTER TABLE bark_exit_states DROP COLUMN movement_id", ()).unwrap();
	}

	fn seed_vtxo(conn: &Connection, vtxo_id: &str, state_kind: &str, state_json: &str) {
		conn.execute(
			"INSERT INTO bark_vtxo (id, amount_sat) VALUES (?1, ?2)",
			params![vtxo_id, 10_000_i64],
		).unwrap();
		conn.execute(
			"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state) VALUES (?1, ?2, ?3)",
			params![vtxo_id, state_kind, state_json.as_bytes()],
		).unwrap();
	}

	fn seed_exit(conn: &Connection, vtxo_id: &str, state: &Value) {
		conn.execute(
			"INSERT INTO bark_exit_states (vtxo_id, state, history) VALUES (?1, ?2, '[]')",
			params![vtxo_id, state.to_string()],
		).unwrap();
	}

	fn seed_exit_movement(conn: &Connection, vtxo_id: &str, status: &str) -> i64 {
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
		id
	}

	fn current_state_kind(conn: &Connection, vtxo_id: &str) -> String {
		conn.query_row(
			"SELECT state_kind FROM most_recent_vtxo_state WHERE vtxo_id = ?1",
			params![vtxo_id],
			|row| row.get(0),
		).unwrap()
	}

	fn movement_status(conn: &Connection, id: i64) -> String {
		conn.query_row(
			"SELECT status FROM bark_movements WHERE id = ?1",
			params![id],
			|row| row.get(0),
		).unwrap()
	}

	fn exit_movement_id(conn: &Connection, vtxo_id: &str) -> Option<i64> {
		conn.query_row(
			"SELECT movement_id FROM bark_exit_states WHERE vtxo_id = ?1",
			params![vtxo_id],
			|row| row.get(0),
		).ok().flatten()
	}

	fn run_migration(conn: &mut Connection) {
		let tx = conn.transaction().unwrap();
		Migration0035 {}.do_migration(&tx).unwrap();
		tx.commit().unwrap();
	}

	fn current_state_json(conn: &Connection, vtxo_id: &str) -> String {
		let blob: Vec<u8> = conn.query_row(
			"SELECT state FROM most_recent_vtxo_state WHERE vtxo_id = ?1",
			params![vtxo_id], |row| row.get(0),
		).unwrap();
		String::from_utf8(blob).unwrap()
	}

	/// Exit still in `Start` — VTXO must lock to the exit movement so coin selection
	/// can't grab it before the next progress tick. The movement_id link is backfilled
	/// and the lock holder names the movement.
	#[test]
	fn start_exit_locks_vtxo_to_movement() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v1";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({ "type": "start", "tip_height": 100 }));
		let mid = seed_exit_movement(&conn, vtxo_id, "successful");

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Locked");
		let state: Value = serde_json::from_str(&current_state_json(&conn, vtxo_id)).unwrap();
		assert_eq!(state["holder"]["type"], "movement");
		assert_eq!(state["holder"]["id"], mid);
		assert_eq!(exit_movement_id(&conn, vtxo_id), Some(mid));
		// Movement status is left alone here — a follow-up migration handles that.
		assert_eq!(movement_status(&conn, mid), "successful");
	}

	/// Processing where every tx is at least broadcast — still pre-confirmation, so the
	/// VTXO is locked to the exit movement (not yet `Exited`). It flips to `Exited`
	/// when the exit progresses to `AwaitingDelta`.
	#[test]
	fn processing_all_broadcast_locks_vtxo() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v2";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({
			"type": "processing",
			"tip_height": 100,
			"transactions": [
				{ "txid": "0101010101010101010101010101010101010101010101010101010101010101",
				  "status": { "type": "awaiting-confirmation",
				              "child_txid": "0202020202020202020202020202020202020202020202020202020202020202",
				              "origin": { "type": "mempool" } } },
				{ "txid": "0303030303030303030303030303030303030303030303030303030303030303",
				  "status": { "type": "confirmed",
				              "child_txid": "0404040404040404040404040404040404040404040404040404040404040404",
				              "block": { "height": 200, "hash": "00".repeat(32) },
				              "origin": { "type": "mempool" } } }
			]
		}));
		let mid = seed_exit_movement(&conn, vtxo_id, "successful");

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Locked");
		let state: Value = serde_json::from_str(&current_state_json(&conn, vtxo_id)).unwrap();
		assert_eq!(state["holder"]["id"], mid);
	}

	/// Processing where at least one tx is still in pre-broadcast territory — VTXO is
	/// locked to the exit movement so the next progress can re-broadcast without
	/// another flow racing in.
	#[test]
	fn processing_partial_broadcast_locks_vtxo() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v3";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({
			"type": "processing",
			"tip_height": 100,
			"transactions": [
				{ "txid": "0a".repeat(32), "status": { "type": "verify-inputs" } },
				{ "txid": "0b".repeat(32),
				  "status": { "type": "awaiting-confirmation",
				              "child_txid": "0c".repeat(32),
				              "origin": { "type": "mempool" } } }
			]
		}));
		let mid = seed_exit_movement(&conn, vtxo_id, "successful");

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Locked");
		let state: Value = serde_json::from_str(&current_state_json(&conn, vtxo_id)).unwrap();
		assert_eq!(state["holder"]["id"], mid);
	}

	/// AwaitingDelta / Claimable / ClaimInProgress all behave the same way.
	#[test]
	fn post_broadcast_states_mark_exited() {
		for state in [
			json!({ "type": "awaiting-delta", "tip_height": 100,
			        "confirmed_block": { "height": 90, "hash": "11".repeat(32) },
			        "claimable_height": 1000 }),
			json!({ "type": "claimable", "tip_height": 100,
			        "claimable_since": { "height": 90, "hash": "22".repeat(32) },
			        "last_scanned_block": null }),
			json!({ "type": "claim-in-progress", "tip_height": 100,
			        "claimable_since": { "height": 90, "hash": "33".repeat(32) },
			        "claim_txid": "44".repeat(32) }),
		] {
			let mut conn = Connection::open(":memory:").unwrap();
			init(&mut conn);
			let vtxo_id = "v_post";
			seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
			seed_exit(&conn, vtxo_id, &state);
			seed_exit_movement(&conn, vtxo_id, "successful");

			run_migration(&mut conn);

			assert_eq!(current_state_kind(&conn, vtxo_id), "Exited",
				"state {} should mark VTXO Exited", state["type"]);
		}
	}

	/// Already-Claimed: VTXO is Exited (terminal) and the movement keeps its Successful status.
	#[test]
	fn claimed_exit_marks_vtxo_exited() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v4";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({
			"type": "claimed", "tip_height": 100,
			"txid": "ff".repeat(32),
			"block": { "height": 90, "hash": "ab".repeat(32) }
		}));
		let mid = seed_exit_movement(&conn, vtxo_id, "successful");

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Exited");
		assert_eq!(movement_status(&conn, mid), "successful");
		assert_eq!(exit_movement_id(&conn, vtxo_id), Some(mid));
	}

	/// An exit without a discoverable movement (very old wallet) still gets its VTXO
	/// state reconciled — we just can't backfill the link.
	#[test]
	fn exit_without_movement_still_updates_vtxo() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v5";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({
			"type": "claimed", "tip_height": 100,
			"txid": "ff".repeat(32),
			"block": { "height": 90, "hash": "ab".repeat(32) }
		}));

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Exited");
		assert_eq!(exit_movement_id(&conn, vtxo_id), None);
	}

	/// An in-progress exit without a discoverable movement still gets locked, but
	/// with no holder — the data is recoverable from current_kind alone.
	#[test]
	fn in_progress_exit_without_movement_locks_with_no_holder() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v_no_mvt";
		seed_vtxo(&conn, vtxo_id, "Spent", r#"{"type":"spent"}"#);
		seed_exit(&conn, vtxo_id, &json!({ "type": "start", "tip_height": 100 }));

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Locked");
		let state: Value = serde_json::from_str(&current_state_json(&conn, vtxo_id)).unwrap();
		assert!(state["holder"].is_null(), "holder should be null when no movement found");
	}

	/// If something else has already moved the VTXO off `Spent` (defensive: shouldn't
	/// happen in practice but the schema doesn't prevent it), don't clobber it.
	#[test]
	fn non_spent_vtxo_is_left_alone() {
		let mut conn = Connection::open(":memory:").unwrap();
		init(&mut conn);
		let vtxo_id = "v6";
		seed_vtxo(&conn, vtxo_id, "Spendable", r#"{"type":"spendable"}"#);
		seed_exit(&conn, vtxo_id, &json!({ "type": "start", "tip_height": 100 }));
		seed_exit_movement(&conn, vtxo_id, "successful");

		run_migration(&mut conn);

		assert_eq!(current_state_kind(&conn, vtxo_id), "Spendable");
	}
}
