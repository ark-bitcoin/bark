use anyhow::Context;
use rusqlite::Transaction;
use serde_json::{Map, Value};

use super::Migration;

pub struct Migration0032 {}

impl Migration for Migration0032 {
	fn name(&self) -> &str {
		"Rewrite persisted ExitTxStatus variants for the unilateral exit refactor"
	}

	fn to_version(&self) -> i64 { 32 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let mut stmt = conn.prepare("SELECT vtxo_id, state, history FROM bark_exit_states")
			.context("prepare select bark_exit_states")?;
		let rows = stmt.query_map([], |row| {
			Ok((
				row.get::<_, String>(0)?,
				row.get::<_, String>(1)?,
				row.get::<_, String>(2)?,
			))
		}).context("query bark_exit_states")?.collect::<Result<Vec<_>, _>>()?;
		drop(stmt);

		for (vtxo_id, state, history) in rows {
			let mut state: Value = serde_json::from_str(&state)
				.with_context(|| format!("parse state for vtxo {}", vtxo_id))?;
			let mut history: Value = serde_json::from_str(&history)
				.with_context(|| format!("parse history for vtxo {}", vtxo_id))?;

			rewrite_exit_state(&mut state)
				.with_context(|| format!("rewrite state for vtxo {}", vtxo_id))?;
			if let Value::Array(items) = &mut history {
				for (i, item) in items.iter_mut().enumerate() {
					rewrite_exit_state(item)
						.with_context(|| format!("rewrite history[{}] for vtxo {}", i, vtxo_id))?;
				}
			} else {
				anyhow::bail!("history for vtxo {} is not a JSON array", vtxo_id);
			}

			conn.execute(
				"UPDATE bark_exit_states SET state = ?2, history = ?3 WHERE vtxo_id = ?1",
				(&vtxo_id, state.to_string(), history.to_string()),
			).with_context(|| format!("update bark_exit_states for vtxo {}", vtxo_id))?;
		}

		Ok(())
	}
}

/// Rewrites a serialised `ExitState` value in place, mapping pre-refactor
/// `ExitTxStatus` variants to their post-refactor equivalents.
///
/// Only `processing` states carry transactions with statuses, so all other
/// states are returned unchanged.
fn rewrite_exit_state(state: &mut Value) -> anyhow::Result<()> {
	let Some(obj) = state.as_object_mut() else {
		anyhow::bail!("ExitState is not a JSON object: {}", state);
	};
	let type_tag = obj.get("type").and_then(Value::as_str).unwrap_or("");
	if type_tag != "processing" {
		return Ok(());
	}
	let Some(transactions) = obj.get_mut("transactions").and_then(Value::as_array_mut) else {
		return Ok(());
	};
	for tx in transactions {
		let Some(status) = tx.get_mut("status") else { continue };
		rewrite_status(status)?;
	}
	Ok(())
}

fn rewrite_status(status: &mut Value) -> anyhow::Result<()> {
	let Some(obj) = status.as_object_mut() else {
		anyhow::bail!("ExitTxStatus is not a JSON object: {}", status);
	};
	let type_tag = obj.get("type").and_then(Value::as_str).unwrap_or("").to_string();
	match type_tag.as_str() {
		"verify-inputs"
		| "awaiting-input-confirmation"
		| "awaiting-cpfp-broadcast"
		| "awaiting-confirmation"
		| "confirmed" => {
			// Either already in new form (idempotent re-run) or unchanged across the refactor.
		},
		"needs-signed-package" | "needs-replacement-package" => {
			let mut new = Map::new();
			new.insert("type".into(), Value::String("awaiting-cpfp-broadcast".into()));
			*obj = new;
		},
		"needs-broadcasting" | "broadcast-with-cpfp" => {
			let child_txid = obj.remove("child_txid")
				.with_context(|| format!("{} missing child_txid", type_tag))?;
			let origin = obj.remove("origin")
				.with_context(|| format!("{} missing origin", type_tag))?;
			let mut new = Map::new();
			new.insert("type".into(), Value::String("awaiting-confirmation".into()));
			new.insert("child_txid".into(), child_txid);
			new.insert("origin".into(), origin);
			*obj = new;
		},
		other => {
			anyhow::bail!("unknown ExitTxStatus variant '{}'", other);
		},
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use rusqlite::Connection;
	use serde_json::json;

	use crate::exit::ExitState;
	use crate::persist::sqlite::migrations::MigrationContext;

	use super::*;

	fn run_migrations_up_to_28(conn: &mut Connection) {
		let ctx = MigrationContext::new();
		// `do_all_migrations` runs everything registered; the test only relies on the
		// schema being at >= 28 before we seed pre-refactor rows.
		ctx.do_all_migrations(conn).expect("migrations apply cleanly");
	}

	fn seed_row(conn: &Connection, vtxo_id: &str, state: &Value, history: &Value) {
		conn.execute(
			"INSERT INTO bark_exit_states (vtxo_id, state, history) VALUES (?1, ?2, ?3)",
			(vtxo_id, state.to_string(), history.to_string()),
		).unwrap();
	}

	fn fetch(conn: &Connection, vtxo_id: &str) -> (Value, Value) {
		let (state, history): (String, String) = conn.query_row(
			"SELECT state, history FROM bark_exit_states WHERE vtxo_id = ?1",
			[vtxo_id],
			|r| Ok((r.get(0)?, r.get(1)?)),
		).unwrap();
		(serde_json::from_str(&state).unwrap(), serde_json::from_str(&history).unwrap())
	}

	#[test]
	fn rewrite_each_old_variant() {
		let txid_a = "0101010101010101010101010101010101010101010101010101010101010101";
		let txid_b = "0202020202020202020202020202020202020202020202020202020202020202";
		let txid_c = "0303030303030303030303030303030303030303030303030303030303030303";
		let txid_d = "0404040404040404040404040404040404040404040404040404040404040404";

		let origin = json!({ "type": "wallet", "confirmed_in": null });

		let old_state = json!({
			"type": "processing",
			"tip_height": 100,
			"transactions": [
				{ "txid": txid_a, "status": { "type": "needs-signed-package" } },
				{ "txid": txid_b, "status": {
					"type": "needs-replacement-package",
					"min_fee_rate": 1000,
					"min_fee": 12345,
				} },
				{ "txid": txid_c, "status": {
					"type": "needs-broadcasting",
					"child_txid": txid_d,
					"origin": origin,
				} },
				{ "txid": txid_d, "status": {
					"type": "broadcast-with-cpfp",
					"child_txid": txid_c,
					"origin": origin,
				} },
				{ "txid": txid_a, "status": { "type": "verify-inputs" } },
			]
		});
		let history = json!([
			{ "type": "start", "tip_height": 99 },
			{
				"type": "processing",
				"tip_height": 99,
				"transactions": [
					{ "txid": txid_a, "status": { "type": "needs-signed-package" } },
				]
			},
		]);

		let mut conn = Connection::open(":memory:").unwrap();
		run_migrations_up_to_28(&mut conn);

		// Wipe and re-seed so we test the rewrite path even though `do_all_migrations` has
		// already pushed the schema past 0029. The migration is idempotent over its own output.
		conn.execute("DELETE FROM bark_exit_states", ()).unwrap();
		seed_row(&conn, "vtxo-1", &old_state, &history);

		let tx = conn.transaction().unwrap();
		Migration0032 {}.do_migration(&tx).unwrap();
		tx.commit().unwrap();

		let (new_state, new_history) = fetch(&conn, "vtxo-1");

		let txs = new_state["transactions"].as_array().unwrap();
		assert_eq!(txs[0]["status"], json!({ "type": "awaiting-cpfp-broadcast" }));
		assert_eq!(txs[1]["status"], json!({ "type": "awaiting-cpfp-broadcast" }));
		assert_eq!(txs[2]["status"], json!({
			"type": "awaiting-confirmation",
			"child_txid": txid_d,
			"origin": origin,
		}));
		assert_eq!(txs[3]["status"], json!({
			"type": "awaiting-confirmation",
			"child_txid": txid_c,
			"origin": origin,
		}));
		assert_eq!(txs[4]["status"], json!({ "type": "verify-inputs" }));

		assert_eq!(new_history[0], json!({ "type": "start", "tip_height": 99 }));
		assert_eq!(
			new_history[1]["transactions"][0]["status"],
			json!({ "type": "awaiting-cpfp-broadcast" })
		);

		// Migrated JSON must deserialize cleanly as the new ExitState type.
		let _: ExitState = serde_json::from_value(new_state).unwrap();
		for item in new_history.as_array().unwrap() {
			let _: ExitState = serde_json::from_value(item.clone()).unwrap();
		}
	}
}
