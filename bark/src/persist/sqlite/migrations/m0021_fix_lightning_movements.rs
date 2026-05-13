use std::str::FromStr;

use anyhow::{Context, bail};
use rusqlite::{Transaction, named_params};

use ark::{ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy};
use ark::vtxo::Full;

use crate::vtxo::{VtxoLockHolder, VtxoState, VtxoStateKind};

use super::Migration;

pub struct Migration0021 {}

impl Migration for Migration0021 {
	fn name(&self) -> &str {
		"Fix lightning movements"
	}

	fn to_version(&self) -> i64 { 21 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Mark HTLC VTXOs which are locked by a finished movement as spent.
		//
		// We access the raw schema directly here rather than going through
		// `query::*` helpers because those helpers track the current
		// (post-m0029) schema; at m0021 the bark_vtxo table still has a
		// single `raw_vtxo` blob column.
		let mut stmt = conn.prepare(
			"SELECT v.id, v.raw_vtxo, vs.state
			FROM bark_vtxo v
			JOIN most_recent_vtxo_state vs ON v.id = vs.vtxo_id",
		)?;
		let rows: Vec<(String, Vec<u8>, Vec<u8>)> = stmt
			.query_map((), |r| Ok((
				r.get::<_, String>(0)?,
				r.get::<_, Vec<u8>>(1)?,
				r.get::<_, Vec<u8>>(2)?,
			)))?
			.collect::<Result<_, _>>()?;
		drop(stmt);

		for (id, raw_vtxo, state_blob) in rows {
			let vtxo = Vtxo::<Full>::deserialize(&raw_vtxo)
				.context("failed to deserialize raw_vtxo")?;
			let state: VtxoState = serde_json::from_slice(&state_blob)
				.context("failed to decode vtxo state")?;

			let is_htlc = match vtxo.policy() {
				VtxoPolicy::Pubkey(_) => false,
				VtxoPolicy::ServerHtlcSend(_) => true,
				VtxoPolicy::ServerHtlcRecv(_) => true,
			};
			let movement_id = match (is_htlc, state) {
				(true, VtxoState::Locked { holder: Some(VtxoLockHolder::Movement { id }) }) => id,
				_ => continue,
			};

			// If the movement is finished, mark this VTXO as spent. This bug
			// was caused by lightning code not marking HTLCs as spent after
			// being swapped.
			let movement_status = {
				let mut s = conn.prepare(
					"SELECT status FROM bark_movements_view WHERE id = ?1",
				)?;
				let mut rows = s.query([movement_id.0])?;
				match rows.next()? {
					Some(row) => row.get::<_, String>("status")?,
					None => bail!("Movement {} not found", movement_id),
				}
			};

			if movement_status == "finished" {
				let vtxo_id = VtxoId::from_str(&id)
					.context("invalid vtxo id in bark_vtxo")?;
				let inserted = conn.prepare(
					r"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
					SELECT :vtxo_id, :state_kind, :state FROM most_recent_vtxo_state
					WHERE
						vtxo_id = :vtxo_id AND
						state_kind IN (SELECT atom FROM json_each(:old_states)) AND
						state_kind != :state_kind",
				)?.execute(named_params! {
					":vtxo_id": vtxo_id.to_string(),
					":state_kind": VtxoState::Spent.kind().as_str(),
					":state": serde_json::to_vec(&VtxoState::Spent)?,
					":old_states": serde_json::to_string(&[VtxoStateKind::Locked])?,
				}).context("failed to update vtxo state")?;
				let _ = inserted;
			}
		}

		Ok(())
	}
}
