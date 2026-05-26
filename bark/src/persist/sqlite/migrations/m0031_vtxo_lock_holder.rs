use anyhow::Context;
use rusqlite::{Transaction, named_params};

use crate::movement::MovementId;
use crate::vtxo::{VtxoLockHolder, VtxoState};

use super::Migration;

pub struct Migration0031 {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum LegacyVtxoState {
	Spendable,
	Locked { movement_id: Option<MovementId> },
	Spent,
}

impl From<LegacyVtxoState> for VtxoState {
	fn from(state: LegacyVtxoState) -> Self {
		match state {
			LegacyVtxoState::Spendable => VtxoState::Spendable,
			LegacyVtxoState::Locked { movement_id } => {
				match movement_id {
					Some(id) => VtxoState::Locked { holder: Some(VtxoLockHolder::Movement { id }) },
					None => VtxoState::Locked { holder: None },
				}
			},
			LegacyVtxoState::Spent => VtxoState::Spent,
		}
	}
}

impl Migration for Migration0031 {
	fn name(&self) -> &str {
		"Rewrite locked vtxo state from movement_id to holder enum"
	}

	fn to_version(&self) -> i64 { 31 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let mut stmt = conn.prepare(
			"SELECT id, state FROM bark_vtxo_state WHERE state_kind = 'Locked'",
		)?;
		let rows: Vec<(i64, Vec<u8>)> = stmt
			.query_map((), |row| Ok((
				row.get::<_, i64>(0)?,
				row.get::<_, Vec<u8>>(1)?,
			)))?
			.collect::<Result<_, _>>()?;
		drop(stmt);

		for (id, bytes) in rows {
			let value: LegacyVtxoState = serde_json::from_slice(&bytes)
				.context("failed to decode locked vtxo state")?;

			conn.execute(
				"UPDATE bark_vtxo_state SET state = :state WHERE id = :id",
				named_params! {
					":state": serde_json::to_vec(&VtxoState::from(value))
						.context("failed to encode rewritten locked vtxo state")?,
					":id": id,
				},
			).context("failed to rewrite bark_vtxo_state locked row")?;
		}

		Ok(())
	}
}
