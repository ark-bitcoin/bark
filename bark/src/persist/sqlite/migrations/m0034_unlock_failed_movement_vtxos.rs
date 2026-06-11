use anyhow::Context;
use log::info;
use rusqlite::{Transaction, named_params};

use crate::vtxo::{VtxoState, VtxoStateKind};

use super::Migration;

pub struct Migration0034 {}

impl Migration for Migration0034 {
	fn name(&self) -> &str {
		"Unlock input vtxos stuck in Locked state for failed offboard movements"
	}

	fn to_version(&self) -> i64 { 34 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Old barks (<= 0.2.3) bail out of a failed offboard without
		// finishing the movement, leaving it pending forever with its input
		// vtxos locked. A legitimately pending offboard always has a
		// bark_pending_offboard row (it is awaiting confirmations), so a
		// pending offboard movement without one is dead: fail it here so the
		// unlock below releases its vtxos.
		let nb_movements = conn.execute(
			"UPDATE bark_movements
			SET status = 'failed',
			    effective_balance = 0,
			    updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now'),
			    completed_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
			WHERE status = 'pending'
			  AND subsystem_name = 'bark.offboard'
			  AND id NOT IN (SELECT movement_id FROM bark_pending_offboard)",
			[],
		).context("failed to fail dead pending offboard movements")?;

		if nb_movements > 0 {
			info!("Migration script failed {} dead pending offboard movements", nb_movements);
		}

		let state_blob = serde_json::to_vec(&VtxoState::Spendable)
			.context("failed to serialize Spendable state")?;

		// Restore to Spendable any input vtxo that is still Locked but belongs
		// to an offboard movement that already reached the Failed terminal
		// state.  This can happen when the process crashes between the
		// vtxo-unlock step and the movement-status-update step (e.g. during
		// offboard cancellation), or for the dead offboards failed above.
		let nb_rows = conn.execute(
			"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
			SELECT vs.vtxo_id, :state_kind, :state
			FROM most_recent_vtxo_state vs
			JOIN bark_movements m ON m.id = json_extract(CAST(vs.state AS TEXT), '$.holder.id')
			WHERE vs.state_kind = 'Locked'
			  AND json_extract(CAST(vs.state AS TEXT), '$.holder.type') = 'movement'
			  AND m.status = 'failed'
			  AND m.subsystem_name = 'bark.offboard'",
			named_params! {
				":state_kind": VtxoStateKind::Spendable.as_str(),
				":state": &state_blob,
			},
		).context("failed to unlock input vtxos for failed movements")?;

		if nb_rows > 0 {
			info!("Migration script fixed {} VTXOs that were stuck in locked state", nb_rows);
		}

		Ok(())
	}
}
