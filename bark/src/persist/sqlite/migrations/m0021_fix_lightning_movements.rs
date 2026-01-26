use anyhow::Context;
use rusqlite::Transaction;

use ark::VtxoPolicy;

use crate::persist::sqlite::query;
use crate::vtxo::{VtxoState, VtxoStateKind};

use super::Migration;

pub struct Migration0021 {}

impl Migration for Migration0021 {
	fn name(&self) -> &str {
		"Fix lightning movements"
	}

	fn to_version(&self) -> i64 { 21 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Mark HTLC VTXOs which are locked by a finished movement as spent
		let vtxos = query::get_all_vtxos(conn).context("failed to get all vtxos")?;
		for wallet_vtxo in vtxos {
			let is_htlc = match wallet_vtxo.policy() {
				VtxoPolicy::Pubkey(_) => false,
				VtxoPolicy::ServerHtlcSend(_) => true,
				VtxoPolicy::ServerHtlcRecv(_) => true,
			};
			match (is_htlc, wallet_vtxo.state.clone()) {
				(true, VtxoState::Locked { movement_id: Some(movement_id) }) => {
					// Get the movement status, if it's finished, mark this VTXO as spent. This
					// issue was caused by a bug in lightning code where HTLCs were not marked as
					// spent after being swapped.
					let movement_status = {
						let mut statement = conn.prepare(
							"SELECT status FROM bark_movements_view WHERE id = ?1",
						)?;
						let mut rows = statement.query([movement_id.0])?;
						if let Some(row) = rows.next()? {
							Ok(row.get::<_, String>("status")?)
						} else {
							Err(anyhow!("Movement {} not found", movement_id))
						}
					}?;

					if movement_status == "finished" {
						query::update_vtxo_state_checked(
							conn, wallet_vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Locked],
						).context("failed to update vtxo state")?;
					}
				},
				_ => continue,
			}
		}

		// Now run queries.
		let queries = [
		];

		for query in queries {
			conn.execute(query, ()).context("failed to execute migration")?;
		}

		Ok(())
	}
}

