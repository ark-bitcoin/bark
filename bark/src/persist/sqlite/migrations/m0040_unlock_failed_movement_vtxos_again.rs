use rusqlite::Transaction;

use super::Migration;
use super::m0034_unlock_failed_movement_vtxos::Migration0034;

pub struct Migration0040 {}

impl Migration for Migration0040 {
	fn name(&self) -> &str {
		"Unlock input vtxos stuck in Locked state for failed offboard movements, again"
	}

	fn to_version(&self) -> i64 { 40 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Barks released after Migration0034 ran can still fail an offboard
		// without releasing its input vtxos, so users have accumulated stuck
		// vtxos again since that one-time cleanup. Run the exact same cleanup
		// once more. It has to run before the next migration: telling a dead
		// pending offboard movement apart from a live one relies on the
		// `bark_pending_offboard` table, which the next migration drops.
		Migration0034{}.do_migration(conn)
	}
}
