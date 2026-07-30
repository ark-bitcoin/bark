//! Track per-vtxo recovery registration.
//!
//! The recovery catch-up re-posts every owned vtxo's ID to the recovery
//! mailbox and re-registers its signed transaction chain during sync. Both
//! endpoints are idempotent, but re-uploading whole exit chains for every
//! vtxo on every sync is needlessly heavy. The new `registered` flag records
//! that both operations succeeded once, so the catch-up can skip those
//! vtxos.
//!
//! Existing rows start unset, so every wallet re-asserts its recovery state
//! one more time after the upgrade and is cheap from then on. If a
//! server-side recovery issue is ever discovered, a follow-up migration can
//! reset the flag to force a full re-upload.

use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0042 {}

impl Migration for Migration0042 {
	fn name(&self) -> &str {
		"Track per-vtxo recovery registration so sync only catches up unregistered vtxos"
	}

	fn to_version(&self) -> i64 { 42 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"ALTER TABLE bark_vtxo ADD COLUMN registered INTEGER NOT NULL DEFAULT 0",
			(),
		).context("failed to add bark_vtxo.registered")?;

		// Recreate vtxo_view to expose the new column.
		conn.execute("DROP VIEW vtxo_view", ())
			.context("failed to drop vtxo_view")?;
		conn.execute(
			"CREATE VIEW vtxo_view AS
			SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_bare,
				v.exit_depth,
				v.exit_tx_weight,
				v.registered,
				v.created_at,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id",
			(),
		).context("failed to recreate vtxo_view")?;

		Ok(())
	}
}
