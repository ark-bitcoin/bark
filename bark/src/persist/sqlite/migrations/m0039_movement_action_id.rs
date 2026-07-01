use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0039 {}

impl Migration for Migration0039 {
	fn name(&self) -> &str {
		"Link movements to their owning wallet action for idempotent creation"
	}

	fn to_version(&self) -> i64 { 39 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute(
			"ALTER TABLE bark_movements ADD COLUMN action_id TEXT",
			(),
		).context("failed to add action_id column to bark_movements")?;

		// One movement per action: lets a re-driven action step find its
		// already-created movement instead of inserting a duplicate. Partial
		// so movements not owned by an action (rounds, boards, …) are exempt.
		conn.execute(
			"CREATE UNIQUE INDEX idx_bark_movements_action_id
				ON bark_movements (action_id) WHERE action_id IS NOT NULL",
			(),
		).context("failed to create unique index on bark_movements.action_id")?;

		Ok(())
	}
}
