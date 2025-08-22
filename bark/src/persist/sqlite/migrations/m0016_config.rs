use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0016 {}

impl Migration for Migration0016 {

	fn name(&self) -> &str {
		"No config in database"
	}

	fn to_version(&self) -> i64 { 16 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		conn.execute("DROP table IF EXISTS bark_config", [])
			.with_context(|| "Failed to drop `bark_config`")?;

		Ok(())
	}
}

