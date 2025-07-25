
use anyhow::Context;
use rusqlite::Transaction;

use super::Migration;

pub struct Migration0010 {}

impl Migration for Migration0010 {
	fn name(&self) -> &str {
		"remove keychain column from vtxo table"
	}

	fn to_version(&self) -> i64 { 10 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let queries = [
			"ALTER TABLE bark_vtxo_key RENAME TO bark_vtxo_key_old;",

			"CREATE TABLE bark_vtxo_key (
				public_key TEXT NOT NULL PRIMARY KEY,
				idx INTEGER NOT NULL UNIQUE
			);",

			"INSERT INTO bark_vtxo_key (public_key, idx)
			SELECT public_key, idx FROM bark_vtxo_key_old;",

			"DROP TABLE bark_vtxo_key_old;",
		];
		for (i, query) in queries.into_iter().enumerate() {
			conn.execute(query, ()).with_context(|| format!("error in query idx #{}", i))?;
		}
		Ok(())
	}
}
