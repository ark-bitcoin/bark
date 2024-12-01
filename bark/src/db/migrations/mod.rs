mod m0001_initial_version;

use anyhow::Context;
use rusqlite::{Connection, Transaction};

use m0001_initial_version::Migration0001;

pub struct MigrationContext {}

impl MigrationContext {

	/// Creates a new migration context
	pub fn new() -> Self {
		MigrationContext {}
	}

	/// Perform all initliazation scripts
	pub fn do_all_migrations(&self, conn: &mut Connection) -> anyhow::Result<()> {
		let tx = conn.transaction().context("Failed to start transcation")?;
		self.init_migrations(&tx)?;
		tx.commit().context("Failed to commit transaction")?;

		// Run all migration scripts
		self.try_migration(conn, &Migration0001{})?;
		Ok(())
	}

	/// Initiliazes the migrations table in the database if needed
	///
	/// This function returns the current schema sversion if succesful
	fn init_migrations(&self, conn: &Connection) -> anyhow::Result<i64> {
		self.create_migrations_table_if_not_exists(conn)?;
		match self.get_current_version(conn) {
			Ok(version) => Ok(version),
			Err(_) => {
				// The database hasn't been initialized yet
				self.update_version(conn, 0)?;
				Ok(0)
			}
		}
	}

	/// Attempts to perform a migration if needed
	fn try_migration(
		&self,
		conn: &mut Connection,
		migration: &impl Migration
	) -> anyhow::Result<()> {
		// Start the transaction
		let tx = conn.transaction().context("Failed to init transaction")?;

		let current_version = self.get_current_version(&tx)?;
		let from_version = migration.from_version();

		if current_version == from_version {
			info!("Performing migration {}", migration.summary());
			migration.do_migration(&tx)?;
			self.update_version(&tx, migration.to_version())?;
		}
		else if current_version < from_version {
			bail!("Failed to perform migration. Database is at {} for migration {}",
				current_version,
				migration.summary()
			);
		}
		else {
			trace!("Skipping migration {}. Nothing to be done", migration.summary());
		};
		tx.commit().context("Failed to commit transaction")?;
		Ok(())
	}

	/// Retrieves the current schema version
	fn get_current_version(&self, conn: &Connection) -> anyhow::Result<i64> {
		const ERR_MSG : &'static str = "Failed to get_current_version from database";

		let query = "SELECT value FROM migrations ORDER BY value DESC LIMIT 1";
		let mut statement = conn.prepare(query).context(ERR_MSG)?;
		let mut rows = statement.query(()).context(ERR_MSG)?;

		let row = rows.next().context(ERR_MSG)?
			.context("the current schema version is not defined in the databases")?;
		Ok(row.get(0).context(ERR_MSG)?)
	}

	/// Update schema version
	fn update_version(&self, conn: &Connection, new_version: i64) -> anyhow::Result<i64> {
		const ERR_MSG : &'static str = "Failed to update_version for database";

		let query = "INSERT INTO migrations (value) VALUES (?1)";
		let mut statement = conn.prepare(query).context(ERR_MSG)?;
		statement.execute([new_version]).context(ERR_MSG)?;

		Ok(new_version)
	}


	/// Creates the migrations table if it doesn't exist yet
	fn create_migrations_table_if_not_exists(&self, conn: &Connection) -> anyhow::Result<()> {
		let query =
			"CREATE TABLE IF NOT EXISTS migrations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				created_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
				value INTEGER NOT NULL
			)";

		conn.execute(query, ()).context("Failed to create migration table")?;

		Ok(())
	}

}

trait Migration {
	fn name(&self) -> &str;
	fn to_version(&self) -> i64;

	fn from_version(&self) -> i64 {
		self.to_version() -1
	}

	/// Performs the migration script on the provided connection
	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()>;

	fn summary(&self) -> String {
		format!("{}->{}:'{}'", self.from_version(), self.to_version(), self.name())
  }
}


#[cfg(test)]
mod test {
	use super::*;

	fn table_exists(conn: &Connection, table_name: &str) -> anyhow::Result<bool> {
		let query = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?";
		let mut statement = conn.prepare(query).context("Invalid query")?;
		let mut rows = statement.query((table_name,)).context("Failed to execute query")?;

		if let Some(_row) = rows.next().unwrap() {
			return Ok(true)
		} else {
			return Ok(false)
		}
	}

	/// Checks if schema matches the initial version
	fn assert_current_version(conn: &Connection, expected: i64) -> anyhow::Result<()> {
		let ctx = MigrationContext::new();
		let current_version = ctx.get_current_version(conn)?;
		if current_version == expected {
			Ok(())
		} else {
			bail!("Migration error; Expected version {} but database was at {}", expected, current_version);
		}
	}

	#[test]
	fn test_set_schema_version() {
		let conn = rusqlite::Connection::open(":memory:").unwrap();
		let migs = MigrationContext::new();

		migs.init_migrations(&conn).unwrap();
		assert_current_version(&conn, 0).unwrap();

		migs.update_version(&conn, 1).unwrap();
		assert_current_version(&conn, 1).unwrap();
	}

	#[test]
	fn test_good_migration() {
		let mut conn = rusqlite::Connection::open(":memory:").unwrap();
		let migs =MigrationContext::new();

		migs.init_migrations(&conn).unwrap();
		assert_current_version(&conn, 0).unwrap();

		// Perform the mgiration and confirm it took effect
		migs.try_migration(&mut conn, &Migration0001{}).unwrap();
		assert_current_version(&conn, 1).unwrap();
		assert!(table_exists(&conn, "vtxo").unwrap());
		assert!(table_exists(&conn, "vtxo_state").unwrap());

		// The migration can be run multiple times
		migs.try_migration(&mut conn, &Migration0001{}).unwrap();
	}

	struct BadMigration {}

	impl Migration for BadMigration {

		fn name(&self) -> &str { "Bad migration"}
		fn to_version(&self) -> i64 { 1 }
		fn do_migration(&self, tx: &Transaction) -> anyhow::Result<()> {

			let good_query =
				"CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER)";
			let bad_query = "NOT VALID SQL";

			tx.execute(good_query, ())?;
			tx.execute(bad_query, ())?;
			Ok(())
		}
	}

	#[test]
	fn test_bad_migration() {
		let mut conn = rusqlite::Connection::open_in_memory().unwrap();
		let migs = MigrationContext::new();

		migs.init_migrations(&conn).unwrap();
		migs.try_migration(&mut conn, &BadMigration{})
			.expect_err("The bad migration failed");

		// The version hasn't been edited
		assert_current_version(&conn, 0).unwrap();

		// The table hasn't been created
		assert!(! table_exists(&conn, "test").unwrap());
	}
}
