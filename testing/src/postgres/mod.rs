
//! The testing framework will create postgres
//! databases that are required to run the server.
//!
//! It can be configured in two different methods
//! - test-managed hosts (default)
//! - externally hosted postgres
//!
//! ## Test Managed hosts
//!
//! The test framework will spin-up a postgres-host
//! for each test. This requires that all postgres binaries
//! such as `init_db` and `pg_ctl` are installed on the system.
//!
//! You can point the test framework to a specific installation
//! using the `POSTGRES_BINS` environment variable. By default
//! it will take the binaries that are available on the path.
//!
//! ## Externally Hosted
//!
//! In an externally hosted set-up the developer or (CI)
//! runs a postgres server. The test framework will connect
//! to this postgres host and create a separate database for
//! every test.
//!
//! This method is used if the `TEST_POSTGRES_HOST` environment
//! variable is set.
//!

mod external;
mod test_managed;
mod query;

use std::path::PathBuf;


use tokio_postgres::Client;

use self::{external::ExternallyManagedPostgres, test_managed::TestManagedPostgres};

/// Check if the testing frame work is configured
/// to use an external host
pub fn externally_hosted() -> bool {
	external::postgres_host().is_some()
}

pub enum PostgresDatabaseManager {
	ExternallyHosted(ExternallyManagedPostgres),
	TestManaged(TestManagedPostgres),
}

impl PostgresDatabaseManager {
	pub async fn init(datadir: PathBuf) -> Self {
		if externally_hosted() {
			Self::ExternallyHosted(ExternallyManagedPostgres::init().await)
		}
		else {
			Self::TestManaged(TestManagedPostgres::init(datadir).await)
		}
	}

	pub async fn request_database(&self, db_name: &str) -> server::config::Postgres {
		match self{
			Self::ExternallyHosted(m) => m.request_database(db_name).await,
			Self::TestManaged(m) => m.request_database(db_name).await,
		}
	}

	/// Returns a client for a specific database.
	pub async fn database_client(&self, db_name: Option<&str>) -> Client {
		match self {
			Self::ExternallyHosted(p) => p.database_client(db_name).await,
			Self::TestManaged(p) => p.database_client(db_name).await,
		}
	}

	/// Returns a client for the global database, can be used to create test databases.
	pub async fn global_client(&self) -> Client {
		match self {
			Self::ExternallyHosted(p) => p.global_client().await,
			Self::TestManaged(p) => p.global_client().await,
		}
	}
}
