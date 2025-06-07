
//! The testing framework will create postgres
//! databases that are required to run aspd.
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

pub mod external;
pub mod test_managed;

/// Check if the testing frame work is configured
/// to use an external host
pub fn externally_hosted() -> bool {
	external::postgres_host().is_some()
}
