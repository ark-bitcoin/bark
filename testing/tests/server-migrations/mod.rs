//! Integration tests that upgrade a running captaind mid-flow.
//!
//! Each test starts captaind on a previous release binary (the
//! OLD_CAPTAIND_EXEC env var), brings a lightning payment into some
//! in-flight state, then stops the server, swaps to the current binary
//! (CAPTAIND_EXEC) and starts it again — running the database
//! migrations on startup. The tests only assert that payments keep
//! succeeding across the upgrade; they don't inspect database records.
//!
//! Run with e.g.:
//! ```text
//! OLD_CAPTAIND_EXEC=/path/to/captaind-0.7.0 just int-server-migrations
//! ```

mod lightning;
