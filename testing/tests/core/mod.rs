//! Tests for the testing framework itself (ark-testing) and
//! some key non-server functionality.
//!
//! These tests will run only once and are fully independent of the
//! configuration of bark.
//!
//! These tests verify that the core infrastructure used by all other
//! integration tests works correctly: daemon lifecycle management,
//! process locking, and chain setup utilities.

mod bitcoind;
mod lightning;
mod pid_lock;
mod wallet_ext;
