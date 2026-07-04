//! Integration tests that exercise the bark Rust SDK (the `bark-wallet`
//! crate's public API) directly, rather than driving the `bark` CLI binary
//! as a subprocess.
//!
//! These tests must NOT be included in the backward-compat job
//! (`compat-bark-0.1.4` in `.gitlab/tests.yml`), which substitutes an older
//! `bark` binary via `BARK_EXEC` — the substitution has no effect on tests
//! that link against the current `bark-wallet` crate, so running them in
//! that mode would silently test the current code under a "compat" label.

mod lightning;
mod offboard;
mod round;
mod vtxo_lock;
