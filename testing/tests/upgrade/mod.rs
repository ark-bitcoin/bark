//! An action started under an older bark release must finish under the build
//! being tested. Each test creates the wallet with `BARK_UPGRADE_FROM_EXEC`,
//! cuts it off mid-action, then reopens the same datadir with `BARK_EXEC`,
//! which runs any new migration against a real in-flight checkpoint.
//!
//! Needs a release fetched up front, so it is excluded from `just int`. See
//! `contrib/agents/skills/upgrade-tests.md`.

mod common;

mod arkoor_send;
mod board;
mod lightning_receive;
mod lightning_send;
mod offboard;
