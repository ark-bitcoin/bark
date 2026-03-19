//! Integration tests for the bark wallet.
//!
//! In CI these tests run under different configurations such as
//! filestore backends and chain sources.

mod arkoor;
mod base;
mod board;
mod chain_source;
mod create;
mod dust;
mod estimate;
mod exit;
mod fees;
mod lightning;
mod mailbox;
mod movement;
mod offboard;
mod onchain;
mod recover;
mod round;
mod vtxos;
