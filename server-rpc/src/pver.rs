//! Specifying protocol versions
//!
//! Protocol versions identify the protocol clients use to speak to the server.
//!


/// Version of the initial mainnet release
pub const PROTOCOL_VERSION_BASE: u64 = 1;

/// Version that has the offboard sighash for multi-input offboards fixed
pub const PROTOCOL_VERSION_OFFBOARD_FIX: u64 = 2;
