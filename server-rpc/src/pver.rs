//! Specifying protocol versions
//!
//! Protocol versions identify the protocol clients use to speak to the server.
//!


/// Version of the initial mainnet release
pub const PROTOCOL_VERSION_BASE: u64 = 1;

/// Version that has the offboard sighash for multi-input offboards fixed
pub const PROTOCOL_VERSION_OFFBOARD_FIX: u64 = 2;

/// Version that checkpoints the lightning-receive claim.
///
/// A checkpoint gives the watchman a stopping point: if the parent (HTLC-recv)
/// VTXO is dragged on-chain, the watchman broadcasts the checkpoint instead of
/// progressing all the way to the claimed leaf and force-exiting it. Clients on
/// this version build the claim with checkpoints and the server requires it.
pub const PROTOCOL_VERSION_LN_RECEIVE_CHECKPOINT: u64 = 3;

/// Version that rounds ppm fees up to a satoshi instead of down and
/// calculates ppm expiry fees on the exact total across all VTXOs rather
/// than per VTXO.
pub const PROTOCOL_VERSION_PPM_FEE_TOTAL: u64 = 4;
