
//! In this module, we define all our log messages.
//!
//! TODO(stevenroose) ideally we'd do this a bit more efficiently
//! I'd like to improve to
//! - have the struct definitions be independent, so we can easily add docs
//! - let the macro just do the impls
//! - somehow build a wrapper that uses serde to be a `Source` and use serde also
//!   to deserialize from the log message

use bitcoin::{Amount, OutPoint, Txid};
use serde::{Deserialize, Serialize};



// round flow

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundStarted {
	pub round_id: u64,
}
impl_slog!(RoundStarted, Info, "Round started");

