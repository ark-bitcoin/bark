//!
//! This module defines an alternate server struct that can be used to complement
//! captaind or the main [crate::Server] struct.
//!
//! It runs a subset of the server services, namely those that are not required
//! for user functionality.
//!

mod config;
mod daemon;

pub use config::Config;
pub use daemon::Daemon;
