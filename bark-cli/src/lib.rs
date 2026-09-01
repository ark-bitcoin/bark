pub mod connection;
pub mod log;
pub mod wallet;

pub mod util;

/// The marker included in the `BARK_VERSION` env variable when not built
/// from a tagged version, e.g. "0.6.0-dev".
pub const VERSION_DEV_MARKER: &str = "-dev";
