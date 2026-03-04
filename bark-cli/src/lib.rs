pub mod log;
pub mod wallet;

pub mod util;

/// The value for the `BARK_VERSION` env variable if not built from
/// a tagged version
pub const VERSION_DIRTY: &str = "DIRTY";
