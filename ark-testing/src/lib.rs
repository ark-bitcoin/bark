#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod context;
pub mod constants;
pub mod daemon;
pub mod util;
pub mod bark;

pub use context::TestContext;
pub use daemon::{Daemon, DaemonHelper};
pub use daemon::bitcoind::{Bitcoind, BitcoindConfig};
pub use daemon::aspd::{Aspd, AspdConfig};
pub use daemon::lightningd::{Lightningd, LightningdConfig};
pub use bark::{Bark, BarkConfig};


#[macro_export]
macro_rules! assert_eq {
	($left:expr, $right:expr $(,)?) => { std::assert_eq!($left, $right) };
	($left:expr, $right:expr, $($arg:tt)+) => { std::assert_eq!($left, $right, $($arg)+) };

	// USAGE: when a test fails and you want to see all failed assertions in one go,
	// comment out the two above lines so that the below lines will match.

	($left:expr, $right:expr $(,)?) => {
		match (&$left, &$right) {
			(left_val, right_val) => {
				if !(*left_val == *right_val) {
					println!("ASSERT FAILED: {:?} != {:?} ({}:{})",
						left_val, right_val, file!(), line!(),
					);
				}
			}
		}
	};
	($left:expr, $right:expr, $($arg:tt)+) => {
		match (&$left, &$right) {
			(left_val, right_val) => {
				if !(*left_val == *right_val) {
					println!("ASSERT FAILED: {:?} != {:?} ({}:{}): {}",
						left_val, right_val, file!(), line!(), format_args!($($arg)+),
					);
				}
			}
		}
	};
}
