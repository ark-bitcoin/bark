#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate lazy_static;

pub mod context;
pub mod constants;
pub mod daemon;
pub mod util;
pub mod bark;
pub mod postgres;

pub use context::TestContext;
pub use daemon::{Daemon, DaemonHelper};
pub use daemon::bitcoind::{Bitcoind, BitcoindConfig};
pub use daemon::electrs::{Electrs, ElectrsConfig};
pub use daemon::aspd::Aspd;
pub use daemon::lightningd::{Lightningd, LightningdConfig};
pub use bark::{Bark, BarkConfig};


use std::fmt;
use std::str::FromStr;

use bitcoin::Amount;

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

/// Shorthand for Amount from sats
pub const fn sat(sats: u64) -> Amount {
	Amount::from_sat(sats)
}

/// Shorthand for Amount from BTC
pub fn btc(btc: impl fmt::Display) -> Amount {
	Amount::from_str(&format!("{} btc", btc))
		.expect(&format!("invalid btc amount: {}", btc))
}
