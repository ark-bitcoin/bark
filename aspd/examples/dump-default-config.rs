//!
//! This "example" is used in dev and CI to dump the default values
//! for the aspd config to stdout.
//!

use std::io;

fn main() {
	aspd::Config::default()
		.write_into(&mut io::stdout())
		.expect("error writing to stdout");
}
