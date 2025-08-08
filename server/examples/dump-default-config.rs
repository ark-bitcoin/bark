//!
//! This "example" is used in dev and CI to dump the default values
//! for the server config to stdout.
//!

use std::io;

fn main() {
	server::Config::default()
		.write_into(&mut io::stdout())
		.expect("error writing to stdout");
}
