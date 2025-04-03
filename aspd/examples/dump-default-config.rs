//!
//! This "example" is used in dev and CI to dump the default values
//! for the aspd config into a file and ensure the checked-in
//! config.default.toml file is up-to-date.
//!

use std::path::PathBuf;

fn main() {
	let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let cfg = aspd::Config::default();
	let path = root.join("config.default.toml");
	println!("Writing config file to {}", path.display());
	cfg.write_to_file(&path).expect("error writing file");
}
