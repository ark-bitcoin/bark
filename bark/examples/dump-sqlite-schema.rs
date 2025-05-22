//!
//! This "example" is used in dev and CI to dump sqlite db schema
//! for the bark database to stdout.
//!

use std::{fs, process};
use std::path::PathBuf;

fn main() {
	let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

	let tmp_file = root.join("tmp-bark-schema.sqlite");
	if tmp_file.exists() != false {
		fs::remove_file(&tmp_file).expect("failed to remove existing temporary db file");
	}

	bark::persist::sqlite::SqliteClient::open(tmp_file.clone())
		.expect("error opening sqlite file");

	let status = process::Command::new("sqlite3")
		.arg(&tmp_file.display().to_string())
		.arg(".schema")
		.stdout(process::Stdio::inherit())
		.spawn().unwrap()
		.wait().unwrap()
		.code().unwrap_or(1);

	fs::remove_file(&tmp_file).expect("failed to remove temporary db file");

	process::exit(status);
}

