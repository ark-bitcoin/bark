
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;


fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rerun-if-env-changed=GIT_HASH");
	println!("cargo:rerun-if-env-changed=SERVER_VERSION");

	if env::var("GIT_HASH").is_err() {
		// Get the Git commit hash
		let output = Command::new("git").args(["rev-parse", "HEAD"]).output()
			.expect("Failed to execute 'git rev-parse HEAD' command");

		let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
		println!("cargo:rustc-env=GIT_HASH={}", git_hash);
	}

	// Determine version from git tag or dev
	if env::var("SERVER_VERSION").is_err() {
		// Try to get tags pointing to current commit
		let output = Command::new("git")
			.args(["tag", "--points-at", "HEAD"])
			.output()
			.expect("Failed to execute 'git tag --points-at HEAD' command");

		let tags = String::from_utf8_lossy(&output.stdout);

		// Look for a tag matching server-X.Y.Z pattern. Builds not made from
		// a release tag keep the crate version as a readable base but get
		// a -dev suffix.
		let version = tags.lines()
			.find(|line| line.starts_with("server-"))
			.and_then(|tag| tag.strip_prefix("server-"))
			.map(|v| v.to_string())
			.unwrap_or_else(|| {
				let base = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
				format!("{}-dev", base)
			});

		println!("cargo:rustc-env=SERVER_VERSION={}", version);
	}

	generate_migrations();
}

/// Generates the embedded database migrations module.
///
/// refinery's embed_migrations! macro embeds the migration files in filesystem
/// readdir order, which differs between machines and makes the build
/// unreproducible. Generate the equivalent module from a sorted file list.
fn generate_migrations() {
	println!("cargo:rerun-if-changed=src/database/migrations");

	let mut files = fs::read_dir("src/database/migrations")
		.expect("failed to read migrations directory")
		.map(|entry| entry.expect("failed to read migrations directory").path())
		.filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
		.collect::<Vec<_>>();
	files.sort();

	let mut code = String::from("pub fn runner() -> ::refinery::Runner {\n");
	code.push_str("\tlet migrations = vec![\n");
	for file in &files {
		let name = file.file_stem().unwrap().to_str()
			.expect("non-utf8 migration filename");
		let path = fs::canonicalize(file).unwrap();
		code.push_str(&format!(
			"\t\t::refinery::Migration::unapplied({:?}, include_str!({:?})).unwrap(),\n",
			name, path,
		));
	}
	code.push_str("\t];\n\t::refinery::Runner::new(&migrations)\n}\n");

	let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("migrations.rs");
	fs::write(out, code).expect("failed to write migrations.rs");
}
