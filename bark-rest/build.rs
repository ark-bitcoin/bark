
use std::env;
use std::process::Command;


fn main() {
	println!("cargo:rustc-env=CARGO_PKG_VERSION={}", env!("CARGO_PKG_VERSION"));
	if env::var("GIT_HASH").is_err() {
		// Get the Git commit hash
		let output = Command::new("git").args(["rev-parse", "HEAD"]).output()
			.expect("Failed to execute 'git rev-parse HEAD' command");

		let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
		println!("cargo:rustc-env=GIT_HASH={}", git_hash);
	}
}
