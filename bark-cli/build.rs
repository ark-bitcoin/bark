
use std::env;
use std::process::Command;


fn main() {
	if env::var("GIT_HASH").is_err() {
		// Get the Git commit hash
		let output = Command::new("git").args(["rev-parse", "HEAD"]).output()
			.expect("Failed to execute 'git rev-parse HEAD' command");

		let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
		println!("cargo:rustc-env=GIT_HASH={}", git_hash);
	}

	// Determine version from git tag or dirty
	if env::var("BARK_VERSION").is_err() {
		// Try to get tags pointing to current commit
		let output = Command::new("git")
			.args(["tag", "--points-at", "HEAD"])
			.output()
			.expect("Failed to execute 'git tag --points-at HEAD' command");

		let tags = String::from_utf8_lossy(&output.stdout);

		// Look for a tag matching bark-X.Y.Z pattern
		let version = tags.lines()
			.find(|line| line.starts_with("bark-"))
			.and_then(|tag| tag.strip_prefix("bark-"))
			.map(|v| v.to_string())
			.unwrap_or_else(|| "DIRTY".into());

		println!("cargo:rustc-env=BARK_VERSION={}", version);
	}
}
