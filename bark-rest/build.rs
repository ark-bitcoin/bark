
use std::{env, fs};
use std::path::{Path, PathBuf};
use std::process::Command;


fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rerun-if-env-changed=GIT_HASH");

	println!("cargo:rustc-env=CARGO_PKG_VERSION={}", env!("CARGO_PKG_VERSION"));
	if env::var("GIT_HASH").is_err() {
		// Get the Git commit hash
		let output = Command::new("git").args(["rev-parse", "HEAD"]).output()
			.expect("Failed to execute 'git rev-parse HEAD' command");

		let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
		println!("cargo:rustc-env=GIT_HASH={}", git_hash);
	}

	stage_bark_web_dist();
}

/// Stage the bark-web distribution to embed for the `web-ui` feature.
///
/// rust-embed's folder attribute must point at a directory that exists at
/// compile time, so the staging directory is always created. It is only
/// populated when the BARK_WEB_DIST env var points at a built bark-web
/// distribution (a directory with index.html at its root); when the var is
/// unset the directory stays empty and barkd serves no web UI.
fn stage_bark_web_dist() {
	println!("cargo:rerun-if-env-changed=BARK_WEB_DIST");
	println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WEB_UI");

	let staging = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bark-web-dist");
	if staging.exists() {
		fs::remove_dir_all(&staging).expect("failed to clear bark-web staging dir");
	}
	fs::create_dir_all(&staging).expect("failed to create bark-web staging dir");

	if let Ok(dist) = env::var("BARK_WEB_DIST") {
		println!("cargo:rerun-if-changed={}", dist);
		let dist = Path::new(&dist);
		assert!(
			dist.join("index.html").is_file(),
			"BARK_WEB_DIST ({}) doesn't look like a bark-web distribution: no index.html",
			dist.display(),
		);
		copy_dir(dist, &staging).expect("failed to copy BARK_WEB_DIST");
	}
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
	for entry in fs::read_dir(src)? {
		let entry = entry?;
		let dest = dst.join(entry.file_name());
		if entry.file_type()?.is_dir() {
			fs::create_dir_all(&dest)?;
			copy_dir(&entry.path(), &dest)?;
		} else {
			fs::copy(entry.path(), &dest)?;
		}
	}
	Ok(())
}
