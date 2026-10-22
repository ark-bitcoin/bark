//! The barkd lifecycle from the client side.
//!
//! The `barkd.lock` flock is the liveness signal - the OS releases it the
//! instant barkd dies, even on SIGKILL.

use std::path::Path;

use anyhow::Context;

use bark_cli::connection;

/// Require a running barkd on the datadir, for a clear error before any
/// request is attempted.
pub fn require_up(datadir: &Path) -> anyhow::Result<u32> {
	connection::barkd_pid(datadir)?.with_context(|| format!(
		"no barkd is running for datadir {} - start one with barkd",
		datadir.display(),
	))
}

/// `bark-cli status` implementation.
pub fn print_status(datadir: &Path) -> anyhow::Result<()> {
	match connection::barkd_pid(datadir)? {
		Some(pid) => println!("barkd running (pid {})", pid),
		None => println!("no barkd is running for datadir {}", datadir.display()),
	}
	Ok(())
}
