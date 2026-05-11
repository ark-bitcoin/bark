//! Shared utilities for the lock-related integration tests
//! (`pid_lock.rs`, `key_lock.rs`).
//!
//! Both suites spawn the `lock-holder` binary as a child process,
//! wait for it to print `LOCKED`, and tear it down with a signal.
//! Centralizing the env-var contract and the readline / kill dance
//! here keeps the test files focused on what they assert.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

/// Path to the `lock-holder` helper binary. Prefer the runtime path that
/// `cargo nextest` sets when running from an archive (CI's prebuilt jobs
/// extract the archive to a temp dir, so the compile-time path baked in
/// by `env!` no longer exists). Fall back to `CARGO_BIN_EXE_lock-holder`
/// for local `cargo`/`nextest` runs that build in-tree.
pub fn lock_holder_bin() -> PathBuf {
	std::env::var_os("NEXTEST_BIN_EXE_lock-holder")
		.map(Into::into)
		.unwrap_or_else(|| env!("CARGO_BIN_EXE_lock-holder").into())
}

/// Spawn `lock-holder` with the given backend kind / dir / optional key
/// and block until the child has reported `LOCKED` on stdout.
///
/// Panics on spawn failure or if the child exits before printing the
/// sentinel — both cases mean the test setup is broken, not the
/// system-under-test.
pub fn spawn_holder(kind: &str, dir: &Path, key: Option<&str>) -> Child {
	let mut cmd = Command::new(lock_holder_bin());
	cmd.env("LOCK_TEST_KIND", kind)
		.env("LOCK_TEST_DIR", dir)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	if let Some(k) = key {
		cmd.env("LOCK_TEST_KEY", k);
	}

	let mut child = cmd.spawn().expect("failed to spawn lock-holder");

	let stdout = child.stdout.as_mut().unwrap();
	let mut line = String::new();
	BufReader::new(stdout).read_line(&mut line).unwrap();
	assert_eq!(line.trim(), "LOCKED", "unexpected output: {line}");

	child
}

/// Signal the child and reap it. Both halves are necessary: without
/// `wait()` the OS may not yet have released file locks held by the
/// child by the time we assert reacquisition.
pub fn kill_and_wait(mut child: Child, sig: Signal) {
	signal::kill(Pid::from_raw(child.id() as i32), sig).unwrap();
	let _ = child.wait();
}
