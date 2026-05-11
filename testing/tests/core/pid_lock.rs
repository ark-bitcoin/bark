#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use nix::sys::signal::Signal;

use ark_testing::TestContext;
use bark::lock_manager::pid_fcntl::FcntlPidLockManager;
use bark::lock_manager::pid_flock::{FlockPidLockManager, LOCK_FILE};

use super::lock_helpers::{kill_and_wait, lock_holder_bin, spawn_holder};

/// What the parent test needs to know about a pid-lock backend: the
/// `LOCK_TEST_KIND` to pass to the child, a human-readable name for
/// failure messages, and a closure that mirrors the child's
/// construction so we can assert "second acquisition fails".
struct PidBackend {
	name: &'static str,
	kind: &'static str,
	/// Returns `true` if a fresh manager could be constructed (i.e. the
	/// lock was free). `false` means "another holder has it".
	try_acquire: fn(&Path) -> bool,
}

fn try_flock(dir: &Path) -> bool {
	FlockPidLockManager::new(dir).is_ok()
}

fn try_fcntl(dir: &Path) -> bool {
	FcntlPidLockManager::new(dir).is_ok()
}

fn pid_backends() -> [PidBackend; 2] {
	[
		PidBackend { name: "flock", kind: "pid-flock", try_acquire: try_flock },
		PidBackend { name: "fcntl", kind: "pid-fcntl", try_acquire: try_fcntl },
	]
}

#[tokio::test]
async fn pid_lock_is_released_after_sigkill() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/sigkill", b.name)).await;
		let child = spawn_holder(b.kind, &ctx.datadir, None);

		// The pid file must exist and contain the child's PID.
		let contents = fs::read_to_string(ctx.datadir.join(LOCK_FILE)).unwrap();
		assert_eq!(contents, child.id().to_string(), "{}", b.name);

		// A second acquisition must fail while the child holds the lock.
		assert!(!(b.try_acquire)(&ctx.datadir),
			"{}: second acquisition should fail while child holds lock", b.name);

		kill_and_wait(child, Signal::SIGKILL);

		assert!((b.try_acquire)(&ctx.datadir),
			"{}: should reacquire after SIGKILL", b.name);
	}
}

#[tokio::test]
async fn pid_lock_is_released_after_sigterm() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/sigterm", b.name)).await;
		let child = spawn_holder(b.kind, &ctx.datadir, None);

		assert!(!(b.try_acquire)(&ctx.datadir),
			"{}: second acquisition should fail while child holds lock", b.name);

		kill_and_wait(child, Signal::SIGTERM);

		assert!((b.try_acquire)(&ctx.datadir),
			"{}: should reacquire after SIGTERM", b.name);
	}
}

#[tokio::test]
async fn pid_lock_is_released_after_sigint() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/sigint", b.name)).await;
		let child = spawn_holder(b.kind, &ctx.datadir, None);

		assert!(!(b.try_acquire)(&ctx.datadir),
			"{}: second acquisition should fail while child holds lock", b.name);

		kill_and_wait(child, Signal::SIGINT);

		assert!((b.try_acquire)(&ctx.datadir),
			"{}: should reacquire after SIGINT", b.name);
	}
}

#[tokio::test]
async fn pid_file_contains_holder_pid() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/pid_content", b.name)).await;
		let child = spawn_holder(b.kind, &ctx.datadir, None);

		let contents = fs::read_to_string(ctx.datadir.join(LOCK_FILE)).unwrap();
		assert_eq!(contents, child.id().to_string(), "{}", b.name);

		kill_and_wait(child, Signal::SIGKILL);
	}
}

#[tokio::test]
async fn stale_pid_file_does_not_prevent_acquisition() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/stale", b.name)).await;

		// Write a fake PID — no process holds the OS lock.
		fs::write(ctx.datadir.join(LOCK_FILE), "999999").unwrap();

		assert!((b.try_acquire)(&ctx.datadir),
			"{}: stale pid file should not block acquisition", b.name);
	}
}

#[tokio::test]
async fn only_one_of_ten_concurrent_holders_succeeds() {
	for b in pid_backends() {
		let ctx = TestContext::new_minimal(&format!("pid/{}/concurrent", b.name)).await;
		let bin = lock_holder_bin();

		// Spawn 10 holders racing for the same lock.
		let mut children: Vec<Child> = (0..10)
			.map(|_| {
				Command::new(&bin)
					.env("LOCK_TEST_KIND", b.kind)
					.env("LOCK_TEST_DIR", &ctx.datadir)
					.stdout(Stdio::piped())
					.stderr(Stdio::piped())
					.spawn()
					.expect("failed to spawn lock-holder")
			})
			.collect();

		// Wait for all losers to exit. Each loser panics on acquire and exits
		// with a non-success status. The single winner stays alive.
		let mut failed = 0;
		let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
		while failed < 9 {
			assert!(
				tokio::time::Instant::now() < deadline,
				"{}: timed out: only {failed} children failed, {} still alive — \
				 more than one process may have acquired the lock",
				b.name, children.len(),
			);

			children.retain_mut(|child| {
				match child.try_wait().unwrap() {
					Some(status) => {
						assert!(!status.success(), "{}", b.name);
						failed += 1;
						false
					}
					None => true,
				}
			});

			tokio::time::sleep(std::time::Duration::from_millis(50)).await;
		}

		assert_eq!(children.len(), 1,
			"{}: exactly one holder should still be alive", b.name);
		assert_eq!(failed, 9, "{}: nine holders should fail", b.name);

		for child in children {
			kill_and_wait(child, Signal::SIGKILL);
		}
	}
}
