#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

use ark_testing::TestContext;
use bark::pid_lock::{PidLock, LOCK_FILE};

fn spawn_lock_holder(datadir: &Path) -> Child {
	let bin = env!("CARGO_BIN_EXE_pid-lock-holder");

	let mut child = Command::new(bin)
		.env("PID_TEST_DATADIR", datadir)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("failed to spawn pid-lock-holder");

	// Wait until the child has acquired the lock.
	let stdout = child.stdout.as_mut().unwrap();
	let mut line = String::new();
	BufReader::new(stdout).read_line(&mut line).unwrap();
	assert_eq!(line.trim(), "LOCKED", "unexpected output: {line}");

	child
}

fn kill_and_wait(mut child: Child, signal: Signal) {
	signal::kill(Pid::from_raw(child.id() as i32), signal).unwrap();
	let _ = child.wait();
}

#[tokio::test]
async fn pid_lock_is_released_after_sigkill() {
	let ctx = TestContext::new_minimal("pid/sigkill").await;

	let child = spawn_lock_holder(&ctx.datadir);

	// The pid file must exist and contain the child's PID.
	let contents = fs::read_to_string(ctx.datadir.join(LOCK_FILE)).unwrap();
	assert_eq!(contents, child.id().to_string());

	// A second acquisition must fail while the child holds the lock.
	assert!(PidLock::acquire(&ctx.datadir).is_err());

	kill_and_wait(child, Signal::SIGKILL);

	// After SIGKILL the OS releases the flock — reacquisition must succeed.
	let _lock = PidLock::acquire(&ctx.datadir).expect("should reacquire after SIGKILL");
}

#[tokio::test]
async fn pid_lock_is_released_after_sigterm() {
	let ctx = TestContext::new_minimal("pid/sigterm").await;

	let child = spawn_lock_holder(&ctx.datadir);
	assert!(PidLock::acquire(&ctx.datadir).is_err());

	kill_and_wait(child, Signal::SIGTERM);

	let _lock = PidLock::acquire(&ctx.datadir).expect("should reacquire after SIGTERM");
}

#[tokio::test]
async fn pid_lock_is_released_after_sigint() {
	let ctx = TestContext::new_minimal("pid/sigint").await;

	let child = spawn_lock_holder(&ctx.datadir);
	assert!(PidLock::acquire(&ctx.datadir).is_err());

	kill_and_wait(child, Signal::SIGINT);

	let _lock = PidLock::acquire(&ctx.datadir).expect("should reacquire after SIGINT");
}

#[tokio::test]
async fn pid_file_contains_holder_pid() {
	let ctx = TestContext::new_minimal("pid/pid_content").await;

	let child = spawn_lock_holder(&ctx.datadir);

	let contents = fs::read_to_string(ctx.datadir.join(LOCK_FILE)).unwrap();
	assert_eq!(contents, child.id().to_string());

	kill_and_wait(child, Signal::SIGKILL);
}

#[tokio::test]
async fn stale_pid_file_does_not_prevent_acquisition() {
	let ctx = TestContext::new_minimal("pid/stale").await;

	// Write a fake PID — no process holds the flock.
	fs::write(ctx.datadir.join(LOCK_FILE), "999999").unwrap();

	// Acquisition must succeed because no flock is held.
	let _lock = PidLock::acquire(&ctx.datadir).expect("stale pid file should not block");
}

#[tokio::test]
async fn only_one_of_ten_concurrent_holders_succeeds() {
	let ctx = TestContext::new_minimal("pid/concurrent").await;
	let bin = env!("CARGO_BIN_EXE_pid-lock-holder");

	// Spawn 10 holders racing for the same lock.
	let mut children: Vec<Child> = (0..10)
		.map(|_| {
			Command::new(bin)
				.env("PID_TEST_DATADIR", &ctx.datadir)
				.stdout(Stdio::piped())
				.stderr(Stdio::piped())
				.spawn()
				.expect("failed to spawn pid-lock-holder")
		})
		.collect();

	// Wait for all losers to exit. Each loser panics on acquire and exits
	// with a non-success status. The single winner stays alive.
	let mut failed = 0;
	let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
	while failed < 9 {
		assert!(
			tokio::time::Instant::now() < deadline,
			"timed out: only {failed} children failed, {} still alive — \
			 more than one process may have acquired the lock",
			children.len(),
		);

		children.retain_mut(|child| {
			match child.try_wait().unwrap() {
				Some(status) => {
					assert!(!status.success());
					failed += 1;
					false
				}
				None => true,
			}
		});

		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}

	assert_eq!(children.len(), 1, "exactly one holder should still be alive");
	assert_eq!(failed, 9, "nine holders should fail");

	for child in children {
		kill_and_wait(child, Signal::SIGKILL);
	}
}
