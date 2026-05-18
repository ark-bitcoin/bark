//! Child binary used by `tests/core/pid_lock.rs` to hold a pid lock from
//! another OS process.
//!
//! The parent test selects a backend via `LOCK_TEST_KIND` (`pid-flock` or
//! `pid-fcntl`) and a target directory via `LOCK_TEST_DIR`. On success
//! the binary prints `LOCKED\n` (flushed) and then sleeps until killed.
//! Any failure exits non-zero *before* printing the sentinel, so the
//! parent's readline either sees `LOCKED` or sees EOF.

use std::io::Write;
use std::path::Path;

use bark::lock_manager::pid_fcntl::FcntlPidLockManager;
use bark::lock_manager::pid_flock::FlockPidLockManager;

fn main() {
	let kind = std::env::var("LOCK_TEST_KIND").expect("LOCK_TEST_KIND must be set");
	let dir = std::env::var("LOCK_TEST_DIR").expect("LOCK_TEST_DIR must be set");
	let dir = Path::new(&dir);

	let _hold: Box<dyn std::any::Any> = match kind.as_str() {
		"pid-flock" => Box::new(
			FlockPidLockManager::new(dir).expect("failed to acquire flock pid lock"),
		),
		"pid-fcntl" => Box::new(
			FcntlPidLockManager::new(dir).expect("failed to acquire fcntl pid lock"),
		),
		other => panic!("unknown LOCK_TEST_KIND: {}", other),
	};

	println!("LOCKED");
	std::io::stdout().flush().unwrap();

	std::thread::sleep(std::time::Duration::from_secs(3600));
	drop(_hold);
}
