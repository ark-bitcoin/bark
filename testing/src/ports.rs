//! Port reservation for test daemons.
//!
//! `portpicker` doesn't keep the port it returns reserved, and bitcoind binds
//! its p2p port only after loading the chainstate, seconds later. If anything
//! picks that port meanwhile, here or in a parallel test process, bitcoind dies
//! with "Unable to bind". So we lock every port we hand out until we exit.

use std::fs::{File, TryLockError};
use std::path::PathBuf;
use std::sync::Mutex;

use log::trace;

/// Shared by all test processes on this machine.
const LOCK_DIR: &str = "/tmp/ark-testing-ports";

const MAX_ATTEMPTS: usize = 100;

/// Never dropped: a port stays ours until the process exits.
static PORT_LOCKS: Mutex<Vec<File>> = Mutex::new(Vec::new());

/// Pick a free port and reserve it for the lifetime of this process.
pub fn pick_port() -> u16 {
	for _ in 0..MAX_ATTEMPTS {
		let port = portpicker::pick_unused_port().expect("No ports free");
		if let Some(lock) = try_reserve(port) {
			PORT_LOCKS.lock().unwrap().push(lock);
			return port;
		}
		trace!("Port {} is reserved by another test, picking another one", port);
	}

	panic!("Failed to reserve a free port in {} attempts", MAX_ATTEMPTS);
}

fn try_reserve(port: u16) -> Option<File> {
	let dir = PathBuf::from(LOCK_DIR);
	std::fs::create_dir_all(&dir).expect("failed to create port lock dir");

	let path = dir.join(format!("{}.lock", port));
	let file = File::options()
		.create(true)
		.write(true)
		.truncate(false)
		.open(&path)
		.expect("failed to open port lock file");

	// Our own picks lock a separate file description, so they conflict too.
	match file.try_lock() {
		Ok(()) => Some(file),
		Err(TryLockError::WouldBlock) => None,
		// Don't burn all our attempts on a filesystem that can't lock.
		Err(TryLockError::Error(e)) => panic!("failed to lock {}: {:#}", path.display(), e),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn a_picked_port_is_locked_out() {
		let port = pick_port();
		assert!(try_reserve(port).is_none(), "a held port should read as contended");
	}
}
