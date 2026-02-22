use std::path::Path;

use bark::pid_lock::PidLock;

fn main() {
	let datadir = std::env::var("PID_TEST_DATADIR")
		.expect("PID_TEST_DATADIR must be set");

	let _lock = PidLock::acquire(Path::new(&datadir))
		.expect("failed to acquire pid lock");

	println!("LOCKED");

	// Sleep until killed.
	std::thread::sleep(std::time::Duration::from_secs(3600));
}
