//! The barkd single-instance guarantee: `barkd.lock`, exclusively locked
//! for the process lifetime. The wallet's `LOCK` can't serve here, since
//! it is only taken once a wallet is open.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context};

use bark::lock_manager::PidLockError;
use bark::lock_manager::pid_flock::FlockPidLockManager;

use crate::wallet::AUTH_TOKEN_FILE;

/// File in the datadir exclusively locked for the lifetime of a barkd process.
pub const BARKD_LOCK_FILE: &str = "barkd.lock";

/// Remove everything in the datadir except the running barkd's own files,
/// so the held lock and auth token survive a wallet wipe.
pub fn wipe_datadir_except_barkd_files(datadir: &Path) -> anyhow::Result<()> {
	let barkd_files = [BARKD_LOCK_FILE, AUTH_TOKEN_FILE];
	for entry in fs::read_dir(datadir).context("failed to list datadir")? {
		let entry = entry?;
		if barkd_files.iter().any(|k| entry.file_name() == *k) {
			continue;
		}
		let path = entry.path();
		if entry.file_type()?.is_dir() {
			fs::remove_dir_all(&path)
		} else {
			fs::remove_file(&path)
		}.with_context(|| format!("failed to remove {}", path.display()))?;
	}
	Ok(())
}

/// Take the exclusive barkd lock on the datadir, or fail fast when another
/// barkd already runs there. The OS releases the lock when the returned value
/// is dropped or the process exits, even on SIGKILL or a crash.
pub fn acquire_barkd_lock(datadir: &Path) -> anyhow::Result<FlockPidLockManager> {
	match FlockPidLockManager::new_with_lock_file(datadir, BARKD_LOCK_FILE) {
		Ok(lock) => Ok(lock),
		Err(PidLockError::AlreadyHeld { datadir, pid }) => match pid {
			Some(pid) => bail!(
				"another barkd is already running on datadir {} (pid {})",
				datadir.display(), pid,
			),
			None => bail!(
				"another barkd is already running on datadir {}",
				datadir.display(),
			),
		},
		Err(e) => Err(e).context("failed to acquire barkd lock"),
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn tmp_dir() -> std::path::PathBuf {
		let dir = std::env::temp_dir()
			.join(format!("bark-connection-{}", std::process::id()))
			.join(format!("{}", std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn wipe_keeps_barkd_files() {
		let dir = tmp_dir();
		let _lock = acquire_barkd_lock(&dir).unwrap();
		fs::write(dir.join(AUTH_TOKEN_FILE), "tok").unwrap();
		fs::write(dir.join("db.sqlite"), "x").unwrap();
		fs::create_dir(dir.join("sub")).unwrap();
		fs::write(dir.join("sub").join("f"), "y").unwrap();

		wipe_datadir_except_barkd_files(&dir).unwrap();

		assert!(dir.join(BARKD_LOCK_FILE).exists());
		assert!(dir.join(AUTH_TOKEN_FILE).exists());
		assert!(!dir.join("db.sqlite").exists());
		assert!(!dir.join("sub").exists());

		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn barkd_lock_refuses_second_holder() {
		let dir = tmp_dir();
		let held = acquire_barkd_lock(&dir).unwrap();

		// flock is per open file description, so a second open in the same
		// process conflicts just like another process would.
		let err = acquire_barkd_lock(&dir).unwrap_err();
		assert!(
			err.to_string().contains("another barkd is already running"),
			"unexpected error: {}", err,
		);
		assert!(err.to_string().contains(&std::process::id().to_string()));

		drop(held);
		let _reacquired = acquire_barkd_lock(&dir).unwrap();

		let _ = fs::remove_dir_all(&dir);
	}
}
