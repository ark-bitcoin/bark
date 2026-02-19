use std::io::{Read, Write};
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

/// File name of the PID lock file.
pub const LOCK_FILE: &str = "LOCK";

/// A guard that holds an exclusive advisory lock on `LOCK`.
///
/// Uses OS-level file locking (`flock` on Unix, `LockFileEx` on Windows)
/// so the lock is automatically released when the process exits, even
/// on SIGKILL or a crash.
pub struct PidLock {
	// Keep the file handle open to hold the advisory lock.
	_file: File,
	path: PathBuf,
}

impl PidLock {
	/// Acquire a PID lock in the given directory.
	///
	/// Opens (or creates) `LOCK` and takes an exclusive advisory lock.
	/// If another process already holds the lock, acquisition fails.
	/// Creates the directory if it does not yet exist.
	pub fn acquire(datadir: &Path) -> anyhow::Result<Self> {
		fs::create_dir_all(datadir)
			.context("failed to create datadir")?;

		let path = datadir.join(LOCK_FILE);

		let mut file = File::options()
			.read(true)
			.write(true)
			.create(true)
			.open(&path)
			.with_context(|| format!("failed to open pid lock at {}", path.display()))?;

		match file.try_lock() {
			Ok(()) => {}
			Err(TryLockError::WouldBlock) => {
				let mut buffer = String::new();
				let _ = file.read_to_string(&mut buffer);
				bail!(
					"Another process is already using this datadir ({})\n\
					 PID in lock file: {}\n",
					path.display(),
					buffer.trim(),
				);
			}
			Err(TryLockError::Error(e)) => {
				bail!("failed to acquire pid lock at {}: {}", path.display(), e);
			}
		}

		// Write our PID (truncate any stale content first).
		file.set_len(0)
			.context("failed to truncate pid lock")?;
		write!(file, "{}", std::process::id())
			.context("failed to write to pid lock")?;
		file.flush()
			.context("failed to flush pid lock")?;

		Ok(PidLock { _file: file, path })
	}
}

impl std::fmt::Debug for PidLock {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("PidLock").field("path", &self.path).finish()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn tmp_datadir() -> PathBuf {
		let dir = std::env::temp_dir()
			.join(format!("bark-pid-test-{}", std::process::id()))
			.join(format!("{}", std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
		// Ensure clean state.
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[test]
	fn acquire_creates_pid_file_with_current_pid() {
		let dir = tmp_datadir();
		let lock = PidLock::acquire(&dir).unwrap();

		let contents = fs::read_to_string(dir.join(LOCK_FILE)).unwrap();
		assert_eq!(contents, std::process::id().to_string());

		drop(lock);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn second_acquire_is_refused() {
		let dir = tmp_datadir();
		let _lock = PidLock::acquire(&dir).unwrap();

		let err = PidLock::acquire(&dir).unwrap_err();
		assert!(
			err.to_string().contains("Another process is already using this datadir"),
			"unexpected error: {}", err,
		);

		drop(_lock);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn can_reacquire_after_drop() {
		let dir = tmp_datadir();

		let lock = PidLock::acquire(&dir).unwrap();
		drop(lock);

		// Should succeed now that the previous lock was dropped.
		let lock2 = PidLock::acquire(&dir).unwrap();
		drop(lock2);

		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn creates_datadir_if_missing() {
		let dir = tmp_datadir();
		assert!(!dir.exists());

		let lock = PidLock::acquire(&dir).unwrap();
		assert!(dir.exists());
		assert!(dir.join(LOCK_FILE).exists());

		drop(lock);
		let _ = fs::remove_dir_all(&dir);
	}
}
