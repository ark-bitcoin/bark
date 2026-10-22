//! The barkd single-instance guarantee: `barkd.lock`, exclusively locked
//! for the process lifetime. The wallet's `LOCK` can't serve here, since
//! it is only taken once a wallet is open.

use std::fs::{self, File, TryLockError};
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context};

use bark::lock_manager::PidLockError;
use bark::lock_manager::pid_flock::FlockPidLockManager;

use crate::wallet::AUTH_TOKEN_FILE;

/// File in the datadir exclusively locked for the lifetime of a barkd process.
pub const BARKD_LOCK_FILE: &str = "barkd.lock";

/// File in the datadir carrying the base URL the barkd holding the lock
/// listens on. Only meaningful while the lock is held.
pub const BARKD_URL_FILE: &str = "barkd.url";

/// Record the base URL this barkd listens on, so that clients on the same
/// datadir connect to it instead of the default listen address.
pub fn store_barkd_url(datadir: &Path, url: &str) -> anyhow::Result<()> {
	let path = datadir.join(BARKD_URL_FILE);
	fs::write(&path, url).with_context(|| format!("failed to write {}", path.display()))
}

/// The base URL recorded by the barkd on this datadir, if any.
pub fn barkd_url(datadir: &Path) -> anyhow::Result<Option<String>> {
	let path = datadir.join(BARKD_URL_FILE);
	match fs::read_to_string(&path) {
		Ok(url) => {
			let url = url.trim();
			Ok(if url.is_empty() { None } else { Some(url.to_string()) })
		},
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
	}
}

/// Remove everything in the datadir except the running barkd's own files,
/// so the held lock, auth token and listen URL survive a wallet wipe.
pub fn wipe_datadir_except_barkd_files(datadir: &Path) -> anyhow::Result<()> {
	let barkd_files = [BARKD_LOCK_FILE, AUTH_TOKEN_FILE, BARKD_URL_FILE];
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

/// The pid of the barkd holding the datadir lock, or `None` when no barkd
/// is running there. The flock, not the file's existence, is the liveness
/// signal: the OS releases it the instant the holder dies.
pub fn barkd_pid(datadir: &Path) -> anyhow::Result<Option<u32>> {
	let path = datadir.join(BARKD_LOCK_FILE);
	let mut file = match File::open(&path) {
		Ok(f) => f,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(e) => return Err(e).with_context(|| {
			format!("failed to open lock file {}", path.display())
		}),
	};

	match file.try_lock() {
		// We got the lock, so no barkd holds it; ours releases with `file`.
		Ok(()) => Ok(None),
		Err(TryLockError::WouldBlock) => {
			let mut holder = String::new();
			file.read_to_string(&mut holder).context("failed to read barkd lock")?;
			let pid = holder.trim().parse::<u32>()
				.context("barkd is running but its lock file carries no pid")?;
			Ok(Some(pid))
		},
		Err(TryLockError::Error(e)) => {
			Err(anyhow::Error::from(e)).with_context(|| {
				format!("failed to probe barkd lock at {}", path.display())
			})
		},
	}
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
		store_barkd_url(&dir, "http://127.0.0.1:3001").unwrap();
		fs::write(dir.join("db.sqlite"), "x").unwrap();
		fs::create_dir(dir.join("sub")).unwrap();
		fs::write(dir.join("sub").join("f"), "y").unwrap();

		wipe_datadir_except_barkd_files(&dir).unwrap();

		assert!(dir.join(BARKD_LOCK_FILE).exists());
		assert!(dir.join(AUTH_TOKEN_FILE).exists());
		assert!(dir.join(BARKD_URL_FILE).exists());
		assert!(!dir.join("db.sqlite").exists());
		assert!(!dir.join("sub").exists());

		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn barkd_url_roundtrip() {
		let dir = tmp_dir();
		assert_eq!(barkd_url(&dir).unwrap(), None, "no url file yet");

		store_barkd_url(&dir, "http://127.0.0.1:3001").unwrap();
		assert_eq!(barkd_url(&dir).unwrap().as_deref(), Some("http://127.0.0.1:3001"));

		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn barkd_pid_reflects_lock_state() {
		let dir = tmp_dir();
		assert_eq!(barkd_pid(&dir).unwrap(), None, "no lock file yet");

		let held = acquire_barkd_lock(&dir).unwrap();
		assert_eq!(barkd_pid(&dir).unwrap(), Some(std::process::id()));

		// The file outlives the holder; only the flock signals liveness.
		drop(held);
		assert_eq!(barkd_pid(&dir).unwrap(), None);

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
