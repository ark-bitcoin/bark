//! `fcntl(F_SETLK)`-based pid lock for single-process-per-datadir
//! deployment.
//!
//! Same shape as [`super::pid_flock::FlockPidLockManager`] — one
//! OS-level lock on `<datadir>/LOCK` held for the manager's lifetime,
//! all per-key locking delegated to an internal
//! [`MemoryLockManager`]. The only
//! difference is the OS primitive: this variant uses POSIX
//! `fcntl(F_SETLK)` instead of `flock(2)`.
//!
//! # Safety scope
//!
//! Prevents concurrent access by callers within the **current OS
//! process**. Construction refuses to start a second process holding
//! the same datadir.
//!
//! # Platform support
//!
//! Linux, macOS, iOS, Android. Not available on Windows or `wasm32`.
//!
//! Pick this over [`super::pid_flock::FlockPidLockManager`] when the
//! datadir may live on a POSIX-compliant networked filesystem (e.g.
//! NFSv4 with locking enabled). `fcntl` is the only file-locking
//! primitive POSIX requires NFS implementations to honor — `flock(2)`
//! on a networked mount is implementation-defined.
//!
//! # When to use
//!
//! - Single-process-per-datadir deployments where the datadir may
//!   sit on networked storage.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::Context;

use super::{LockGuard, LockManager, PidLockError};
use super::memory::MemoryLockManager;

/// File name used for the datadir-level PID lock.
pub const LOCK_FILE: &str = "LOCK";

fn open_lock_file(path: &Path) -> anyhow::Result<File> {
	File::options()
		.read(true)
		.write(true)
		.create(true)
		.truncate(false)
		.open(path)
		.with_context(|| format!("failed to open lock file {}", path.display()))
}

/// Attempt a non-blocking POSIX write lock on the whole file.
fn try_fcntl_lock(file: &File) -> anyhow::Result<bool> {
	let mut lk: libc::flock = unsafe { std::mem::zeroed() };
	lk.l_type = libc::F_WRLCK as libc::c_short;
	lk.l_whence = libc::SEEK_SET as libc::c_short;
	lk.l_start = 0;
	lk.l_len = 0;

	let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lk) };
	if ret == 0 {
		return Ok(true);
	}
	let err = std::io::Error::last_os_error();
	match err.raw_os_error() {
		Some(libc::EAGAIN) | Some(libc::EACCES) => Ok(false),
		_ => Err(err).context("fcntl F_SETLK failed"),
	}
}


pub struct FcntlPidLockManager {
	// Holds the OS lock for the lifetime of the manager. Dropped on
	// drop of the manager — at which point the OS releases the lock.
	_pid_file: File,
	// Removes our datadir from the in-process registry on drop so a
	// subsequent `new()` can re-acquire.
	_registration: Registration,
	datadir: PathBuf,
	in_process: MemoryLockManager,
}

impl FcntlPidLockManager {
	/// Take the pid lock on `datadir` via `fcntl(F_SETLK)` and construct
	/// a manager. Fails with [`PidLockError::AlreadyHeld`] if another
	/// process — or another instance in this process — already holds
	/// the lock, or [`PidLockError::SetupFailed`] for any other I/O
	/// failure.
	pub fn new(datadir: impl Into<PathBuf>) -> Result<Self, PidLockError> {
		let datadir = datadir.into();
		let setup = |source: anyhow::Error| PidLockError::SetupFailed {
			datadir: datadir.clone(),
			source,
		};

		fs::create_dir_all(&datadir)
			.with_context(|| format!("failed to create datadir {}", datadir.display()))
			.map_err(&setup)?;

		// POSIX fcntl locks are scoped to (process, inode), so a second
		// `fcntl(F_SETLK)` from the same process on the same file would
		// silently succeed. Track which datadirs this process already
		// holds the lock for so a second `new()` fails cleanly.
		let registration = Registration::try_register(&datadir)?;

		let path = datadir.join(LOCK_FILE);
		let mut file = open_lock_file(&path).map_err(&setup)?;

		if !try_fcntl_lock(&file).map_err(&setup)? {
			let mut holder = String::new();
			let _ = file.read_to_string(&mut holder);
			let pid = holder.trim().parse::<u32>().ok();
			return Err(PidLockError::AlreadyHeld { datadir, pid });
		}

		// Stamp the holder PID for diagnostics. Truncate first to drop
		// any stale content left by a previous holder.
		file.set_len(0).context("failed to truncate pid lock").map_err(&setup)?;
		write!(file, "{}", std::process::id())
			.context("failed to write pid lock").map_err(&setup)?;
		file.flush().context("failed to flush pid lock").map_err(&setup)?;

		Ok(Self {
			_pid_file: file,
			_registration: registration,
			datadir,
			in_process: MemoryLockManager::new(),
		})
	}

	pub fn datadir(&self) -> &Path {
		&self.datadir
	}
}

/// Process-local registry of datadirs currently held by an
/// `FcntlPidLockManager`. Removed on drop.
struct Registration {
	datadir: PathBuf,
}

impl Registration {
	fn try_register(datadir: &Path) -> Result<Self, PidLockError> {
		let mut held = held_datadirs().lock().expect("FcntlPidLockManager registry poisoned");
		if !held.insert(datadir.to_path_buf()) {
			return Err(PidLockError::AlreadyHeld {
				datadir: datadir.to_path_buf(),
				pid: Some(std::process::id()),
			});
		}
		Ok(Self { datadir: datadir.to_path_buf() })
	}
}

impl Drop for Registration {
	fn drop(&mut self) {
		if let Ok(mut held) = held_datadirs().lock() {
			held.remove(&self.datadir);
		}
	}
}

fn held_datadirs() -> &'static Mutex<HashSet<PathBuf>> {
	static HELD: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
	HELD.get_or_init(|| Mutex::new(HashSet::new()))
}

impl std::fmt::Debug for FcntlPidLockManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("FcntlPidLockManager").field("datadir", &self.datadir).finish()
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl LockManager for FcntlPidLockManager {
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>> {
		self.in_process.try_lock(key).await
	}

	async fn lock(
		&self,
		key: &str,
		timeout: std::time::Duration,
	) -> anyhow::Result<Box<dyn LockGuard>> {
		self.in_process.lock(key, timeout).await
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn tmp_dir() -> PathBuf {
		let dir = std::env::temp_dir()
			.join(format!("bark-pid-fcntl-lockmgr-{}", std::process::id()))
			.join(format!("{}", std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
		let _ = fs::remove_dir_all(&dir);
		dir
	}

	#[tokio::test]
	async fn acquire_writes_holder_pid() {
		let dir = tmp_dir();
		let mgr = FcntlPidLockManager::new(&dir).unwrap();
		let contents = fs::read_to_string(dir.join(LOCK_FILE)).unwrap();
		assert_eq!(contents, std::process::id().to_string());
		drop(mgr);
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn second_acquire_in_same_process_is_refused() {
		let dir = tmp_dir();
		let _held = FcntlPidLockManager::new(&dir).unwrap();
		let err = FcntlPidLockManager::new(&dir).unwrap_err();
		assert!(
			err.to_string().contains("another process is already using datadir"),
			"unexpected error: {}", err,
		);
		drop(_held);
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn reacquire_after_drop_succeeds() {
		let dir = tmp_dir();
		let first = FcntlPidLockManager::new(&dir).unwrap();
		drop(first);
		let _second = FcntlPidLockManager::new(&dir).unwrap();
		let _ = fs::remove_dir_all(&dir);
	}

	#[tokio::test]
	async fn per_key_locking_works_in_process() {
		let dir = tmp_dir();
		let mgr = FcntlPidLockManager::new(&dir).unwrap();

		let g = mgr.try_lock("foo").await;
		assert!(g.is_some());

		let busy = mgr.try_lock("foo").await;
		assert!(busy.is_none(), "same key should be blocked");

		let g2 = mgr.try_lock("bar").await;
		assert!(g2.is_some(), "different key should be free");

		let _ = fs::remove_dir_all(&dir);
	}
}
