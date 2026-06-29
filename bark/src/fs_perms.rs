//! Filesystem permission helpers for protecting wallet secrets on disk.
//!
//! The wallet datadir holds the seed, wallet state, config and server access
//! token. These helpers lock those paths to the owning user and write secrets
//! atomically so they're never momentarily readable by other users. They are
//! unix-only; on other targets they degrade to plain writes / no-ops (Windows
//! would need ACLs instead).

use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::Context;
use log::warn;

/// `chmod` `path` to `mode` so other (non-root) users can't reach it.
///
/// Use `0o700` for the datadir (the `x` bit lets the owner traverse in; a dir
/// without it is unusable even by the owner) and `0o600` for secret files.
#[cfg(unix)]
pub fn harden(path: &Path, mode: u32) -> anyhow::Result<()> {
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
		.with_context(|| format!("failed to harden permissions on {}", path.display()))
}
#[cfg(not(unix))]
pub fn harden(_path: &Path, _mode: u32) -> anyhow::Result<()> {
	Ok(())
}

/// Whether `mode` grants any group or other access.
#[cfg(unix)]
fn is_loose(mode: u32) -> bool {
	mode & 0o077 != 0
}

/// Warn (without modifying) if `path` is accessible by group or other users.
///
/// New wallets are hardened at creation; for paths created before hardening
/// existed we only nudge, since silently re-chmod'ing on every open would
/// override a deliberate setup (e.g. a shared service account). `recommended`
/// is the mode shown in the message (0o700 dirs, 0o600 files).
#[cfg(unix)]
pub fn warn_if_loose(path: &Path, recommended: u32) {
	if let Ok(meta) = std::fs::metadata(path) {
		let mode = meta.permissions().mode() & 0o777;
		if is_loose(mode) {
			warn!(
				"{} is accessible by other users (mode {:03o}); run `chmod {:o} {}` to secure it",
				path.display(), mode, recommended, path.display(),
			);
		}
	}
}
#[cfg(not(unix))]
pub fn warn_if_loose(_path: &Path, _recommended: u32) {}

/// Atomically create a brand-new owner-only (`0o600`) file and write `contents`.
///
/// `create_new` refuses to follow or overwrite an existing path, so this never
/// clobbers an existing secret (e.g. a seed), and the restrictive mode is
/// applied at creation so the bytes are never momentarily readable by others.
#[cfg(unix)]
pub fn create_new_owner_only(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
	let mut f = std::fs::OpenOptions::new()
		.write(true).create_new(true).mode(0o600)
		.open(path)
		.with_context(|| format!("failed to create {}", path.display()))?;
	write_or_unlink(&mut f, path, contents)
}
#[cfg(not(unix))]
pub fn create_new_owner_only(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
	let mut f = std::fs::OpenOptions::new()
		.write(true).create_new(true)
		.open(path)
		.with_context(|| format!("failed to create {}", path.display()))?;
	write_or_unlink(&mut f, path, contents)
}

/// Write `contents` to a freshly-created `f`, removing `path` if the write
/// fails — a leftover empty/partial file would make the next `create_new`
/// fail (or yield a corrupt read), poisoning retries.
fn write_or_unlink(f: &mut std::fs::File, path: &Path, contents: &[u8]) -> anyhow::Result<()> {
	f.write_all(contents).map_err(|e| {
		let _ = std::fs::remove_file(path);
		e
	}).with_context(|| format!("failed to write {}", path.display()))
}

/// Atomically (re)write `path` with owner-only (`0o600`) permissions.
///
/// The bytes go to a temp sibling created `0o600`, which is then renamed over
/// `path`. So readers never see a partial file, the contents are never
/// momentarily group/other-readable, and an existing file is replaced rather
/// than truncated in place. Callers must hold the datadir lock (single writer).
#[cfg(unix)]
pub fn write_atomic_owner_only(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
	let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
	let name = path.file_name()
		.with_context(|| format!("path has no file name: {}", path.display()))?
		.to_string_lossy();

	// Write to a temp sibling, created exclusively, then rename over `path`.
	// create_new (O_EXCL) refuses to follow a pre-planted symlink or reuse an
	// existing file. The nanosecond timestamp distinguishes this write from other
	// calls and from any stale temp left by a crash (which carries an older one);
	// the attempt index breaks a tie should two writes land in the same tick. We
	// only ever rename the temp this call created.
	let nanos = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_nanos())
		.unwrap_or(0);
	const MAX_ATTEMPTS: u32 = 16;
	for n in 0..MAX_ATTEMPTS {
		let file = format!(".{}.temp.{}.{}.tmp", name, nanos, n);
		let tmp = match parent {
			Some(dir) => dir.join(&file),
			None => std::path::PathBuf::from(&file),
		};
		let mut f = match std::fs::OpenOptions::new()
			.write(true).create_new(true).mode(0o600).open(&tmp)
		{
			Ok(f) => f,
			Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
			Err(e) => return Err(e)
				.with_context(|| format!("failed to create {}", tmp.display())),
		};
		let res = (|| -> anyhow::Result<()> {
			f.write_all(contents)
				.with_context(|| format!("failed to write {}", tmp.display()))?;
			// Flush to disk before the rename: a failed fsync must not let
			// unflushed data replace the existing file.
			f.sync_all()
				.with_context(|| format!("failed to flush {}", tmp.display()))?;
			std::fs::rename(&tmp, path).with_context(|| format!(
				"failed to replace {} with {}", path.display(), tmp.display(),
			))
		})();
		if res.is_err() {
			let _ = std::fs::remove_file(&tmp);
		}
		return res;
	}
	anyhow::bail!("failed to create a unique temp file for {}", path.display())
}
#[cfg(not(unix))]
pub fn write_atomic_owner_only(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
	std::fs::write(path, contents)
		.with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;

	fn mode_of(path: &Path) -> u32 {
		std::fs::metadata(path).unwrap().permissions().mode() & 0o777
	}

	#[test]
	fn harden_sets_mode_on_file_and_dir() {
		let dir = tempfile::tempdir().unwrap();
		let f = dir.path().join("f");
		std::fs::write(&f, b"x").unwrap();
		std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();

		harden(&f, 0o600).unwrap();
		assert_eq!(mode_of(&f), 0o600);

		harden(dir.path(), 0o700).unwrap();
		assert_eq!(mode_of(dir.path()), 0o700);
	}

	#[test]
	fn is_loose_detects_group_and_other_bits() {
		assert!(!is_loose(0o600));
		assert!(!is_loose(0o700));
		assert!(is_loose(0o640));
		assert!(is_loose(0o604));
		assert!(is_loose(0o644));
		assert!(is_loose(0o755));
	}

	#[test]
	fn create_new_is_owner_only_and_refuses_clobber() {
		let dir = tempfile::tempdir().unwrap();
		let f = dir.path().join("seed");

		create_new_owner_only(&f, b"hello").unwrap();
		assert_eq!(mode_of(&f), 0o600);
		assert_eq!(std::fs::read(&f).unwrap(), b"hello");

		// must not overwrite an existing secret
		assert!(create_new_owner_only(&f, b"again").is_err());
		assert_eq!(std::fs::read(&f).unwrap(), b"hello");
	}

	#[test]
	fn write_atomic_is_owner_only_replaces_and_leaves_no_temp() {
		let dir = tempfile::tempdir().unwrap();
		let f = dir.path().join("token");

		write_atomic_owner_only(&f, b"one").unwrap();
		assert_eq!(mode_of(&f), 0o600);
		assert_eq!(std::fs::read(&f).unwrap(), b"one");

		write_atomic_owner_only(&f, b"two").unwrap();
		assert_eq!(mode_of(&f), 0o600);
		assert_eq!(std::fs::read(&f).unwrap(), b"two");

		// the temp sibling must be cleaned up by the rename
		assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
	}

	#[test]
	fn write_atomic_keeps_owner_only_even_when_target_preexists_loose() {
		let dir = tempfile::tempdir().unwrap();
		let f = dir.path().join("config");
		std::fs::write(&f, b"old").unwrap();
		std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();

		// rename replaces the inode, so the result is owner-only regardless
		write_atomic_owner_only(&f, b"new").unwrap();
		assert_eq!(mode_of(&f), 0o600);
		assert_eq!(std::fs::read(&f).unwrap(), b"new");
	}

	#[test]
	fn write_atomic_replaces_a_symlinked_target_without_writing_through_it() {
		let dir = tempfile::tempdir().unwrap();
		let victim = dir.path().join("victim");
		std::fs::write(&victim, b"secret").unwrap();

		// the target is itself a symlink to the victim; the rename must replace
		// the symlink with our own regular file rather than write through it
		let target = dir.path().join("config");
		std::os::unix::fs::symlink(&victim, &target).unwrap();

		write_atomic_owner_only(&target, b"new").unwrap();

		// victim untouched; target is now a fresh owner-only regular file
		assert_eq!(std::fs::read(&victim).unwrap(), b"secret");
		assert!(std::fs::symlink_metadata(&target).unwrap().file_type().is_file());
		assert_eq!(std::fs::read(&target).unwrap(), b"new");
		assert_eq!(mode_of(&target), 0o600);
	}
}
