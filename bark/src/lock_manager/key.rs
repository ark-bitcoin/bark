/// Reject keys that aren't safe to use as a filename component.
///
/// The file-based backends turn `<dir>/<key>.lock` into a real path on
/// disk, so the key effectively *is* a filename. A hostile or careless
/// key could escape the lock directory (`../foo`, absolute paths,
/// path separators), collide with unrelated files (NUL, control
/// characters), or produce filesystem entries that are hostile to
/// debug (shell metacharacters, whitespace). Rather than enumerate
/// everything that can go wrong, we allow only a tightly-bounded
/// character set: it's easier to reason about and easier to read in
/// logs.
///
/// Rules:
/// - Only ASCII alphanumeric, `-`, `_`, `.`.
/// - Must start with an alphanumeric character (letter or digit).
/// - Must end with a letter or digit.
/// - At most 200 bytes (well under the 255-byte filename limit on
///   typical filesystems, with room left for the `.lock` suffix).
///
/// `bark.lightning.send.42` and `01abcdef.round.7` pass;
/// `..`, `_abc`, `abc-`, `a/b` do not.
pub(crate) fn validate_key(key: &str) -> anyhow::Result<()> {
	if key.is_empty() {
		bail!("lock key must not be empty");
	}
	if key.len() > 200 {
		bail!("lock key must be at most 200 bytes: got {}", key.len());
	}
	let first = key.chars().next().unwrap();
	if !first.is_ascii_alphanumeric() {
		bail!("lock key must start with a letter or digit: {:?}", key);
	}
	let last = key.chars().last().unwrap();
	if !last.is_ascii_alphanumeric() {
		bail!("lock key must end with a letter or digit: {:?}", key);
	}
	for c in key.chars() {
		let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
		if !ok {
			bail!(
				"lock key must contain only ASCII alphanumeric, '-', '_', '.': {:?}",
				key,
			);
		}
	}
	Ok(())
}
