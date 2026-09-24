//! Shared scaffolding: the gate the proxies read, and the assertions every
//! action test makes.

use std::sync::{atomic, Arc};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use log::{info, warn};
use semver::Version;

use bark_json::primitives::VtxoStateInfo;

use ark_testing::Bark;
use ark_testing::util::poll_interval;

/// How long the old release runs before it is killed.
///
/// The kill is what leaves the checkpoint behind: bark retries through parks on
/// its own, so a failing RPC alone would eventually succeed. Only startup and
/// sync need to fit; raise it with `BARK_UPGRADE_CUT_OFF_MILLIS`.
pub(crate) fn cut_off_timeout() -> Duration {
	match std::env::var("BARK_UPGRADE_CUT_OFF_MILLIS") {
		Ok(millis) => Duration::from_millis(
			millis.parse().expect("BARK_UPGRADE_CUT_OFF_MILLIS is not a number of millis"),
		),
		Err(_) => Duration::from_secs(5),
	}
}

/// Closed while the old release runs so its action cannot finish, opened
/// before the new one takes over so the resumed action can.
#[derive(Clone)]
pub(crate) struct Gate(Arc<AtomicBool>);

impl Gate {
	pub(crate) fn closed() -> Self {
		Self(Arc::new(AtomicBool::new(true)))
	}

	pub(crate) fn open(&self) {
		self.0.store(false, atomic::Ordering::Relaxed);
	}

	pub(crate) fn is_closed(&self) -> bool {
		self.0.load(atomic::Ordering::Relaxed)
	}
}

/// Strip the `-dev` a non-release build appends, leaving the semver base.
pub(crate) fn version_base(version: &str) -> Version {
	let base = version.strip_suffix("-dev").unwrap_or(version);
	Version::parse(base).unwrap_or_else(|e| panic!("bark reported {}: {}", version, e))
}

/// The version out of a `bark --version` line, e.g. `0.7.1-dev`.
fn version_of(build: &str) -> &str {
	build.strip_prefix("bark ")
		.and_then(|rest| rest.split_whitespace().next())
		.unwrap_or_else(|| panic!("unexpected bark --version output: {}", build))
}

/// Assert the two sides are different builds, so a stale `target/debug/bark`
/// cannot turn every test here into a same-build run that checks nothing.
///
/// Identity is the whole `bark --version` line, including the commit hash,
/// because the version alone cannot tell two builds apart: everything built
/// after a release tag reports the same `X.Y.Z-dev`. Comparing builds rather
/// than versions also lets the suite run between two dev builds, which is how
/// you bisect the commit that broke a migration.
///
/// Going backwards only warns. A downgrade is usually a mistake, but running
/// one deliberately is a legitimate way to check a migration is survivable.
pub(crate) async fn assert_upgrade_spans_builds(old: &Bark, new: &Bark) {
	let from = old.instance_build().await;
	let to = new.instance_build().await;

	assert_ne!(
		from, to,
		"upgrade test runs the same build on both sides, so it exercises no \
		 migration. BARK_EXEC is probably stale; rebuild it.",
	);

	let (from_base, to_base) = (version_base(version_of(&from)), version_base(version_of(&to)));
	if to_base < from_base {
		warn!("upgrade test runs backwards: {} -> {}", from, to);
	}

	info!("upgrade test spans {} -> {}", from, to);
}

/// Drive pending actions with the upgraded binary until `done` holds. One
/// `maintain` is not always enough: a resumed action can park again.
pub(crate) async fn maintain_until<F, Fut>(bark: &Bark, what: &str, done: F)
where
	F: Fn() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	for attempt in 0..30 {
		bark.maintain().await;
		if done().await {
			return;
		}
		info!("{}: not settled after {} maintain runs", what, attempt + 1);
		tokio::time::sleep(poll_interval()).await;
	}
	panic!("{} did not settle after the upgrade", what);
}

/// Assert the old release parked exactly where this test means to cover. End
/// state alone cannot tell that from "parked elsewhere and recovered anyway".
pub(crate) async fn assert_parked_at(bark: &Bark, expected: &str) {
	let steps = bark.checkpoint_steps().await;
	assert_eq!(
		steps, vec![expected.to_string()],
		"expected the old release to park exactly at {}", expected,
	);
}

/// The action is finished and left nothing behind.
///
/// Two separate failures, because either can happen without the other. A
/// surviving checkpoint means the executor never reached `Advance::Done`, which
/// the balance cannot show. A surviving lock means it did, but `stop_wallet_action`
/// failed to release the VTXOs — the executor only warns on that path, so
/// nothing else would notice.
pub(crate) async fn assert_action_completed(bark: &Bark) {
	let steps = bark.checkpoint_steps().await;
	assert!(
		steps.is_empty(),
		"action still checkpointed after it should have completed: {:?}", steps,
	);

	let vtxos = bark.vtxos().await;
	assert!(
		!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })),
		"VTXOs left locked after the action completed: {:?}", vtxos,
	);
}
