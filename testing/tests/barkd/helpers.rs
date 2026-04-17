
use std::time::Duration;

use bitcoin::Amount;

use bark_json::exit::ExitState;

use ark_testing::TestContext;
use ark_testing::daemon::barkd::Barkd;

/// Poll until the on-chain balance reaches the expected amount. Relies on
/// the daemon's background `run_onchain_sync` to detect new transactions.
pub async fn wait_for_onchain_balance(barkd: &Barkd, expected: Amount) {
	let timeout = Duration::from_secs(15);
	let poll_interval = Duration::from_secs(1);
	let start = std::time::Instant::now();

	loop {
		let balance = barkd.onchain_balance().await;
		if balance >= expected {
			return;
		}
		if start.elapsed() > timeout {
			panic!(
				"onchain balance did not reach {} within {:?} (current: {})",
				expected, timeout, balance,
			);
		}
		tokio::time::sleep(poll_interval).await;
	}
}

/// Wait for the daemon's background sync to register all confirmed boards
/// as spendable VTXOs. Polls `get_pending_boards()` (read-only)
/// so the daemon does the work, not an explicit sync call.
pub async fn wait_for_boards_synced(barkd: &Barkd) {
	let timeout = Duration::from_secs(15);
	let poll_interval = Duration::from_secs(1);
	let start = std::time::Instant::now();

	loop {
		let pending = barkd.get_pending_boards().await;
		if pending.is_empty() {
			return;
		}
		if start.elapsed() > timeout {
			panic!(
				"board auto-sync did not clear pending boards within {:?}",
				timeout,
			);
		}
		tokio::time::sleep(poll_interval).await;
	}
}

/// Wait for the barkd daemon to finish processing all pending rounds.
///
/// Blocks are generated on each iteration because `trigger_round` returns
/// before the round completes (fire-and-forget). The round tx may not have
/// been broadcast when the caller's `generate_blocks` ran, so we keep mining
/// here until the tx is confirmed with enough depth.
///
/// Uses `pending_rounds()` which internally syncs round state via the REST
/// endpoint — no explicit `wallet.sync()` call needed.
pub async fn wait_for_rounds_complete(ctx: &TestContext, barkd: &Barkd) {
	let timeout = Duration::from_secs(60);
	let poll_interval = Duration::from_secs(1);
	let start = std::time::Instant::now();

	loop {
		ctx.generate_blocks(1).await;
		tokio::time::sleep(poll_interval).await;

		let pending = barkd.pending_rounds().await;
		if pending.is_empty() {
			return;
		}
		if start.elapsed() > timeout {
			panic!(
				"barkd pending rounds did not complete within {:?}",
				timeout,
			);
		}
	}
}

/// Wait for all in-progress exits to reach the Claimable (or Claimed) state.
///
/// Generates blocks and polls the exit status endpoint, letting the daemon's
/// background `run_exits()` do all the actual work. Does NOT call
/// `exit_progress()` — that would manually drive exits and hide daemon bugs.
pub async fn wait_for_exits_claimable(ctx: &TestContext, barkd: &Barkd) {
	let timeout = Duration::from_secs(120);
	let poll_interval = Duration::from_secs(3);
	let start = std::time::Instant::now();

	loop {
		ctx.generate_blocks(1).await;

		let statuses = barkd.get_all_exit_status(None, None).await;
		let all_claimable = !statuses.is_empty() && statuses.iter().all(|s|
			matches!(s.state, ExitState::Claimable(_) | ExitState::Claimed(_))
		);
		if all_claimable {
			return;
		}

		if start.elapsed() > timeout {
			panic!(
				"exit auto-progress did not complete within {:?} — \
				 daemon background run_exits() may not be running. \
				 Current states: {:?}",
				timeout,
				statuses.iter().map(|s| &s.state).collect::<Vec<_>>(),
			);
		}

		tokio::time::sleep(poll_interval).await;
	}
}
