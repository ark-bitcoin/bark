
use std::time::Duration;

use bitcoin::Amount;

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

