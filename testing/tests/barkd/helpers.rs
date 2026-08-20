
use std::time::Duration;

use bitcoin::Amount;

use bark_json::exit::ExitState;
use bark_json::primitives::{VtxoStateInfo, WalletVtxoInfo};

use ark_testing::TestContext;
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::barkd::Barkd;
use ark_testing::util::poll_interval;

/// Poll until the on-chain balance reaches the expected amount. Relies on
/// the daemon's background `run_onchain_sync` to detect new transactions.
pub async fn wait_for_onchain_balance(barkd: &Barkd, expected: Amount) {
	let timeout = Duration::from_secs(15);
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
		tokio::time::sleep(poll_interval()).await;
	}
}

/// Wait for the daemon's background sync to register all confirmed boards
/// as spendable VTXOs. Polls `get_pending_boards()` (read-only)
/// so the daemon does the work, not an explicit sync call.
pub async fn wait_for_boards_synced(barkd: &Barkd) {
	let timeout = Duration::from_secs(15);
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
		tokio::time::sleep(poll_interval()).await;
	}
}

/// Wait for the barkd daemon to finish processing all pending rounds.
///
/// Blocks are generated on each iteration because `trigger_round` returns
/// before the round completes (fire-and-forget). Once the round funding tx
/// is broadcast, the remaining confirmations are mined in one go instead of
/// block-per-poll.
///
/// Uses `pending_rounds()` which internally syncs round state via the REST
/// endpoint — no explicit `wallet.sync()` call needed.
pub async fn wait_for_rounds_complete(ctx: &TestContext, barkd: &Barkd) {
	let timeout = Duration::from_secs(60);
	let poll_interval = Duration::from_millis(250);
	let start = std::time::Instant::now();

	// A daemon-driven round may not be registered yet when we get here;
	// only conclude there is nothing to wait for after this grace period.
	let registration_grace = Duration::from_secs(3);
	let mut pending = barkd.pending_rounds().await;
	while pending.is_empty() && start.elapsed() < registration_grace {
		tokio::time::sleep(poll_interval).await;
		pending = barkd.pending_rounds().await;
	}

	loop {
		if pending.is_empty() {
			return;
		}
		if start.elapsed() > timeout {
			panic!(
				"barkd pending rounds did not complete within {:?}",
				timeout,
			);
		}

		if pending.iter().any(|r| r.funding_txid.is_some()) {
			// The funding tx is broadcast; mine the full confirmation depth
			// at once. Overshooting is harmless if it confirmed already.
			ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
		} else {
			// The round is still in its submit/sign phases; keep the chain
			// moving so anything in flight confirms.
			ctx.generate_blocks(1).await;
		}
		tokio::time::sleep(poll_interval).await;
		pending = barkd.pending_rounds().await;
	}
}

/// Wait for all in-progress exits to reach the Claimable (or Claimed) state.
///
/// Polls the exit status endpoint, letting the daemon's background
/// `run_exits()` do all the actual work. Does NOT call `exit_progress()` —
/// that would manually drive exits and hide daemon bugs.
///
/// Once an exit reports `AwaitingDelta`, the blocks still needed to reach
/// `claimable_height` are mined in one go, using the tip watcher to confirm
/// the tip moved, instead of mining one block per poll interval.
pub async fn wait_for_exits_claimable(ctx: &TestContext, barkd: &Barkd) {
	let timeout = Duration::from_secs(120);
	let poll_interval = Duration::from_millis(250);
	let start = std::time::Instant::now();

	loop {
		let statuses = barkd.get_live_exit_status(None, None).await;
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

		let claimable_height = statuses.iter().filter_map(|s| match s.state {
			ExitState::AwaitingDelta(ref delta) => Some(delta.claimable_height),
			_ => None,
		}).max();
		let any_processing = statuses.iter().any(|s|
			matches!(s.state, ExitState::Processing(_))
		);

		let tip = ctx.bitcoind().tip_watcher().tip().height;
		let blocks_to_mine = match claimable_height {
			Some(target) if target > tip => target - tip,
			// An exit tx still has to confirm; mine a block so it can.
			_ if any_processing => 1,
			_ => 0,
		};
		if blocks_to_mine > 0 {
			if any_processing {
				// Synced generation lets the exit tx propagate before mining.
				ctx.generate_blocks(blocks_to_mine).await;
			} else {
				ctx.generate_blocks_unsynced(blocks_to_mine).await;
				// Confirm the tip actually moved before re-polling statuses.
				ctx.bitcoind().wait_for_blockheight(tip + blocks_to_mine).await;
			}
			continue;
		}

		tokio::time::sleep(poll_interval).await;
	}
}

/// Drive `sync` until the wallet's spendable balance equals `expected`.
///
/// Some flows (e.g. a Lightning receive) resolve asynchronously after the REST
/// call returns, so we sync on each poll. Panics with the last-seen balance on
/// timeout rather than failing silently.
pub async fn wait_for_spendable(barkd: &Barkd, expected: Amount) {
	let timeout = Duration::from_secs(15);
	let start = std::time::Instant::now();

	loop {
		barkd.sync().await;
		let balance = barkd.bark_balance().await;
		if balance.spendable == expected {
			return;
		}
		if start.elapsed() > timeout {
			panic!(
				"spendable balance did not reach {} within {:?} (current: {})",
				expected, timeout, balance.spendable,
			);
		}
		tokio::time::sleep(poll_interval()).await;
	}
}

/// Drive `sync` until the wallet's VTXO set satisfies `predicate`, returning it.
///
/// For flows that resolve asynchronously after the REST call returns (e.g. a
/// Lightning send resolving to change, or a failed send being revoked). Panics
/// with the last-seen set on timeout.
#[allow(dead_code)]
pub async fn wait_for_vtxos(
	barkd: &Barkd,
	predicate: impl Fn(&[WalletVtxoInfo]) -> bool,
) -> Vec<WalletVtxoInfo> {
	let timeout = Duration::from_secs(15);
	let start = std::time::Instant::now();

	loop {
		barkd.sync().await;
		let vtxos = barkd.vtxos(None).await;
		if predicate(&vtxos) {
			return vtxos;
		}
		if start.elapsed() > timeout {
			panic!(
				"wallet VTXO set did not reach the expected state within {:?}: {:?}",
				timeout, vtxos,
			);
		}
		tokio::time::sleep(poll_interval()).await;
	}
}

/// Drive `sync` until the wallet holds exactly `count` VTXOs that are all
/// spendable, returning them.
///
/// Gating on the spendable state (not just the count) skips transient
/// intermediates: an in-flight Lightning HTLC or offboard change is briefly
/// present as a locked VTXO the server already considers spent, so a bare count
/// can capture a VTXO the recovered wallet will never rediscover.
#[allow(dead_code)]
pub async fn wait_for_spendable_vtxos(barkd: &Barkd, count: usize) -> Vec<WalletVtxoInfo> {
	wait_for_vtxos(barkd, |vtxos| {
		vtxos.len() == count && vtxos.iter().all(|v| v.state == VtxoStateInfo::Spendable)
	}).await
}
