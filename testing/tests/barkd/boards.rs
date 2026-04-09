use std::time::Duration;

use ark::fees::{BoardFees, PpmFeeRate};
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use bitcoin::Amount;

/// Verify that `barkd` can board all on-chain funds via the REST API.
#[tokio::test]
async fn board_all_barkd() {
	let ctx = TestContext::new("barkd/board_all_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	assert_eq!(barkd.onchain_balance().await, sat(100_000));

	let balance_before = barkd.bark_balance().await;
	assert_eq!(balance_before.spendable, Amount::ZERO, "bark balance should be zero before boarding");
	assert_eq!(balance_before.pending_board, Amount::ZERO, "bark balance should be zero before boarding");

	let board = barkd.board_all().await;

	let balance_after = barkd.bark_balance().await;
	assert_ne!(balance_after.pending_board, Amount::ZERO, "bark balance should be non-zero after boarding");

	assert_eq!(board.vtxos.len(), 1, "board should produce one VTXO");
	// On-chain miner fees reduce the VTXO amount below the funded amount,
	// so we verify consistency between the board response and the pending balance
	// rather than comparing against the hardcoded funded amount.
	assert_eq!(board.amount, balance_after.pending_board, "board amount should match pending balance");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// After BOARD_CONFIRMATIONS the on-chain wallet should be drained.
	assert_eq!(barkd.onchain_balance().await, Amount::ZERO);

	let balance_confirmed = barkd.bark_balance().await;
	assert_eq!(balance_confirmed.spendable, board.amount, "spendable balance should match boarded amount after confirmation");
	assert_eq!(balance_confirmed.pending_board, Amount::ZERO, "pending board should be cleared after confirmation");
}

/// Verify that `POST /boards/board-amount` boards a specific amount and that
/// `GET /boards/pending` tracks the pending board until confirmed.
#[tokio::test]
async fn board_amount_barkd() {
	let ctx = TestContext::new("barkd/board_amount_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(200_000)).await;

	let board = barkd.board_amount(sat(100_000)).await;

	// The boarded amount may be slightly less than 100k due to on-chain fees,
	// but must be positive and not exceed the requested amount.
	assert!(board.amount > Amount::ZERO, "board amount should be positive");
	assert!(board.amount <= sat(100_000), "board amount should not exceed requested amount");

	// One pending board should appear before confirmation.
	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 1, "should have one pending board before confirmation");
	assert_eq!(pending[0].amount, board.amount, "pending board amount should match board response");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// After confirmation the board should be spendable.
	let balance = barkd.bark_balance().await;
	assert_eq!(balance.spendable, board.amount, "spendable balance should match boarded amount after confirmation");
	assert_eq!(balance.pending_board, Amount::ZERO, "pending board should be cleared after confirmation");

	// Pending boards list should now be empty.
	let pending_after = barkd.get_pending_boards().await;
	assert!(pending_after.is_empty(), "pending boards should be empty after confirmation");
}

/// Verify that two boards created before any confirmation both appear in
/// `GET /boards/pending` and that the list clears once they are confirmed.
#[tokio::test]
async fn pending_boards_barkd() {
	let ctx = TestContext::new("barkd/pending_boards_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	// Fund enough for two separate boards.
	ctx.fund_barkd(&barkd, sat(300_000)).await;

	let board1 = barkd.board_amount(sat(100_000)).await;
	let board2 = barkd.board_amount(sat(100_000)).await;

	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 2, "should have two pending boards before confirmation");

	// Both amounts should match the respective board responses.
	let amounts: Vec<Amount> = pending.iter().map(|b| b.amount).collect();
	assert!(amounts.contains(&board1.amount), "first board amount should be in pending list");
	assert!(amounts.contains(&board2.amount), "second board amount should be in pending list");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Both boards confirmed — list must be empty.
	let pending_after = barkd.get_pending_boards().await;
	assert!(pending_after.is_empty(), "pending boards should be empty after confirmation");

	// Combined spendable balance should reflect both boards.
	let balance = barkd.bark_balance().await;
	let expected = board1.amount + board2.amount;
	assert_eq!(balance.spendable, expected, "spendable balance should equal sum of both boarded amounts");
}

/// Verify that the daemon's background `run_boards_sync` automatically registers
/// a confirmed board without any manual `sync()` call.
#[tokio::test]
async fn board_auto_sync_barkd() {
	let ctx = TestContext::new("barkd/board_auto_sync_barkd").await;

	let srv = ctx.new_captaind("server", None).await;

	// Use a short slow-sync interval so the test doesn't wait for the 60s default.
	let slow_sync_secs: u64 = 5;
	let mut barkd = ctx.new_barkd_unstarted("barkd1", &srv).await;
	barkd.set_env("BARK_DAEMON_SLOW_SYNC_INTERVAL_SECS", slow_sync_secs.to_string());
	barkd.start().await.expect("failed to start barkd");
	barkd.create_wallet().await.expect("failed to create barkd wallet");

	ctx.fund_barkd(&barkd, sat(100_000)).await;

	// Board all funds. board_amount internally syncs onchain before boarding,
	// which is fine — the key is that we never call sync() after this point.
	let board = barkd.board_amount(sat(50_000)).await;
	assert!(board.amount > Amount::ZERO, "board amount should be positive");

	// Confirm the board is pending.
	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 1, "should have one pending board");

	// Mine enough blocks so the funding tx is confirmed.
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Do NOT call barkd.sync() or barkd.bark_balance() — let the daemon's
	// background run_boards_sync handle registration.
	// Poll get_pending_boards() which does not trigger a sync.
	let timeout = Duration::from_secs(slow_sync_secs * 3);
	let poll_interval = Duration::from_secs(1);
	let start = std::time::Instant::now();

	loop {
		let pending = barkd.get_pending_boards().await;
		if pending.is_empty() {
			break;
		}

		if start.elapsed() > timeout {
			panic!(
				"board auto-sync did not clear pending board within {:?} — \
				 daemon background sync may not be running (connected flag, \
				 select starvation, or silent error in sync_pending_boards)",
				timeout,
			);
		}

		tokio::time::sleep(poll_interval).await;
	}

	// The daemon auto-synced. Now verify the balance is correct.
	// bark_balance() calls sync() but the board is already registered,
	// so this just confirms the final state.
	let balance = barkd.bark_balance().await;
	assert_eq!(
		balance.spendable, board.amount,
		"spendable balance should match boarded amount after auto-sync",
	);
	assert_eq!(
		balance.pending_board, Amount::ZERO,
		"pending board should be zero after auto-sync",
	);
}

/// Verify that the fee estimation endpoints return sensible values for
/// board operations and on-chain fee rates.
#[tokio::test]
async fn board_fee_estimate_barkd() {
	let ctx = TestContext::new("barkd/board_fee_estimate_barkd").await;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	// Fee rates should be available even without funds.
	let rates = barkd.onchain_fee_rates().await;
	assert!(rates.fast_sat_per_vb > 0, "fast fee rate should be positive");
	assert!(rates.regular_sat_per_vb > 0, "regular fee rate should be positive");
	assert!(rates.slow_sat_per_vb > 0, "slow fee rate should be positive");
	assert!(rates.fast_sat_per_vb >= rates.regular_sat_per_vb, "fast should be >= regular");
	assert!(rates.regular_sat_per_vb >= rates.slow_sat_per_vb, "regular should be >= slow");

	// Estimate board fee for a specific amount.
	// Fee = base(100) + 100,000 * 10,000 / 1,000,000 = 100 + 1,000 = 1,100
	let estimate = barkd.board_fee(sat(100_000)).await;
	assert_eq!(estimate.gross_amount, sat(100_000), "gross amount should equal the requested amount");
	assert_eq!(estimate.fee, sat(1_100), "board fee should be base + ppm");
	assert_eq!(estimate.net_amount, sat(98_900), "net amount should be gross minus fee");
	assert_eq!(
		estimate.gross_amount, estimate.net_amount + estimate.fee,
		"gross should equal net + fee",
	);

	// Fund, board, and verify the actual board amount matches the estimate.
	ctx.fund_barkd(&barkd, sat(200_000)).await;

	let board = barkd.board_amount(sat(100_000)).await;

	// The board amount (VTXO value) should match the estimated net amount,
	// since both reflect the Ark protocol fee deduction on the same input.
	assert_eq!(
		board.amount, estimate.net_amount,
		"actual board amount should match the fee estimate net amount",
	);
}
