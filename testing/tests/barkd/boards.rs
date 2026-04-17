use ark::fees::{BoardFees, PpmFeeRate};
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use bitcoin::Amount;

use super::helpers::{wait_for_boards_synced, wait_for_onchain_balance};

/// Verify that `barkd` can board all on-chain funds via the REST API.
#[tokio::test]
async fn board_all_barkd() {
	let ctx = TestContext::new("barkd/board_all_barkd").await;

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_onchain_balance(&barkd, sat(100_000)).await;

	let balance_before = barkd.bark_balance().await;
	assert_eq!(balance_before.spendable, Amount::ZERO, "bark balance should be zero before boarding");
	assert_eq!(balance_before.pending_board, Amount::ZERO, "bark balance should be zero before boarding");

	let board = barkd.board_all().await;

	// board_all drains the onchain wallet; the gross board amount is the
	// funded amount minus the onchain tx fee. With deterministic regtest
	// fees the resulting net amount (after Ark fees) is fixed.
	let expected_net = sat(98_349);
	assert_eq!(board.amount, expected_net, "board_all net amount should match expected");

	let balance_after = barkd.bark_balance().await;
	assert_eq!(balance_after.pending_board, board.amount, "pending board should match board amount");

	assert_eq!(board.vtxos.len(), 1, "board should produce one VTXO");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

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

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(200_000)).await;
	wait_for_onchain_balance(&barkd, sat(200_000)).await;

	let estimate = barkd.board_fee(sat(100_000)).await;
	assert_eq!(estimate.net_amount, sat(98_900), "net amount should be gross minus fees");

	let board = barkd.board_amount(sat(100_000)).await;
	assert_eq!(board.amount, estimate.net_amount, "board amount should match fee estimate");

	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 1, "should have one pending board before confirmation");
	assert_eq!(pending[0].amount, board.amount, "pending board amount should match board response");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let balance = barkd.bark_balance().await;
	assert_eq!(balance.spendable, estimate.net_amount, "spendable balance should match net amount after confirmation");
	assert_eq!(balance.pending_board, Amount::ZERO, "pending board should be cleared after confirmation");

	let pending_after = barkd.get_pending_boards().await;
	assert!(pending_after.is_empty(), "pending boards should be empty after confirmation");
}

/// Verify that two boards created before any confirmation both appear in
/// `GET /boards/pending` and that the list clears once they are confirmed.
#[tokio::test]
async fn pending_boards_barkd() {
	let ctx = TestContext::new("barkd/pending_boards_barkd").await;

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(300_000)).await;
	wait_for_onchain_balance(&barkd, sat(300_000)).await;

	let estimate = barkd.board_fee(sat(100_000)).await;
	assert_eq!(estimate.net_amount, sat(98_900), "net amount should be gross minus fees");

	let board1 = barkd.board_amount(sat(100_000)).await;
	let board2 = barkd.board_amount(sat(100_000)).await;

	assert_eq!(board1.amount, estimate.net_amount, "first board should match fee estimate");
	assert_eq!(board2.amount, estimate.net_amount, "second board should match fee estimate");

	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 2, "should have two pending boards before confirmation");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let pending_after = barkd.get_pending_boards().await;
	assert!(pending_after.is_empty(), "pending boards should be empty after confirmation");

	let balance = barkd.bark_balance().await;
	let expected = estimate.net_amount + estimate.net_amount;
	assert_eq!(balance.spendable, expected, "spendable balance should equal sum of both net amounts");
}

/// Verify that the daemon's background `run_boards_sync` automatically registers
/// a confirmed board without any manual `sync()` call.
#[tokio::test]
async fn board_auto_sync_barkd() {
	let ctx = TestContext::new("barkd/board_auto_sync_barkd").await;

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;

	let mut barkd = ctx.new_barkd_unstarted("barkd1", &srv).await;
	barkd.start().await.expect("failed to start barkd");
	barkd.create_wallet().await.expect("failed to create barkd wallet");

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_onchain_balance(&barkd, sat(100_000)).await;

	let estimate = barkd.board_fee(sat(50_000)).await;
	assert_eq!(estimate.net_amount, sat(49_400), "net amount should be gross minus fees");

	let board = barkd.board_amount(sat(50_000)).await;
	assert_eq!(board.amount, estimate.net_amount, "board amount should match fee estimate");

	let pending = barkd.get_pending_boards().await;
	assert_eq!(pending.len(), 1, "should have one pending board");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	wait_for_boards_synced(&barkd).await;

	let balance = barkd.bark_balance().await;
	assert_eq!(
		balance.spendable, estimate.net_amount,
		"spendable balance should match net amount after auto-sync",
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

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	let rates = barkd.onchain_fee_rates().await;
	assert!(rates.fast_sat_per_vb > 0, "fast fee rate should be positive");
	assert!(rates.regular_sat_per_vb > 0, "regular fee rate should be positive");
	assert!(rates.slow_sat_per_vb > 0, "slow fee rate should be positive");
	assert!(rates.fast_sat_per_vb >= rates.regular_sat_per_vb, "fast should be >= regular");
	assert!(rates.regular_sat_per_vb >= rates.slow_sat_per_vb, "regular should be >= slow");

	let estimate = barkd.board_fee(sat(100_000)).await;
	assert_eq!(estimate.gross_amount, sat(100_000), "gross amount should equal the requested amount");
	assert_eq!(estimate.fee, sat(1_100), "board fee should be base + ppm");
	assert_eq!(estimate.net_amount, sat(98_900), "net amount should be gross minus fee");
	assert_eq!(
		estimate.gross_amount, estimate.net_amount + estimate.fee,
		"gross should equal net + fee",
	);

	ctx.fund_barkd(&barkd, sat(200_000)).await;
	wait_for_onchain_balance(&barkd, sat(200_000)).await;

	let board = barkd.board_amount(sat(100_000)).await;

	assert_eq!(
		board.amount, estimate.net_amount,
		"actual board amount should match the fee estimate net amount",
	);
}

