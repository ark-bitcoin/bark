use bitcoin::Amount;
use bitcoin_ext::P2TR_DUST_SAT;

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

use ark_testing::barkd_helpers::{wait_for_boards_synced, wait_for_onchain_balance};

/// Server without fees
#[tokio::test]
async fn board_endpoints_barkd() {
	let ctx = TestContext::new("barkd/board_endpoints_barkd").await;
	let srv = ctx.captaind("server").create().await;

	// Board all on-chain funds
	Box::pin(async {
		let barkd = ctx.barkd("all", &srv).funded(sat(100_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(100_000)).await;

		let board = barkd.board_all().await;
		let [output] = board.funding_tx.tx.output.clone().try_into().expect("no change output");
		assert_eq!(board.amount, output.value);

		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wait_for_boards_synced(&barkd).await;

		assert_eq!(barkd.onchain_balance().await, Amount::ZERO);
		assert_eq!(barkd.bark_balance().await.spendable, board.amount);
	}).await;

	// Board twice before either board confirms
	Box::pin(async {
		let barkd = ctx.barkd("twice", &srv).funded(sat(300_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(300_000)).await;

		let board1 = barkd.board_amount(sat(100_000)).await;
		let board2 = barkd.board_amount(sat(100_000)).await;
		assert_eq!(board1.amount, sat(100_000));
		assert_eq!(board2.amount, sat(100_000));
		assert_eq!(barkd.get_pending_boards().await.len(), 2);
		assert_eq!(barkd.bark_balance().await.pending_board, sat(200_000));

		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wait_for_boards_synced(&barkd).await;

		assert_eq!(barkd.bark_balance().await.spendable, sat(200_000));
	}).await;

	// Refuse a board below the dust limit
	Box::pin(async {
		let barkd = ctx.barkd("dust", &srv).funded(sat(100_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(100_000)).await;

		let err = barkd.try_board_amount(sat(P2TR_DUST_SAT - 1)).await.unwrap_err().to_string();
		assert!(err.contains("Output below the dust limit"), "unexpected error: {err}");
		assert!(barkd.get_pending_boards().await.is_empty());
	}).await;

	// Report on-chain fee rates
	Box::pin(async {
		let barkd = ctx.barkd("fee-rates", &srv).create().await;

		let rates = barkd.onchain_fee_rates().await;
		assert!(rates.slow_sat_per_vb > 0, "slow fee rate should be positive");
		assert!(rates.fast_sat_per_vb >= rates.regular_sat_per_vb, "fast should be >= regular");
		assert!(rates.regular_sat_per_vb >= rates.slow_sat_per_vb, "regular should be >= slow");
	}).await;
}
