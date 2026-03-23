
mod core;
mod onchain;
mod vtxo;

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
