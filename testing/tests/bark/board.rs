use bitcoin::Amount;
use bitcoin_ext::P2TR_DUST_SAT;

use bark_json::primitives::VtxoStateInfo;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

#[tokio::test]
async fn board_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_bark").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(100_000)).await;

	let board = bark1.board(sat(BOARD_AMOUNT)).await;

	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT), bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_twice_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_twice_bark").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(200_000)).await;

	let board_a = bark1.board(sat(BOARD_AMOUNT)).await;
	let board_b = bark1.board(sat(BOARD_AMOUNT)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "should have 2 board vtxos");
	assert!(vtxos.iter().any(|v| v.id == board_a.vtxos[0]));
	assert!(vtxos.iter().any(|v| v.id == board_b.vtxos[0]));
	assert!(vtxos.iter().all(|v| matches!(v.state, VtxoStateInfo::Locked { .. })));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT) * 2, bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_all_bark() {
	let ctx = TestContext::new("bark/board_all_bark").await;

	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;

	// Get the bark-address and fund it
	ctx.fund_bark(&bark1, sat(100_000)).await;
	assert_eq!(bark1.onchain_balance().await, sat(100_000));

	let board = bark1.board_all().await;
	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Check that we emptied our on-chain balance
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	// Check if the boarding tx's output value is the same as our off-chain balance
	let board_tx = ctx.bitcoind().await_transaction(board.funding_tx.txid).await;
	assert_eq!(
		bark1.spendable_balance().await,
		board_tx.output.last().unwrap().value,
	);
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn bark_rejects_boarding_subdust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_subdust_amount").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	let board_amount = sat(P2TR_DUST_SAT - 1);
	let res = bark1.try_board(board_amount).await;

	// This is taken care by BDK
	assert!(res.unwrap_err().to_string().contains(&format!("Output below the dust limit: 0")));
}

#[tokio::test]
async fn bark_rejects_boarding_below_minimum_board_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_below_minimum_board_amount").await;
	// Set up server with `min_board_amount` of 30 000 sats
	const MIN_BOARD_AMOUNT_SATS: u64 = 30_000;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.min_board_amount = sat(MIN_BOARD_AMOUNT_SATS);
	}).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	let board_amount = sat(MIN_BOARD_AMOUNT_SATS - 1);
	let res = bark1.try_board(board_amount).await;

	assert!(res.unwrap_err().to_string().contains(&format!(
		"board amount of 0.00029999 BTC is less than minimum board amount required by server (0.00030000 BTC)",
	)));
}
