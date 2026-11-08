use bitcoin_ext::P2TR_DUST_SAT;

use ark_testing::{btc, sat, TestContext};

#[tokio::test]
async fn bark_allows_sending_dust_arkoor_but_errors_on_dust_refresh() {
	let ctx = TestContext::new("bark/bark_allows_sending_dust_arkoor_but_errors_on_dust_refresh").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

	let board_amount = sat(800_000);
	bark1.board_and_confirm_and_register(&ctx, board_amount).await;

	let dust_amount = sat(P2TR_DUST_SAT - 1);
	bark1.try_send_oor(&bark2.address().await, dust_amount, true).await.unwrap();

	let err = bark2.try_refresh_all_no_retry().await.unwrap_err();
	let err_str = format!("{err:?}");
	assert!(err_str.contains("vtxo amount must be at least"),
		"expected: dust validation error, got: {err_str}");
}
