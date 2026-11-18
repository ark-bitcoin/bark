use bitcoin_ext::P2TR_DUST_SAT;

use ark_testing::{btc, require_bark_version, sat, TestContext};

#[tokio::test]
async fn bark_allows_sending_dust_arkoor_but_errors_on_dust_refresh() {
	require_bark_version!(>= "0.9.0");

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

/// A spend of a small VTXO has only dust outputs. All of them go to the dust
/// isolation tx, so the checkpoint tx has no dust output and can be relayed.
#[tokio::test]
async fn bark_can_spend_small_vtxo_to_dust_outputs() {
	// A released bark puts these dust outputs on the checkpoint tx. The server
	// does not co-sign that.
	require_bark_version!(>= "0.9.0");

	let ctx = TestContext::new("bark/bark_can_spend_small_vtxo_to_dust_outputs").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	let bark3 = ctx.bark("bark3", &srv).create().await;

	bark1.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	// bark2 gets a single small VTXO
	bark1.send_oor(&bark2.address().await, sat(600)).await;
	assert_eq!(bark2.spendable_balance().await, sat(600));
	assert_eq!(bark2.vtxos().await.len(), 1);

	// both the payment and the change are dust
	bark2.send_oor(&bark3.address().await, sat(100)).await;
	assert_eq!(bark2.spendable_balance().await, sat(500));
	assert_eq!(bark3.spendable_balance().await, sat(100));

	// the isolated VTXOs can be spent again
	bark2.send_oor(&bark3.address().await, sat(250)).await;
	assert_eq!(bark2.spendable_balance().await, sat(250));
	assert_eq!(bark3.spendable_balance().await, sat(350));
}
