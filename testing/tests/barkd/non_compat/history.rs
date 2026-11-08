
use ark_testing::{btc, sat, TestContext};
use bark_json::movements::PaymentMethod;
use bark_rest_client::apis::Error;
use bark_rest_client::apis::history_api;

/// `GET /api/v1/history` returns the full movement history, and the `type` and
/// `value` query parameters filter it down to a single payment method.
#[tokio::test]
async fn history_filter_by_payment_method() {
	let ctx = TestContext::new("barkd/history_filter_by_payment_method").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(90_000)).create().await;
	let receiver = ctx.barkd("receiver", &srv).create().await;

	sender.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	// Send an arkoor to a known address of the receiver, then make sure the
	// resulting movement is persisted.
	let addr = receiver.ark_address().await;
	sender.send_oor(&addr, sat(20_000)).await;
	receiver.sync().await;

	// Without query parameters the full history is returned.
	let full = receiver.history(None, None).await;
	assert!(!full.is_empty(), "receiver should have at least one movement");

	// Filtering by the ark address the payment was received on returns exactly
	// that movement.
	let filtered = receiver.history(Some("ark"), Some(&addr)).await;
	assert_eq!(filtered.len(), 1,
		"exactly one movement should match the receiving ark address");
	assert!(
		filtered[0].received_on.iter().any(|d| matches!(
			&d.destination, PaymentMethod::Ark(a) if *a == addr,
		)),
		"matched movement should have been received on the queried address",
	);

	// Filtering by an unrelated but valid ark address matches nothing.
	let other = sender.address().await;
	let none = receiver.history(Some("ark"), Some(&other)).await;
	assert!(none.is_empty(),
		"no movement should match an address the wallet never received on");

	// Supplying only one of the pair is a bad request.
	match history_api::list(&receiver.client_config(), Some("ark"), None).await {
		Ok(_) => panic!("`type` without `value` should be rejected"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 400),
		Err(other) => panic!("expected 400 ResponseError, got {:?}", other),
	}
}
