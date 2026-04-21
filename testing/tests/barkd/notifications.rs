
use ark_testing::{btc, sat, TestContext};
use ark_testing::util::FutureExt;
use bark_json::notifications::WalletNotification;
use futures::StreamExt;

/// Verify that barkd pushes a `MovementCreated` notification over its
/// websocket endpoint when the wallet receives an arkoor payment.
#[tokio::test]
async fn barkd_pushes_notification_on_arkoor_received() {
	let ctx = TestContext::new("barkd/barkd_pushes_notification_on_arkoor_received").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(90_000)).create().await;
	let receiver = ctx.new_barkd("receiver", &srv).await;

	sender.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	let mut notifications = receiver.notification_websocket().await;

	let addr = receiver.ark_address().await;
	sender.send_oor(&addr, sat(20_000)).await;

	let movement = loop {
		let notif = notifications.next()
			.ready().await
			.expect("websocket closed before notification");
		match notif {
			WalletNotification::MovementCreated { movement } => break movement,
			// The first `MovementUpdated` for an arkoor receive can also be
			// acceptable, but we want to assert the `Created` path fires.
			WalletNotification::MovementUpdated { .. }
			| WalletNotification::ChannelLagging => continue,
		}
	};

	assert_eq!(movement.received_on.len(), 1, "expected exactly one recipient on the movement");
	assert_eq!(movement.received_on[0].amount, sat(20_000),
		"notification amount should match the arkoor send amount");

	let balance = receiver.bark_balance().await;
	assert_eq!(balance.spendable, sat(20_000),
		"receiver spendable balance should reflect the received arkoor");
}
