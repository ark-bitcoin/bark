
use std::time::Duration;

use ark_testing::{TestContext, btc, require_bark_version, sat};
use ark_testing::util::FutureExt;
use bark_json::movements::PaymentMethod;
use bark_json::notifications::WalletNotification;
use chrono::Utc;
use futures::StreamExt;

/// Verify that barkd pushes a `MovementCreated` notification over its
/// websocket endpoint when the wallet receives an arkoor payment.
#[tokio::test]
async fn barkd_pushes_notification_on_arkoor_received() {
	let ctx = TestContext::new("barkd/barkd_pushes_notification_on_arkoor_received").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(90_000)).create().await;
	let receiver = ctx.barkd("receiver", &srv).create().await;

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

/// Verify that barkd's long-poll `/notifications/wait` endpoint returns a
/// `MovementCreated` notification when an arkoor payment arrives while the
/// request is in flight.
#[tokio::test]
async fn barkd_long_polls_notification_on_arkoor_received() {
	require_bark_version!(> "0.1.4");
	let ctx = TestContext::new("barkd/barkd_long_polls_notification_on_arkoor_received").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(90_000)).create().await;
	let receiver = ctx.barkd("receiver", &srv).create().await;

	sender.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	// Calling wait before any notifications are pushed should return an empty response
	let resp = receiver.wait_notification(None).await;
	assert!(resp.notifications.is_empty(), "should not have received any notifications yet");
	assert!(resp.last_pushed_at.is_none(), "there is no notification in the buffer yet");

	// Calling wait before any notifications are pushed should return an empty response
	let now = Utc::now();
	let resp = receiver.wait_notification(Some(now)).await;
	assert!(resp.notifications.is_empty(), "should not have received any notifications yet");
	assert_eq!(resp.last_pushed_at, Some(now),
		"last_pushed_at should be the same as the now timestamp");

	// Wait for first notification to be received
	let addr_1 = receiver.ark_address().await;
	let (resp, _) = tokio::join!(
		receiver.wait_notification(resp.last_pushed_at),
		async {
			tokio::time::sleep(Duration::from_millis(300)).await;
			sender.send_oor(&addr_1, sat(30_000)).await;
		},
	);

	let [notif_1] = resp.notifications.try_into()
		.expect("expected exactly one notification");
	match &notif_1 {
		WalletNotification::MovementCreated { movement } => {
			assert_eq!(movement.received_on.len(), 1, "expected exactly one recipient on the movement");
			assert_eq!(movement.received_on[0].amount, sat(30_000),
				"notification amount should match the board amount");
			assert_eq!(movement.received_on[0].destination, PaymentMethod::Ark(addr_1),
				"notification address should match the arkoor send address");
		},
		_ => panic!("expected a MovementCreated notification"),
	}
	assert!(resp.last_pushed_at.is_some(),
		"long-poll response missing last_pushed_at timestamp");

	// Calling wait again with last notification timestamp should return the only the new notification
	let addr_2 = receiver.ark_address().await;
	let (resp, _) = tokio::join!(
		receiver.wait_notification(resp.last_pushed_at),
		async {
			tokio::time::sleep(Duration::from_millis(300)).await;
			sender.send_oor(&addr_2, sat(20_000)).await;
		},
	);

	let [notif_2] = resp.notifications.try_into()
		.expect("expected exactly one notification");
	match &notif_2 {
		WalletNotification::MovementCreated { movement } => {
			assert_eq!(movement.received_on.len(), 1, "expected exactly one recipient on the movement");
			assert_eq!(movement.received_on[0].amount, sat(20_000),
				"notification amount should match the board amount");
			assert_eq!(movement.received_on[0].destination, PaymentMethod::Ark(addr_2),
				"notification address should match the arkoor send address");
		},
		_ => panic!("expected a MovementCreated notification"),
	}
	assert!(resp.last_pushed_at.is_some(),
		"long-poll response missing last_pushed_at timestamp");

	// Calling wait again with no since should return both notifications
	let resp = receiver.wait_notification(None).ready().await;
	assert_eq!(resp.notifications, vec![notif_1, notif_2]);

	let balance = receiver.bark_balance().await;
	assert_eq!(balance.spendable, sat(50_000),
		"receiver spendable balance should reflect the received arkoor");
}

/// Verify that the long-poll `/notifications/wait` endpoint rejects requests
/// that lack an `Authorization: Bearer …` header. Authentication is enforced
/// at the HTTP layer before any business logic runs.
#[tokio::test]
async fn barkd_long_poll_rejects_unauthenticated() {
	require_bark_version!(> "0.1.4");
	let ctx = TestContext::new("barkd/barkd_long_poll_rejects_unauthenticated").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("receiver", &srv).create().await;

	let url = format!("{}/api/v1/notifications/wait", barkd.base_url());
	let resp = reqwest::Client::new()
		.get(&url)
		.send()
		.await
		.expect("request to /notifications/wait failed");

	assert_eq!(resp.status().as_u16(), 401,
		"expected 401 Unauthorized from unauthenticated long-poll, got {}", resp.status());
}
