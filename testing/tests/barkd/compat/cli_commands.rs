//! Tests for `bark-cli` commands that map onto barkd endpoints. The
//! endpoints themselves are covered by the barkd suite.

use std::time::Instant;

use bitcoin::Amount;
use tokio::io::AsyncReadExt;

use bark_json::notifications::WalletNotification;
use bark_rest_client::apis::lightning_api;

use ark_testing::{btc, sat, BarkClient, Barkd, TestContext};
use ark_testing::util::{poll_interval, wait_timeout};

async fn wait_for_spendable(barkd: &Barkd, expected: Amount) {
	let deadline = Instant::now() + wait_timeout();
	loop {
		barkd.sync().await;
		let spendable = barkd.bark_balance().await.spendable;
		if spendable == expected {
			return;
		}
		assert!(Instant::now() < deadline,
			"spendable balance did not reach {} (current: {})", expected, spendable);
		tokio::time::sleep(poll_interval()).await;
	}
}

/// `send` pays a BIP 321 URI through barkd, with the method kind picked by
/// `--method`.
#[tokio::test]
async fn send_to_bip321_uri() {
	let ctx = TestContext::new("bark_client/send_to_bip321_uri").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let bark = BarkClient::new("bark", sender.datadir(), Some(sender.base_url()));

	let uri = recipient.bip321_uri(None, true, None, None, false).await.bip321;
	bark.run(["send", &uri, "50000 sats", "--method", "ark"]).await;

	wait_for_spendable(&recipient, sat(50_000)).await;
}

/// `bip321` prints a URI with the requested destinations.
#[tokio::test]
async fn bip321_prints_uri() {
	let ctx = TestContext::new("bark_client/bip321_prints_uri").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;
	let bark = BarkClient::new("bark", barkd.datadir(), Some(barkd.base_url()));

	let uri = bark.run(["bip321", "--onchain"]).await;
	assert!(uri.starts_with("bitcoin:"), "unexpected uri: {}", uri);
	assert!(uri.contains("ark="), "uri should carry an Ark address: {}", uri);
	assert!(uri.contains("tb="), "uri should carry an on-chain address: {}", uri);
}

/// `watch` prints the notification for an incoming arkoor payment.
#[tokio::test]
async fn watch_prints_received_payment() {
	let ctx = TestContext::new("bark_client/watch_prints_received_payment").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let bark = BarkClient::new("bark", recipient.datadir(), Some(recipient.base_url()));

	let mut watch = bark.spawn(["watch"]);
	let mut stdout = watch.stdout.take().expect("stdout is piped");

	// watch only prints notifications from its start on.
	tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	let addr = recipient.ark_address().await;
	sender.send(&addr, sat(30_000)).await;

	// Notifications are printed as pretty JSON, so read until one parses.
	let deadline = Instant::now() + wait_timeout();
	let mut output = String::new();
	let notification = loop {
		let mut buf = [0u8; 4096];
		let read = tokio::time::timeout(poll_interval(), stdout.read(&mut buf)).await;
		if let Ok(read) = read {
			let n = read.expect("failed to read watch output");
			assert!(n > 0, "watch exited early, output: {}", output);
			output.push_str(std::str::from_utf8(&buf[..n]).expect("watch output is utf-8"));
			let mut stream = serde_json::Deserializer::from_str(&output)
				.into_iter::<WalletNotification>();
			if let Some(Ok(notification)) = stream.next() {
				break notification;
			}
		}
		assert!(Instant::now() < deadline, "no notification printed, output: {}", output);
	};

	assert!(matches!(notification, WalletNotification::MovementCreated { .. }),
		"unexpected notification: {:?}", notification);
}

/// `ln invoice --wait` stops with an error once the receive is canceled,
/// rather than waiting for a payment that cannot come.
#[tokio::test]
async fn invoice_wait_stops_on_canceled_receive() {
	let ctx = TestContext::new("bark_client/invoice_wait_stops_on_canceled_receive").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;
	let bark = BarkClient::new("bark", barkd.datadir(), Some(barkd.base_url()));
	let config = barkd.client_config();

	let cancel = async {
		let deadline = Instant::now() + wait_timeout();
		let invoice = loop {
			let receives = lightning_api::list_receive_statuses(&config).await
				.expect("failed to list receives");
			if let Some(receive) = receives.first() {
				break receive.invoice.clone();
			}
			assert!(Instant::now() < deadline, "the invoice was never created");
			tokio::time::sleep(poll_interval()).await;
		};
		lightning_api::cancel_receive(&config, &invoice).await
			.expect("failed to cancel the receive");
	};
	let (wait, ()) = tokio::join!(bark.try_run(["ln", "invoice", "10000 sats", "--wait"]), cancel);

	let err = wait.expect_err("ln invoice --wait should fail once the receive is canceled");
	assert!(err.to_string().contains("ended without settling"), "unexpected error: {:#}", err);
}

