
use std::sync::Arc;
use std::time::Duration;

use ark_testing::{btc, lightning_test, require_bark_version, sat, Captaind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::context::LightningPaymentSetup;
use bark_rest_client::apis::lightning_api;

/// Verify that lightning receives are claimed via the mailbox path by
/// running barkd in `daemon_manual_sync` mode and driving the claim with
/// explicit `POST /sync/mailbox` calls. Any other code path would be unable
/// to advance the claim in this configuration, so a successful balance
/// update is proof that the mailbox did the work.
async fn ln_receive_via_mailbox(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	// The new ServerHtlcRecv policy breaks LN receive for bark 0.5.0 and older
	require_bark_version!(> "0.5.0");

	srv.wait_for_vtxopool(&ctx).await;

	// barkd in manual-sync mode: no startup sync, no periodic sync, no
	// round-events subscription, no mailbox subscription. Only the server
	// connection heartbeat keeps running. Every sync has to come from a
	// REST call below.
	let barkd = ctx.barkd("barkd", srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(btc(5))
		.create().await;

	// Pick up the on-chain funding, board, confirm, then force a sync so
	// the board lands as a spendable VTXO. The full /sync below runs
	// before any invoices exist, so the mailbox is still empty and this
	// doesn't prejudge the mailbox-only claim assertion further down.
	let board_amount = btc(3);
	barkd.onchain_sync().await;
	barkd.board_amount(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.sync().await;

	let amount_1 = sat(500_000);
	let amount_2 = sat(300_000);
	let invoice_1 = barkd.lightning_invoice(amount_1).await;
	let invoice_2 = barkd.lightning_invoice(amount_2).await;

	// In intra mode pay_lightning_wait blocks until the receiver claims.
	// The claim only lands when we pull the mailbox notification, so run
	// /sync/mailbox in a concurrent loop until the balance matches.
	let expected_balance = board_amount + amount_1 + amount_2;
	tokio::join!(
		pay(invoice_1.invoice),
		pay(invoice_2.invoice),
		async {
			let mut claimed = false;
			for _ in 0..30 {
				tokio::time::sleep(Duration::from_millis(500)).await;
				barkd.sync_mailbox().await;
				if barkd.bark_balance().await.spendable == expected_balance {
					claimed = true;
					break;
				}
			}
			assert!(claimed, "lightning receives should be claimed by /sync/mailbox");
		},
	);

	let pending = barkd.pending_lightning_receives().await;
	assert!(pending.is_empty(), "no pending receives should remain after mailbox sync");
	assert_eq!(
		barkd.bark_balance().await.spendable, expected_balance,
		"mailbox-driven claims should reflect the full expected balance",
	);
}
lightning_test!(ln_receive_via_mailbox, |cfg| {
	cfg.invoice_check_interval = Duration::from_secs(1);
});

/// `GET /lightning/sends/{identifier}` reports `unknown` for a payment
/// hash the wallet has never seen and rejects invalid identifiers.
#[tokio::test]
async fn lightning_send_status_unknown_for_unseen_hash() {
	let ctx = TestContext::new("barkd/lightning_send_status_unknown_for_unseen_hash").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let config = barkd.client_config();
	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	let info = lightning_api::get_send_status(&config, hash).await
		.expect("send status for an unseen hash should not error");
	assert_eq!(info.state, "unknown");
	assert_eq!(info.payment_hash.to_string(), hash);
	assert_eq!(info.preimage, None);

	lightning_api::get_send_status(&config, "lnbc1invalid").await
		.expect_err("an identifier that is neither a hash nor an invoice should be rejected");
}
