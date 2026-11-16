
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bark_json::cli::LightningSendStateKind;

use ark_testing::{btc, lightning_test, require_bark_version, sat, Captaind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::context::LightningPaymentSetup;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{action_drive_factor, FutureExt, poll_interval};
use ark::lightning::Invoice;
use bark_rest_client::apis::{lightning_api, Error};
use bark_rest_client::models::{LightningInvoiceRequest, LightningPayRequest};
use server::database::Db;
use server_rpc::protos;

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
	ctx.generate_blocks(2).await;

	// barkd in manual-sync mode: no startup sync, no periodic sync, no
	// round-events subscription, no mailbox subscription. Only the server
	// connection heartbeat keeps running. Every sync has to come from a
	// REST call below.
	let barkd = ctx.barkd("barkd", srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.create().await;

	// Generate two lightning invoices
	let amount_1 = sat(500_000);
	let amount_2 = sat(300_000);
	let invoice_1 = barkd.lightning_invoice(amount_1).await;
	let invoice_2 = barkd.lightning_invoice(amount_2).await;

	// In intra mode pay_lightning_wait blocks until the receiver claims.
	// The claim only lands when we pull the mailbox notification, so run
	// /sync/mailbox in a concurrent loop until the balance matches.
	let expected_balance = amount_1 + amount_2;
	tokio::join!(
		pay(invoice_1.invoice),
		pay(invoice_2.invoice),
		async {
			let mut claimed = false;
			for _ in 0..30 {
				tokio::time::sleep(Duration::from_millis(500)).await;
				barkd.sync().await;
				if barkd.bark_balance().await.spendable == expected_balance {
					claimed = true;
					break;
				}
			}
			assert!(claimed, "lightning receives should be claimed by /sync");
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

/// barkd retries a lightning receive claim that failed.
///
/// The mailbox notification drives the claim one time. A proxy fails that
/// claim, so only the periodic daemon sync can complete the receive.
#[tokio::test]
async fn retries_failed_lightning_receive_claim() {
	require_bark_version!(> "0.8.1");

	let ctx = TestContext::new("barkd/retries_failed_lightning_receive_claim").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;

	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	/// Fails the first `fail_count` claims and forwards the others.
	#[derive(Clone)]
	struct FailFirstClaims {
		claims: Arc<AtomicUsize>,
		fail_count: usize,
	}

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for FailFirstClaims {
		async fn claim_lightning_receive(
			&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			if self.claims.fetch_add(1, Ordering::Relaxed) < self.fail_count {
				return Err(tonic::Status::internal("simulated claim failure"));
			}
			Ok(upstream.claim_lightning_receive(req).await?.into_inner())
		}
	}

	// Fail all claims of the first drive. The double-drive mode runs each
	// step two times.
	let fail_count = action_drive_factor();
	let claims = Arc::new(AtomicUsize::new(0));
	let proxy = srv.start_proxy_no_mailbox(FailFirstClaims { claims: claims.clone(), fail_count }).await;
	let barkd = ctx.barkd("barkd", &srv)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;

	let amount = sat(500_000);
	let invoice = barkd.lightning_invoice(amount).await;

	tokio::join!(
		lightning.external.pay_bolt11(invoice.invoice),
		async {
			// Read the balance only. `POST /sync` also drives the claim.
			while barkd.bark_balance().await.spendable != amount {
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(30_000),
	);

	assert!(claims.load(Ordering::Relaxed) > fail_count,
		"barkd must claim again after the failed claim");
}

/// barkd drives pending lightning receives without `POST /sync`.
///
/// The invoice is not paid, so the Ark server sends no mailbox message.
/// Only the periodic daemon sync can see that the Ark server canceled the
/// expired invoice, and remove the receive.
#[tokio::test]
async fn removes_expired_lightning_receive() {
	require_bark_version!(> "0.8.1");

	let ctx = TestContext::new("barkd/removes_expired_lightning_receive").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	let barkd = ctx.barkd("barkd", &srv).create().await;

	let req = LightningInvoiceRequest {
		amount_sat: 500_000, description: None, expiry_secs: Some(1), token: None,
	};
	lightning_api::generate_invoice(&barkd.client_config(), req).await.unwrap();
	assert_eq!(barkd.pending_lightning_receives().await.len(), 1);

	// Read the pending list only. `POST /sync` also drives the receive.
	async {
		while !barkd.pending_lightning_receives().await.is_empty() {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
}

/// `GET /lightning/sends/{identifier}` reports `unknown` for a payment
/// hash the wallet has never seen and rejects invalid identifiers.
#[tokio::test]
async fn lightning_send_status_unknown_for_unseen_hash() {
	require_bark_version!(>= "0.6.2");

	let ctx = TestContext::new("barkd/lightning_send_status_unknown_for_unseen_hash").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let config = barkd.client_config();
	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	let info = lightning_api::get_send_status(&config, hash).await
		.expect("send status for an unseen hash should not error");
	assert_eq!(info.state, LightningSendStateKind::Unknown);
	assert_eq!(info.payment_hash.to_string(), hash);
	assert_eq!(info.preimage, None);

	lightning_api::get_send_status(&config, "lnbc1invalid").await
		.expect_err("an identifier that is neither a hash nor an invoice should be rejected");
}

/// `GET /lightning/receives/{identifier}` is a 404 for a payment hash the
/// wallet does not know, which includes a receive that ended without settling.
#[tokio::test]
async fn lightning_receive_status_not_found_for_unseen_hash() {
	require_bark_version!(>= "0.8.1");

	let ctx = TestContext::new("barkd/lightning_receive_status_not_found_for_unseen_hash").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let hash = "0000000000000000000000000000000000000000000000000000000000000000";
	match lightning_api::get_receive_status(&barkd.client_config(), hash).await {
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 404),
		other => panic!("expected 404 for an unseen hash, got {:?}", other.map(|r| r.state)),
	}
}

/// Both REST payment endpoints pass `retry_for_secs` on to the server.
#[tokio::test]
async fn pay_with_retry_for() {
	// Older barkd binaries don't know the field and silently drop it.
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("barkd/pay_with_retry_for").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let barkd = ctx.barkd("barkd", &srv).funded(btc(5)).create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(btc(3)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.sync().await;
	lightning.sync().await;

	let max = srv.config().cln_xpay_max_retry_for.as_secs();
	let config = barkd.client_config();
	let db = Db::connect(&srv.config().postgres).await.expect("connect to server db");

	// Above the maximum is capped to it.
	let pay_invoice = lightning.external.invoice(Some(btc(0.1)), "pay", "pay").await;
	let resp = lightning_api::pay(&config, LightningPayRequest {
		destination: pay_invoice,
		amount_sat: None,
		comment: None,
		retry_for_secs: Some(max + 1),
	}).await.expect("lightning pay");

	let send_invoice = lightning.external.invoice(Some(btc(0.1)), "send", "send").await;
	barkd.pay_lightning(&send_invoice, Some(max - 2)).await;
	let send_payment_hash = Invoice::from_str(&send_invoice).expect("invoice").payment_hash();

	for (payment_hash, retry_for_secs) in [
		(resp.payment_hash.expect("payment hash"), max),
		(send_payment_hash, max - 2),
	] {
		let attempt = async {
			loop {
				let attempt = db.read(async |t|
					t.get_latest_payment_attempt_by_payment_hash(payment_hash).await
				).await.expect("db read");
				if let Some(attempt) = attempt {
					break attempt;
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(10_000).await;
		assert_eq!(attempt.retry_for, Some(Duration::from_secs(retry_for_secs)));
	}
}
