//! Lightning payments across a captaind upgrade.
//!
//! Every test brings a payment into a specific in-flight state on the
//! old release (the OLD_CAPTAIND_EXEC binary), upgrades the server to
//! the current binary, and verifies the payment (and fresh ones) still
//! complete. No database records are inspected; the only oracle is
//! wallet-observable behavior.

use std::time::Duration;

use futures::StreamExt;

use ark::lightning::{PaymentHash, Preimage};
use ark_testing::{btc, Captaind, TestContext};
use ark_testing::context::LightningPaymentSetup;
use ark_testing::daemon::captaind::proxy::ArkRpcProxyServer;
use ark_testing::util::{FutureExt, poll_interval};

use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::LightningReceiveState;
use cln_rpc::plugins::hold;
use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMsg;

/// Run `<exec> --version` and return its stdout.
async fn captaind_version(exec: &std::path::Path) -> String {
	let output = tokio::process::Command::new(exec)
		.arg("--version")
		.output().await
		.unwrap_or_else(|e| panic!("failed to run {} --version: {}", exec.display(), e));
	assert!(output.status.success(),
		"{} --version exited with {}", exec.display(), output.status);
	String::from_utf8(output.stdout).expect("--version output is valid utf-8")
}

/// Write the old and new captaind versions to the test artifacts, so a
/// failed run always shows which two binaries were involved.
async fn write_version_artifact(ctx: &TestContext) {
	let old = captaind_version(&Captaind::old_exec()).await;
	let new = {
		let e = std::env::var("CAPTAIND_EXEC").expect("CAPTAIND_EXEC env not set");
		let exec = ark_testing::util::resolve_path(e).expect("failed to resolve CAPTAIND_EXEC");
		captaind_version(&exec).await
	};
	let content = format!("old: {}new: {}", old, new);
	tokio::fs::write(ctx.datadir.join("captaind-versions.txt"), content).await
		.expect("writing captaind-versions.txt artifact");
}

/// Config overrides needed to run the current Config struct on the old
/// release binary.
fn old_captaind_cfg(cfg: &mut server::Config) {
	// The upgrade itself takes a while; held HTLCs must not time out
	// mid-upgrade.
	cfg.receive_htlc_forward_timeout = Duration::from_secs(300);
}

/// Stop the old-release captaind and start the same datadir and
/// database on the current binary. Database migrations run on startup.
async fn upgrade_captaind(srv: &Captaind, proxy: &ArkRpcProxyServer) {
	srv.stop().await.expect("old captaind stops");
	srv.set_exec(None);
	srv.start().await.expect("new captaind starts");
	// The restart moved the server to fresh ports; repoint the proxy.
	proxy.set_ark_upstream(srv.get_public_rpc().await);
	proxy.set_mailbox_upstream(srv.get_mailbox_public_rpc().await);
}

/// Create a hold invoice on the external CLN node.
async fn create_external_hold_invoice(
	lightning: &LightningPaymentSetup,
	amount: bitcoin::Amount,
) -> (String, Preimage, PaymentHash) {
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();

	let mut hold_client = lightning.external.hold_client().await;
	let bolt11 = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"server_migration_hold_invoice".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	(bolt11, preimage, payment_hash)
}

/// Wait until the hold plugin holds the payment's HTLCs.
async fn wait_for_hold_invoice_accepted(
	hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>,
	payment_hash: PaymentHash,
) {
	async {
		loop {
			let invoices = hold_client.list(hold::ListRequest {
				constraint: Some(hold::list_request::Constraint::PaymentHash(
					payment_hash.as_ref().to_vec(),
				)),
			}).await.expect("list hold invoices").into_inner().invoices;
			let invoice = invoices.first().expect("hold invoice should exist");
			if invoice.state() == hold::InvoiceState::Accepted {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await
}

/// Wait on the wallet's mailbox stream until the server announces an
/// incoming lightning payment for the given hash.
async fn wait_for_incoming_payment_notification(
	wallet: &bark::Wallet,
	payment_hash: PaymentHash,
) {
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");
	loop {
		let msg = mailbox.next().wait_millis(30_000).await
			.expect("mailbox stream ended before notification")
			.expect("mailbox stream error");
		if let Some(MailboxMsg::IncomingLightningPayment(m)) = msg.message {
			assert_eq!(m.payment_hash, payment_hash.to_vec(),
				"notification for unexpected payment");
			break;
		}
	}
}

/// An outgoing payment to an external hold invoice survives the
/// upgrade: HTLCs are held while the server is swapped, the invoice is
/// settled afterwards and the wallet sees the payment succeed.
#[tokio::test]
async fn external_send_settles_after_upgrade() {
	let ctx = TestContext::new("server-migrations/external_send_settles_after_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	// Wallets connect through the proxy: the server restarts on fresh
	// ports during the upgrade and the proxy is repointed instead.
	let proxy = srv.start_proxy_no_mailbox(()).await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &proxy).boarded(board_amount).create().await;
	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let (bolt11, preimage, payment_hash) =
		create_external_hold_invoice(&lightning, invoice_amount).await;

	// The old server sends the HTLCs; the external node holds them.
	wallet.pay_lightning_invoice(bolt11, None, false).await
		.expect("pay_lightning_invoice failed");
	let mut hold_client = lightning.external.hold_client().await;
	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	upgrade_captaind(&srv, &proxy).await;

	// Settle the invoice; the upgraded server must pick up the
	// completed payment and hand the preimage to the wallet.
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	let status = wallet.check_lightning_payment(payment_hash, true)
		.wait_millis(60_000).await
		.expect("check_lightning_payment errored");
	match status {
		LightningSendState::Paid(paid) => {
			assert_eq!(paid.payment_hash, payment_hash);
			assert_eq!(paid.preimage, preimage);
		},
		other => panic!("payment should be paid after settle, got {:?}", other),
	}

	let balance = wallet.balance().await.expect("balance");
	assert_eq!(balance.spendable, board_amount - invoice_amount);
}

/// An outgoing payment whose hold invoice is cancelled after the
/// upgrade fails cleanly: the upgraded server revokes the HTLC vtxos
/// and the wallet gets its funds back.
#[tokio::test]
async fn external_send_revokes_after_upgrade() {
	let ctx = TestContext::new("server-migrations/external_send_revokes_after_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &proxy).boarded(board_amount).create().await;
	lightning.sync().await;

	let (bolt11, _preimage, payment_hash) =
		create_external_hold_invoice(&lightning, btc(0.5)).await;

	wallet.pay_lightning_invoice(bolt11, None, false).await
		.expect("pay_lightning_invoice failed");
	let mut hold_client = lightning.external.hold_client().await;
	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	upgrade_captaind(&srv, &proxy).await;

	// Cancel the hold invoice — the HTLC fails back to the upgraded
	// server and the wallet revokes the HTLC vtxos.
	hold_client.cancel(hold::CancelRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
	}).await.expect("cancel hold invoice");

	// On failure the send record is removed once revocation completes.
	let status = wallet.check_lightning_payment(payment_hash, true)
		.wait_millis(60_000).await
		.expect("check_lightning_payment errored");
	assert_eq!(status, LightningSendState::Unknown);

	let balance = wallet.balance().await.expect("balance");
	assert_eq!(balance.spendable, board_amount);
	assert_eq!(balance.pending_lightning_send, btc(0));
}

/// A bolt11 invoice created on the old server is still payable after
/// the upgrade: the external node pays, the wallet claims.
#[tokio::test]
async fn external_receive_created_before_upgrade() {
	let ctx = TestContext::new("server-migrations/external_receive_created_before_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	upgrade_captaind(&srv, &proxy).await;

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			wait_for_incoming_payment_notification(&wallet, payment_hash).await;
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);
	pay_result.expect("lightning payment failed");

	let balance = wallet.balance().await.expect("balance");
	assert_eq!(balance.spendable, invoice_amount);
}

/// A receive whose HTLCs were already accepted on the old server can
/// still be claimed after the upgrade.
#[tokio::test]
async fn external_receive_accepted_before_upgrade() {
	let ctx = TestContext::new("server-migrations/external_receive_accepted_before_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// The old server accepts the HTLCs and posts the
			// notification; the upgrade happens with the HTLCs held.
			wait_for_incoming_payment_notification(&wallet, payment_hash).await;
			upgrade_captaind(&srv, &proxy).await;
			wallet.try_claim_lightning_receive(payment_hash, true).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);
	pay_result.expect("lightning payment failed");

	let balance = wallet.balance().await.expect("balance");
	assert_eq!(balance.spendable, invoice_amount);
}

/// An intra-ark invoice created on the old server completes after the
/// upgrade: one bark pays, the other claims, both see success.
#[tokio::test]
async fn intra_ark_created_before_upgrade() {
	let ctx = TestContext::new("server-migrations/intra_ark_created_before_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;
	srv.wait_for_vtxopool(&ctx).await;

	let receiver = ctx.bark_sdk("receiver", &proxy)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	let sender = ctx.bark_sdk("sender", &proxy).boarded(btc(2)).create().await;

	let invoice_amount = btc(0.5);
	let invoice = receiver.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	upgrade_captaind(&srv, &proxy).await;

	sender.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	let state = receiver.try_claim_lightning_receive(payment_hash, true)
		.wait_millis(60_000).await
		.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	let status = sender.check_lightning_payment(payment_hash, true)
		.wait_millis(60_000).await
		.expect("check_lightning_payment errored");
	assert!(matches!(status, LightningSendState::Paid(_)),
		"send should be paid after the claim, got {:?}", status);

	let balance = receiver.balance().await.expect("balance");
	assert_eq!(balance.spendable, invoice_amount);
}

/// An intra-ark payment whose HTLCs were already locked on the old
/// server completes after the upgrade.
#[tokio::test]
async fn intra_ark_accepted_before_upgrade() {
	let ctx = TestContext::new("server-migrations/intra_ark_accepted_before_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;
	srv.wait_for_vtxopool(&ctx).await;

	let receiver = ctx.bark_sdk("receiver", &proxy)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	let sender = ctx.bark_sdk("sender", &proxy).boarded(btc(2)).create().await;

	let invoice_amount = btc(0.5);
	let invoice = receiver.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	// The old server locks the sender's HTLC vtxos and marks the
	// receive accepted; the receiver hasn't claimed yet.
	sender.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	upgrade_captaind(&srv, &proxy).await;

	let state = receiver.try_claim_lightning_receive(payment_hash, true)
		.wait_millis(60_000).await
		.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	let status = sender.check_lightning_payment(payment_hash, true)
		.wait_millis(60_000).await
		.expect("check_lightning_payment errored");
	assert!(matches!(status, LightningSendState::Paid(_)),
		"send should be paid after the claim, got {:?}", status);

	let balance = receiver.balance().await.expect("balance");
	assert_eq!(balance.spendable, invoice_amount);
}

/// A server upgraded with a settled payment history keeps serving
/// fresh payments: a new send and a new receive both complete on the
/// upgraded server.
#[tokio::test]
async fn fresh_payments_after_upgrade() {
	let ctx = TestContext::new("server-migrations/fresh_payments_after_upgrade").await;
	write_version_artifact(&ctx).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.exec(Captaind::old_exec())
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.cfg(old_captaind_cfg)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(()).await;
	srv.wait_for_vtxopool(&ctx).await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.boarded(board_amount)
		.create().await;
	lightning.sync().await;

	// Complete a payment on the old server so the upgrade has real
	// payment history to migrate.
	let pre_amount = btc(0.2);
	let pre_invoice = lightning.external
		.invoice(Some(pre_amount), "pre-upgrade", "pre-upgrade payment").await;
	wallet.pay_lightning_invoice(pre_invoice, None, true).await
		.expect("pre-upgrade payment failed");

	upgrade_captaind(&srv, &proxy).await;

	// A fresh send on the upgraded server.
	let send_amount = btc(0.3);
	let invoice = lightning.external
		.invoice(Some(send_amount), "post-upgrade", "post-upgrade payment").await;
	wallet.pay_lightning_invoice(invoice, None, true)
		.wait_millis(60_000).await
		.expect("post-upgrade payment failed");

	// A fresh receive on the upgraded server.
	let receive_amount = btc(0.1);
	let invoice = wallet.bolt11_invoice(receive_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			wait_for_incoming_payment_notification(&wallet, payment_hash).await;
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);
	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);
	pay_result.expect("lightning payment failed");

	let balance = wallet.balance().await.expect("balance");
	assert_eq!(
		balance.spendable,
		board_amount - pre_amount - send_amount + receive_amount,
	);
}
