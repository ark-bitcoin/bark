use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;

use bitcoin::Amount;
use bitcoin::secp256k1::Keypair;

use ark::{ProtocolEncoding, SECP, VtxoPolicy};
use ark::address::VtxoDelivery;
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::arkoor::state::UserGeneratedNonces;
use ark::lightning::{Bolt11InvoiceExt, PaymentHash, Preimage};
use bitcoin_ext::{AmountExt, BlockDelta};
use ark_testing::{TestContext, btc, sat, util::{FutureExt, poll_interval}};
use ark_testing::Captaind;
use ark_testing::balance::assert_balance_consistent;
use ark_testing::context::LightningPaymentSetup;
use ark_testing::daemon::captaind::{self, ArkClient};

use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::movement::MovementStatus;
use bark::subsystem::Subsystem;
use bark::LightningSendOptions;
use bark::lightning_invoice::Bolt11Invoice;
use cln_rpc::plugins::hold;
use server::database::Db;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message as MailboxMsg;

/// Wait until the hold plugin holds the payment's HTLCs. The invoice turns
/// ACCEPTED only once every HTLC is irrevocably committed and handed to the
/// plugin; a settle before that fails with "no HTLCs to settle".
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
	}.wait_millis(30_000).await
}

#[tokio::test]
async fn pay_hold_succeeds() {
	let ctx = TestContext::new("bark_sdk/pay_hold_succeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	// Build a hold invoice on the external CLN node. The HTLC won't be
	// settled until we hand the preimage to the hold plugin.
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"sdk_pay_lightning_hold_invoice".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	// Initiates the payment; HTLCs are now in flight but the external
	// node holds them. pay_lightning_invoice returns once the HTLCs are
	// sent, not once they settle.
	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// The payment is pending because the receiver hasn't claimed it yet
	// We report this correctly
	let status = wallet.check_lightning_payment(payment_hash, false).await .expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to get completed
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't settled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before settlement");

	// Settle the invoice
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	// ready()'s 2s bound is too tight under BARK_DOUBLE_DRIVE_ACTIONS: steps run twice and the send re-polls every 2s.
	let status = waiter.wait_millis(10_000).await.expect("join waiter");
	match &status {
		Ok(LightningSendState::Paid(invoice)) => {
			assert_eq!(invoice.payment_hash, payment_hash);
			assert_eq!(invoice.preimage, preimage);
		},
		err => panic!("Payment did not succeed: {:?}", err),
	}

	// A subsequent check should return the same cached result
	let new_status =  wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, status.unwrap());

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, board_amount - invoice_amount);
}

#[tokio::test]
async fn pay_hold_with_near_expiry_inputs_succeeds() {
	let ctx = TestContext::new("bark_sdk/pay_hold_with_near_expiry_inputs_succeeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	// Short vtxo lifetime keeps the block-advance cheap; absurdly long
	// round interval keeps any background refresh out of the picture.
	let srv = ctx.captaind("server").lightningd(&lightning.internal).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(100);
		cfg.round_interval = Duration::from_secs(86400);
	}).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	// Push the boarded VTXO past its expiry. An expired VTXO can still fund
	// a lightning payment; it and its change count as needs_refresh. The
	// lightning send used to spuriously fail this scenario because it
	// conflated input-VTXO expiry with HTLC expiry; the fresh HTLC's own
	// CLTV (htlc_send_expiry_delta blocks ahead) is still comfortably far
	// out, so the payment should still settle normally.
	ctx.generate_blocks(98).await;

	lightning.sync().await;

	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"pay_hold_with_expired_inputs_succeeds".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// The payment is pending because the receiver hasn't claimed it yet
	// We report this correctly
	let status = wallet.check_lightning_payment(payment_hash, false).await .expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.needs_refresh, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to get completed
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't settled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before settlement");

	// Settle the invoice
	hold_client.settle(hold::SettleRequest {
		payment_preimage: preimage.as_ref().to_vec(),
	}).await.expect("settle hold invoice");

	// ready()'s 2s bound is too tight under BARK_DOUBLE_DRIVE_ACTIONS: steps run twice and the send re-polls every 2s.
	let status = waiter.wait_millis(10_000).await.expect("join waiter");
	match &status {
		Ok(LightningSendState::Paid(invoice)) => {
			assert_eq!(invoice.payment_hash, payment_hash);
			assert_eq!(invoice.preimage, preimage);
		},
		err => panic!("Payment did not succeed: {:?}", err),
	}

	// A subsequent check should return the same cached result
	let new_status =  wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, status.unwrap());

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.needs_refresh, board_amount - invoice_amount);
}

#[tokio::test]
async fn pay_hold_refused() {
	let ctx = TestContext::new("bark_sdk/pay_hold_refused").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	// Build a hold invoice on the external CLN node. We never settle it
	// — instead we cancel, which makes the held HTLC fail back through
	// the route.
	let preimage = Preimage::random();
	let payment_hash = preimage.compute_payment_hash();
	let invoice_amount = btc(0.5);

	let mut hold_client = lightning.external.hold_client().await;
	let invoice = hold_client.invoice(hold::InvoiceRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_msat: invoice_amount.to_sat() * 1_000,
		description: Some(hold::invoice_request::Description::Memo(
			"sdk_pay_lightning_hold_invoice_fail".into(),
		)),
		min_final_cltv_expiry: Some(18),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.expect("create hold invoice").into_inner().bolt11;

	wallet.pay_lightning_invoice(invoice, None, false).await
		.expect("pay_lightning_invoice failed");

	// The payment is pending because the receiver hasn't claimed or
	// cancelled it yet; while the HTLC is in flight the locked amount
	// should be tracked as pending lightning send and excluded from
	// spendable.
	let status = wallet.check_lightning_payment(payment_hash, false).await.expect("no-wait check errored");
	match status {
		LightningSendState::InProgress(pending) => {
			let pending_balance = pending.payment_amount + pending.fee;
			let balance = assert_balance_consistent(&wallet, false).await;
			assert_eq!(balance.spendable, board_amount - pending_balance);
			assert_eq!(balance.pending_lightning_send, pending_balance);
		}
		other => panic!("Payment should be pending was {:?}", other),
	};

	// Wait for the payment to resolve
	let waiter = {
		let wallet = wallet.clone();
		tokio::spawn(async move {
			wallet.check_lightning_payment(payment_hash, true).await
		})
	};

	// We should wait if the invoice isn't cancelled
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(!waiter.is_finished(), "waiting check resolved before cancel");

	// A cancel that races the HTLC into the hold plugin cancels 0 HTLCs and
	// leaves the HTLC held forever.
	wait_for_hold_invoice_accepted(&mut hold_client, payment_hash).await;

	// Cancel the hold invoice — the HTLC fails back to the server and
	// bark revokes the HTLC vtxos, restoring the funds.
	hold_client.cancel(hold::CancelRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
	}).await.expect("cancel hold invoice");

	// On failure the LightningSend record is removed once revocation completes, so the state
	// is Unknown. With CLN 26.06, xpay reports the destination failure before CLN's own sendpay
	// row transitions to failed, so captaind's immediate listpays reconciliation still sees
	// Pending and marks the attempt Submitted. It only flips to Failed on the next
	// process_payment_attempts tick. Wait long enough for that under
	// BARK_DOUBLE_DRIVE_ACTIONS + a couple of bark re-poll intervals.
	let status = waiter.wait_millis(40_000).await.expect("join waiter")
		.expect("waiting check errored");
	assert_eq!(status, LightningSendState::Unknown);

	// A subsequent check should also report Unknown
	let new_status = wallet.check_lightning_payment(payment_hash, false).await.expect("Failed to query lightning send");
	assert_eq!(new_status, LightningSendState::Unknown);

	// After revocation the HTLC vtxos come back as spendable
	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, board_amount);
	assert_eq!(balance.pending_lightning_send, btc(0));
}

/// Any integrator should be able to claim a lightning receive off the raw mailbox stream
/// alone, without depending on bark's own background sync loop or any particular sync method:
/// create an invoice, wait on the mailbox stream for the incoming-HTLC notification, then call
/// `try_claim_lightning_receive` once. No daemon and no background syncing runs, so that single
/// claim call has to complete the receive on its own.
#[tokio::test]
async fn receive_claim_on_mailbox_notification() {
	let ctx = TestContext::new("bark_sdk/receive_claim_on_mailbox_notification").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);

	// Subscribe to the mailbox stream before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// Wait for the server's incoming-payment notification.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(m)) = msg.message {
					assert_eq!(m.payment_hash, payment_hash.to_vec(),
						"notification for unexpected payment");
					break;
				}
			}
			wallet.try_claim_lightning_receive(payment_hash, false).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let movements = wallet.history().await.expect("movements");
	let recv_mvt = movements.iter()
		.find(|m| m.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE))
		.expect("no lightning receive movement");
	assert_eq!(recv_mvt.status, MovementStatus::Successful,
		"lightning receive movement should be successful, got {:?}", recv_mvt.status);

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

/// The cooperative claim and the server's hold settler both settle the hold
/// invoice off the same preimage, so either can get there first. Settling the
/// invoice out of band before the claim forces the losing case: the claim
/// must still hand over the claim vtxos rather than fail on the hold plugin's
/// "no HTLCs to settle".
#[tokio::test]
async fn receive_claim_after_hold_invoice_already_settled() {
	let ctx = TestContext::new("bark_sdk/receive_claim_after_hold_invoice_already_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;

	lightning.sync().await;

	let invoice_amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(invoice_amount, None, None).await
		.expect("creating invoice");
	let payment_hash = PaymentHash::from(&invoice);
	let preimage = wallet.lightning_receive_checkpoint(payment_hash).await
		.expect("fetching receive checkpoint")
		.expect("receive checkpoint should exist")
		.payment_preimage;

	let mut hold_client = lightning.internal.hold_client().await;

	// Subscribe before the payment arrives.
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await
		.expect("subscribing to mailbox stream");

	let (pay_result, claim_result) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			// The server posts the incoming-payment notification only after
			// it has registered the acceptance, so settling after it keeps
			// the server able to hand over the claim vtxos.
			loop {
				let msg = mailbox.next().wait_millis(10_000).await
					.expect("mailbox stream ended before notification")
					.expect("mailbox stream error");
				if let Some(MailboxMsg::IncomingLightningPayment(_)) = msg.message {
					break;
				}
			}

			// Stand in for the hold settler getting there first.
			hold_client.settle(hold::SettleRequest {
				payment_preimage: preimage.as_ref().to_vec(),
			}).await.expect("settling the hold invoice out of band");

			wallet.try_claim_lightning_receive(payment_hash, true).await
		},
	);

	let state = claim_result.expect("try_claim_lightning_receive errored");
	assert!(matches!(state, LightningReceiveState::Settled(_)),
		"receive should be settled after the claim, got {:?}", state);

	pay_result.expect("lightning payment failed");

	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.spendable, invoice_amount);
}

#[tokio::test]
async fn pay_with_retry_for() {
	let ctx = TestContext::new("bark_sdk/pay_with_retry_for").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let board_amount = btc(2);
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(board_amount)
		.create().await;

	lightning.sync().await;

	let max = srv.config().cln_xpay_max_retry_for;

	// The server keeps the time on the attempt, which the xpay monitor waits
	// out before reconciling it. 0 makes a single attempt, and a time above
	// the maximum is capped to it.
	let db = Db::connect(&srv.config().postgres).await.expect("connect to server db");
	let one_sec = Duration::from_secs(1);
	for (retry_for, expected) in [
		(Duration::ZERO, Duration::ZERO),
		(max - one_sec, max - one_sec),
		(max + one_sec, max),
	] {
		let invoice = lightning.external.invoice(Some(btc(0.1)), format!("pay-{:?}", retry_for), "pay").await;
		let opts = LightningSendOptions::default().wait(true).retry_for(Some(retry_for));
		let invoice = wallet.pay_lightning_invoice_with(invoice, None, opts).await
			.expect("pay_lightning_invoice failed");

		let attempt = db.read(async |t|
			t.get_latest_payment_attempt_by_payment_hash(invoice.payment_hash()).await
		).await.expect("db read").expect("payment attempt");
		assert_eq!(attempt.retry_for, Some(expected));
	}
}

/// A server that lets users put their Ark address in invoices, and two
/// wallets on it that use it.
async fn ark_address_hint_setup(
	ctx: &TestContext, expiry_payouts: bool,
) -> (LightningPaymentSetup, Arc<Captaind>, bark::Wallet, bark::Wallet) {
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(move |cfg| {
			cfg.ln_receive_ark_address_hints = true;
			cfg.expiry_payouts = expiry_payouts;
		})
		.create().await;
	srv.wait_for_vtxopool(ctx).await;
	let payer = ctx.bark_sdk("payer", &srv).boarded(sat(400_000))
		.cfg(|cfg| cfg.lightning_ark_address_hints = true)
		.create().await;
	let receiver = ctx.bark_sdk("receiver", &srv)
		.cfg(|cfg| cfg.lightning_ark_address_hints = true)
		.create().await;
	lightning.sync().await;
	(lightning, srv, payer, receiver)
}

async fn server_receive_status(
	srv: &Captaind,
	hash: PaymentHash,
) -> protos::LightningReceiveStatus {
	let status = srv.get_public_rpc().await
		.check_lightning_receive(protos::CheckLightningReceiveRequest {
			hash: hash.to_vec(),
			wait: false,
		}).await.unwrap().into_inner().status;
	protos::LightningReceiveStatus::try_from(status).unwrap()
}

/// An invoice that carries the receiver's Ark address is paid with an
/// arkoor by a wallet on the same server. The server and the receiver see
/// the invoice paid, as if it had been paid over lightning, and it can't
/// be paid again.
#[tokio::test]
async fn pay_invoice_on_its_ark_address() {
	let ctx = TestContext::new("bark_sdk/pay_invoice_on_its_ark_address").await;
	let (lightning, srv, payer, receiver) = ark_address_hint_setup(&ctx, false).await;

	let amount = sat(100_000);
	let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let address = invoice.ark_address().expect("invoice carries an Ark address");

	// A plain arkoor to that address doesn't pay the invoice.
	payer.send_arkoor_payment(&address, sat(10_000)).await.unwrap();
	receiver.sync().await;
	assert!(matches!(receiver.lightning_receive_state(hash).await.unwrap(),
		LightningReceiveState::InProgress(_)));
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Created);

	let mut paid = receiver.subscribe_notifications().filter_lightning_payment_movements(hash);
	payer.pay_lightning_invoice(invoice.clone(), None, true).await.unwrap();
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Settled);

	receiver.sync().await;
	let movement = paid.next().wait_millis(10_000).await.expect("receiver saw the invoice paid");
	assert_eq!(movement.status, MovementStatus::Successful);
	assert!(movement.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE));
	match receiver.lightning_receive_state(hash).await.unwrap() {
		LightningReceiveState::Settled(settled) => assert_eq!(settled.amount, amount),
		other => panic!("receive not settled: {:?}", other),
	}

	// No lightning fees on either side.
	let balance = assert_balance_consistent(&receiver, false).await;
	assert_eq!(balance.spendable, amount + sat(10_000));
	let balance = assert_balance_consistent(&payer, false).await;
	assert_eq!(balance.spendable, sat(400_000) - amount - sat(10_000));

	// Nobody can pay the invoice again.
	payer.pay_lightning_invoice(invoice.clone(), None, true).await
		.expect_err("paid the invoice twice");
	lightning.external.try_pay_bolt11(invoice.to_string()).await
		.expect_err("paid over lightning after it was paid by arkoor");
	let balance = assert_balance_consistent(&receiver, false).await;
	assert_eq!(balance.spendable, amount + sat(10_000));
}

/// Lightning nodes find no route through the Ark address hints and pay
/// the invoice as usual.
#[tokio::test]
async fn external_payer_pays_invoice_with_ark_address() {
	let ctx = TestContext::new("bark_sdk/external_payer_pays_invoice_with_ark_address").await;
	let (lightning, _srv, _payer, receiver) = ark_address_hint_setup(&ctx, false).await;

	let amount = sat(100_000);
	let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
	assert!(invoice.ark_address().is_some());
	let hash = PaymentHash::from(&invoice);

	let (paid, claimed) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		receiver.try_claim_lightning_receive(hash, true),
	);
	paid.expect("external payment failed");
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
}

/// A wallet that doesn't pay Ark addresses pays the invoice over
/// lightning, and the wallet that didn't ask for an Ark address gets an
/// invoice without one.
#[tokio::test]
async fn ark_address_hints_are_opt_in() {
	let ctx = TestContext::new("bark_sdk/ark_address_hints_are_opt_in").await;
	let (_lightning, srv, _payer, receiver) = ark_address_hint_setup(&ctx, false).await;

	let other = ctx.bark_sdk("other", &srv).boarded(sat(400_000)).create().await;
	let invoice = other.bolt11_invoice(sat(10_000), None, None).await.unwrap();
	assert_eq!(invoice.ark_address(), None);

	let amount = sat(100_000);
	let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
	assert!(invoice.ark_address().is_some());
	let hash = PaymentHash::from(&invoice);

	let (paid, claimed) = tokio::join!(
		other.pay_lightning_invoice(invoice.clone(), None, true),
		receiver.try_claim_lightning_receive(hash, true),
	);
	paid.unwrap();
	assert!(matches!(claimed.unwrap(), LightningReceiveState::Settled(_)));
	assert!(matches!(other.lightning_send_state(hash).await.unwrap(), LightningSendState::Paid(_)));
}

/// An invoice paid on its Ark address in payout mode binds the VTXO the
/// receiver gets to the receiver's mailbox.
#[tokio::test]
async fn ark_address_payment_binds_the_receivers_mailbox() {
	let ctx = TestContext::new("bark_sdk/ark_address_payment_binds_the_receivers_mailbox").await;
	let (_lightning, srv, payer, receiver) = ark_address_hint_setup(&ctx, true).await;
	let invoice = receiver.bolt11_invoice(sat(50_000), None, None).await.unwrap();
	assert!(invoice.ark_address().is_some());
	let hash = PaymentHash::from(&invoice);
	payer.pay_lightning_invoice(invoice, None, true).await.unwrap();
	receiver.sync().await;
	assert!(matches!(receiver.lightning_receive_state(hash).await.unwrap(), LightningReceiveState::Settled(_)));
	let ids = receiver.spendable_vtxos().await.unwrap().iter().map(|vtxo| vtxo.id()).collect::<Vec<_>>();
	assert!(!ids.is_empty());
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let owners = db.read(async |t| t.vtxo_owner_mailboxes(&ids).await).await.unwrap();
	assert!(ids.iter().all(|id| owners.get(id) == Some(&receiver.mailbox_identifier().as_pubkey())));
}

/// A wallet that asks for Ark address route hints and syncs only when the
/// test asks it to, so it claims no receive by itself.
async fn manual_hint_receiver(ctx: &TestContext, srv: &Captaind) -> bark::Wallet {
	ctx.bark_sdk("manual_receiver", srv)
		.cfg(|cfg| {
			cfg.lightning_ark_address_hints = true;
			cfg.daemon_manual_sync = true;
		})
		.create().await
}

/// An arkoor that pays the amount of `invoice` from a VTXO of `payer` to the
/// Ark address of the invoice, with the change to a key nobody uses, and
/// the key of that VTXO.
async fn arkoor_to_invoice_address(
	payer: &bark::Wallet, invoice: &Bolt11Invoice,
) -> (ArkoorPackageBuilder<UserGeneratedNonces>, Keypair) {
	let address = invoice.ark_address().expect("invoice carries an Ark address");
	let amount = Amount::from_msat_floor(invoice.amount_milli_satoshis().unwrap());
	let vtxo = payer.spendable_vtxos().await.unwrap().pop().unwrap();
	let vtxo = payer.get_full_vtxo(vtxo.id()).await.unwrap();
	let key = payer.get_vtxo_key(&vtxo).await.unwrap();
	let change = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let outputs = vec![
		ArkoorDestination { total_amount: amount, policy: address.policy().clone() },
		ArkoorDestination {
			total_amount: vtxo.amount() - amount,
			policy: VtxoPolicy::new_pubkey(change.public_key()),
		},
	];
	let builder = ArkoorPackageBuilder::new_with_checkpoints([vtxo], outputs).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	(builder, key)
}

/// The request to pay the invoice of `hash` with `arkoor`.
fn invoice_arkoor(
	hash: PaymentHash, arkoor: &ArkoorPackageBuilder<UserGeneratedNonces>,
) -> protos::LightningReceiveArkoorCosignRequest {
	protos::LightningReceiveArkoorCosignRequest {
		payment_hash: hash.to_vec(),
		cosign_request: Some(arkoor.cosign_request().into()),
	}
}

/// The receive row of `hash` and the number of its history rows.
async fn receive_rows(db: &Db, hash: PaymentHash) -> (String, i64) {
	db.read(async |t| {
		let row = t.query_one("
			SELECT to_jsonb(s)::TEXT FROM lightning_htlc_subscription s WHERE payment_hash = $1
		", &[&hash.to_string()]).await?;
		let history = t.query_one("
			SELECT COUNT(*) FROM lightning_htlc_subscription_history WHERE payment_hash = $1
		", &[&hash.to_string()]).await?;
		Ok((row.get(0), history.get(0)))
	}).await.unwrap()
}

/// Only a new arkoor settles an invoice on its Ark address. An arkoor that
/// the server co-signed before as a plain arkoor cannot settle it. A retry
/// of the arkoor that settled it is co-signed again and changes nothing,
/// and the settled receive takes no other arkoor.
#[tokio::test]
async fn ark_address_invoice_is_settled_by_a_new_arkoor_only() {
	let ctx = TestContext::new("bark_sdk/ark_address_invoice_is_settled_by_a_new_arkoor_only").await;
	let (_lightning, srv, payer, receiver) = ark_address_hint_setup(&ctx, false).await;
	let second_payer = ctx.bark_sdk("second_payer", &srv).boarded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = receiver.bolt11_invoice(sat(100_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;

	let (plain, _) = arkoor_to_invoice_address(&payer, &invoice).await;
	rpc.request_arkoor_cosign(protos::ArkoorPackageCosignRequest::from(plain.cosign_request())).await.unwrap();
	let error = rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &plain)).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Created);

	let (new, _) = arkoor_to_invoice_address(&second_payer, &invoice).await;
	rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &new)).await.unwrap();
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Settled);
	let settled = receive_rows(&db, hash).await;

	rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &new)).await
		.expect("a retry of the arkoor that settled the receive is co-signed");
	assert_eq!(receive_rows(&db, hash).await, settled);

	let error = rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &plain)).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(receive_rows(&db, hash).await, settled);
}

/// The state of the hold invoice of `hash`.
async fn hold_invoice_state(
	hold_client: &mut hold::hold_client::HoldClient<tonic::transport::Channel>,
	hash: PaymentHash,
) -> hold::InvoiceState {
	let invoices = hold_client.list(hold::ListRequest {
		constraint: Some(hold::list_request::Constraint::PaymentHash(hash.as_ref().to_vec())),
	}).await.unwrap().into_inner().invoices;
	invoices.first().expect("hold invoice exists").state()
}

/// An arkoor that the server co-signed as a plain arkoor to the Ark address
/// of an invoice cannot cancel a Lightning payment of that invoice: the
/// server refuses it while it holds the payment, and after the receiver
/// claimed it.
#[tokio::test]
async fn ark_address_arkoor_cannot_cancel_a_lightning_payment() {
	let ctx = TestContext::new("bark_sdk/ark_address_arkoor_cannot_cancel_a_lightning_payment").await;
	let (lightning, srv, payer, _) = ark_address_hint_setup(&ctx, false).await;
	let receiver = manual_hint_receiver(&ctx, &srv).await;
	let invoice = receiver.bolt11_invoice(sat(100_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let (arkoor, _) = arkoor_to_invoice_address(&payer, &invoice).await;
	let mut rpc = srv.get_public_rpc().await;
	rpc.request_arkoor_cosign(protos::ArkoorPackageCosignRequest::from(arkoor.cosign_request())).await.unwrap();

	let mut hold_client = lightning.internal.hold_client().await;
	let (paid, ()) = tokio::join!(
		lightning.external.try_pay_bolt11(invoice.to_string()),
		async {
			async {
				while server_receive_status(&srv, hash).await != protos::LightningReceiveStatus::Accepted {
					tokio::time::sleep(poll_interval()).await;
				}
			}.wait_millis(30_000).await;
			let error = rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &arkoor)).await
				.unwrap_err();
			assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
			assert_eq!(hold_invoice_state(&mut hold_client, hash).await, hold::InvoiceState::Accepted);
			assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Accepted);
			assert!(matches!(receiver.try_claim_lightning_receive(hash, true).await.unwrap(),
				LightningReceiveState::Settled(_)));
		},
	);
	paid.expect("the Lightning payment succeeds");

	let error = rpc.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &arkoor)).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Settled);
}

/// The receiver credits VTXOs on the Ark address of a settled invoice as
/// the Lightning receive only when they pay the invoice amount. The payer
/// settles the invoice with an arkoor that it holds back and sends a small
/// arkoor to the same address. The receiver credits that one as an
/// ordinary arkoor and keeps the receive pending. Once the payer registers
/// and delivers the arkoor that settled the invoice, the receiver credits
/// it as the receive.
#[tokio::test]
async fn ark_address_receive_is_credited_only_for_its_amount() {
	let ctx = TestContext::new("bark_sdk/ark_address_receive_is_credited_only_for_its_amount").await;
	let (_lightning, srv, payer, _) = ark_address_hint_setup(&ctx, false).await;
	let receiver = manual_hint_receiver(&ctx, &srv).await;
	let small_payer = ctx.bark_sdk("small_payer", &srv).boarded(sat(100_000)).create().await;
	let amount = sat(100_000);
	let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let address = invoice.ark_address().unwrap();
	let (arkoor, key) = arkoor_to_invoice_address(&payer, &invoice).await;
	let response = srv.get_public_rpc().await
		.request_lightning_receive_arkoor_cosign(invoice_arkoor(hash, &arkoor)).await.unwrap().into_inner();
	assert_eq!(server_receive_status(&srv, hash).await, protos::LightningReceiveStatus::Settled);

	small_payer.send_arkoor_payment(&address, sat(1_000)).await.unwrap();
	receiver.sync().await;
	assert!(matches!(receiver.lightning_receive_state(hash).await.unwrap(), LightningReceiveState::InProgress(_)),
		"a small arkoor on the address of a settled invoice does not pay it");
	assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, sat(1_000));
	let history = receiver.history().await.unwrap();
	assert_eq!(history.len(), 1);
	assert!(history[0].subsystem.is_subsystem(Subsystem::ARKOOR));

	let vtxos = arkoor.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap()).unwrap()
		.build_signed_vtxos();
	payer.register_vtxo_transactions_with_server(&vtxos).await.unwrap();
	let Some(VtxoDelivery::ServerMailbox { blinded_id }) = address.delivery().first() else {
		panic!("the Ark address of the invoice has no mailbox");
	};
	srv.get_mailbox_public_rpc().await.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
		blinded_id: blinded_id.as_ref().to_vec(),
		vtxos: vtxos.iter().filter(|v| v.policy() == address.policy()).map(|v| v.serialize()).collect(),
	}).await.unwrap();
	receiver.sync().await;
	match receiver.lightning_receive_state(hash).await.unwrap() {
		LightningReceiveState::Settled(settled) => assert_eq!(settled.amount, amount),
		other => panic!("receive not settled: {:?}", other),
	}
	assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, amount + sat(1_000));
}

/// Holds the reply to the first receive claim forever, after the server
/// handled the claim.
#[derive(Clone)]
struct LoseClaimReply {
	hold: Arc<AtomicBool>,
	arrived: Arc<tokio::sync::Notify>,
	requests: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for LoseClaimReply {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, request: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		self.requests.fetch_add(1, Ordering::SeqCst);
		let response = upstream.claim_lightning_receive(request).await?.into_inner();
		if self.hold.swap(false, Ordering::SeqCst) {
			self.arrived.notify_one();
			std::future::pending::<()>().await;
		}
		Ok(response)
	}
}

/// With a payout server the wallet stores that it revealed the preimage of
/// a receive before it sends the claim. When the reply is lost and the
/// wallet stops, it claims again after it opens, and credits the receive
/// once.
#[tokio::test]
async fn receive_claim_survives_a_lost_reply() {
	let ctx = TestContext::new("bark_sdk/receive_claim_survives_a_lost_reply").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = LoseClaimReply {
		hold: Arc::new(AtomicBool::new(true)),
		arrived: Arc::new(tokio::sync::Notify::new()),
		requests: Arc::new(AtomicUsize::new(0)),
	};
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("receiver", &proxy).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	lightning.sync().await;
	let amount = btc(0.5);
	let invoice = wallet.bolt11_invoice(amount, None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let mut mailbox = wallet.subscribe_mailbox_messages(None).await.unwrap();
	let (paid, checkpoint) = tokio::join!(lightning.external.try_pay_bolt11(invoice.to_string()), async {
		loop {
			let message = mailbox.next().wait_millis(10_000).await.unwrap().unwrap();
			if let Some(MailboxMsg::IncomingLightningPayment(message)) = message.message {
				assert_eq!(message.payment_hash, hash.to_vec());
				break;
			}
		}
		let mut claim = Box::pin(wallet.try_claim_lightning_receive(hash, false));
		tokio::select! {
			result = &mut claim => panic!("the claim finished without its reply: {result:?}"),
			_ = gate.arrived.notified().wait_millis(30_000) => {},
		}
		let checkpoint = wallet.lightning_receive_checkpoint(hash).await.unwrap().unwrap();
		assert!(futures::poll!(&mut claim).is_pending());
		drop(claim);
		checkpoint
	});
	paid.unwrap();
	assert!(matches!(&checkpoint.progress, bark::actions::lightning::receive::Progress::PreimageRevealed(_)),
		"the revealed preimage is stored before the claim");
	drop(mailbox);
	wallet.stop_daemon_wait().await.unwrap();
	drop(wallet);

	let reopened = ctx.bark_sdk("receiver", &proxy).mnemonic(mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	assert!(reopened.lightning_receive_checkpoint(hash).await.unwrap() == Some(checkpoint));
	assert!(matches!(reopened.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
	assert!(gate.requests.load(Ordering::SeqCst) >= 2, "the wallet claims again");
	assert!(reopened.lightning_receive_checkpoint(hash).await.unwrap().is_none());
	let balance = assert_balance_consistent(&reopened, false).await;
	assert_eq!(balance.spendable, amount);
	let receives = reopened.history().await.unwrap().into_iter()
		.filter(|movement| movement.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE)).collect::<Vec<_>>();
	assert_eq!(receives.len(), 1, "the receive is credited once");
	assert_eq!((receives[0].status, receives[0].effective_balance),
		(MovementStatus::Successful, amount.to_signed().unwrap()));
}
