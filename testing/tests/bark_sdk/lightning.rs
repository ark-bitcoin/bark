use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures::StreamExt;

use bitcoin::Amount;

use ark::fees::{IntraArkFees, LightningReceiveFees, LightningSendFees, PpmFeeRate};
use ark::lightning::{Bolt11Invoice, Invoice, PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;
use ark_testing::{TestContext, btc, sat, util::{FutureExt, poll_interval}};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::daemon::captaind::{self, ArkClient};

use bark::actions::lightning::pay::LightningSendState;
use bark::actions::lightning::receive::LightningReceiveState;
use bark::movement::MovementStatus;
use bark::subsystem::Subsystem;
use bark::LightningSendOptions;
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

/// Claims a receive and waits until it is settled. The wallet's own sync
/// can be claiming it already, in which case the claim call returns early.
async fn claim_until_settled(wallet: &bark::Wallet, hash: PaymentHash) {
	let _ = wallet.try_claim_lightning_receive(hash, true).await;
	async {
		loop {
			if let LightningReceiveState::Settled(_) = wallet.lightning_receive_state(hash).await.unwrap() {
				return;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
}

fn flat_send_fees(base: Amount) -> LightningSendFees {
	LightningSendFees { min_fee: Amount::ZERO, base_fee: base, ppm_expiry_table: vec![] }
}

fn flat_receive_fees(base: Amount) -> LightningReceiveFees {
	LightningReceiveFees { base_fee: base, ppm: PpmFeeRate::ZERO }
}

#[derive(Clone, Default)]
struct FailFirstReceiveLookup(Arc<AtomicBool>);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for FailFirstReceiveLookup {
	async fn check_lightning_receive(
		&self, upstream: &mut ArkClient, req: protos::CheckLightningReceiveRequest,
	) -> Result<protos::CheckLightningReceiveResponse, tonic::Status> {
		if !self.0.swap(true, Ordering::Relaxed) {
			return Err(tonic::Status::unavailable("receive lookup unavailable"));
		}
		Ok(upstream.check_lightning_receive(req).await?.into_inner())
	}
}

/// A Lightning payment between two wallets of the same server pays the
/// intra-Ark fees on both sides. Payments to and from the outside still pay
/// the normal Lightning fees.
#[tokio::test]
async fn intra_ark_payment_pays_intra_ark_fees() {
	let ctx = TestContext::new("bark_sdk/intra_ark_payment_pays_intra_ark_fees").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.fees.lightning_send = flat_send_fees(sat(75));
			cfg.fees.lightning_receive = flat_receive_fees(sat(100));
			cfg.fees.intra_ark = Some(IntraArkFees {
				lightning_send: flat_send_fees(sat(10)),
				lightning_receive: flat_receive_fees(sat(7)),
			});
		})
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let board = sat(400_000);
	let proxy = srv.start_proxy_no_mailbox(FailFirstReceiveLookup::default()).await;
	let payer = ctx.bark_sdk("payer", &proxy).boarded(board).create().await;
	let receiver = ctx.bark_sdk("receiver", &srv).create().await;
	lightning.sync().await;

	let postgres = srv.config().postgres.clone();
	// Let the runtime poll the wallets independently of the daemon setup future.
	tokio::spawn(async move {
		// The two wallets pay the configured send and receive fees.
		let amount = sat(50_000);
		let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
		let hash = PaymentHash::from(&invoice);
		let err = payer.pay_lightning_invoice(invoice.clone(), None, false).await.unwrap_err();
		assert!(format!("{err:#}").contains("could not determine the Lightning send fee"), "{err:#}");

		let estimate = payer.estimate_invoice_payment_fee(&Invoice::Bolt11(invoice.clone()), amount).await.unwrap();
		assert_eq!(estimate.fee, sat(10));
		payer.pay_lightning_invoice(invoice, None, false).await.unwrap();
		claim_until_settled(&receiver, hash).await;
		let sent = payer.check_lightning_payment(hash, true).await.unwrap();
		let LightningSendState::Paid(proof) = sent else { panic!("payment did not settle: {sent:?}") };
		assert_eq!(PaymentHash::from(proof.preimage), hash);
		let db = Db::connect(&postgres).await.unwrap();
		let attempt = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
		assert!(attempt.lightning_htlc_subscription_id.is_some());
		assert_eq!(attempt.final_amount_msat, None, "no payment was sent over a Lightning channel");
		assert_eq!(assert_balance_consistent(&payer, false).await.spendable, board - amount - sat(10));
		assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, amount - sat(7));

		// To the outside: the normal send fee.
		let out_amount = sat(30_000);
		let outgoing = lightning.external.invoice(Some(out_amount), "intra-ark-fees-out", "out").await;
		let outgoing = Invoice::Bolt11(outgoing.parse::<Bolt11Invoice>().unwrap());
		let estimate = payer.estimate_invoice_payment_fee(&outgoing, out_amount).await.unwrap();
		assert_eq!(estimate.fee, sat(75));
		payer.pay_lightning_invoice(outgoing, None, true).await.unwrap();
		assert_eq!(assert_balance_consistent(&payer, false).await.spendable,
			board - amount - sat(10) - out_amount - sat(75));

		// From the outside: the normal receive fee.
		let in_amount = sat(20_000);
		let incoming = receiver.bolt11_invoice(in_amount, None, None).await.unwrap();
		let hash = PaymentHash::from(&incoming);
		let (paid, ()) = tokio::join!(
			lightning.external.try_pay_bolt11(incoming.to_string()),
			claim_until_settled(&receiver, hash),
		);
		paid.expect("external payment failed");
		assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, amount - sat(7) + in_amount - sat(100));
	}).await.unwrap();
}

/// Without intra-Ark fees, an intra-Ark payment pays the normal fees, and
/// the wallet does not ask the server about the invoice.
#[tokio::test]
async fn intra_ark_payment_without_intra_ark_fees() {
	let ctx = TestContext::new("bark_sdk/intra_ark_payment_without_intra_ark_fees").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| {
			cfg.fees.lightning_send = flat_send_fees(sat(75));
			cfg.fees.lightning_receive = flat_receive_fees(sat(100));
		})
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let board = sat(400_000);
	let proxy = srv.start_proxy_no_mailbox(FailFirstReceiveLookup::default()).await;
	let payer = ctx.bark_sdk("payer", &proxy).boarded(board).create().await;
	let receiver = ctx.bark_sdk("receiver", &srv).create().await;

	let amount = sat(50_000);
	let invoice = receiver.bolt11_invoice(amount, None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let estimate = payer.estimate_invoice_payment_fee(&Invoice::Bolt11(invoice.clone()), amount).await.unwrap();
	assert_eq!(estimate.fee, sat(75));
	payer.pay_lightning_invoice(invoice, None, false).await.unwrap();
	claim_until_settled(&receiver, hash).await;
	payer.check_lightning_payment(hash, true).await.unwrap();
	assert_eq!(assert_balance_consistent(&payer, false).await.spendable, board - amount - sat(75));
	assert_eq!(assert_balance_consistent(&receiver, false).await.spendable, amount - sat(100));
}
