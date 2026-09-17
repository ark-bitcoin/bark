//! Lightning send cut off mid-flight across an upgrade.

use bitcoin::Amount;

use server_rpc::protos;

use ark_testing::{btc, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::upgrade_from_exec;

use crate::common::{
	assert_parked_at, cut_off_timeout, maintain_until, assert_upgrade_spans_builds, assert_action_completed, Gate,
};

/// Parks the send at `HtlcReceived`: inputs committed and HTLCs cosigned, but
/// the server never told to pay.
#[derive(Clone)]
struct GatedInitiatePayment(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedInitiatePayment {
	async fn initiate_lightning_payment(
		&self, upstream: &mut ArkClient, req: protos::InitiateLightningPaymentRequest,
	) -> Result<protos::Empty, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped initiate_lightning_payment"));
		}
		Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
	}
}

/// Parks the send at `PaymentInitiated`: the payment is in flight and its
/// outcome unknown to the wallet.
#[derive(Clone)]
struct GatedCheckPayment(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedCheckPayment {
	async fn check_lightning_payment(
		&self, upstream: &mut ArkClient, req: protos::CheckLightningPaymentRequest,
	) -> Result<protos::LightningPaymentStatus, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped check_lightning_payment"));
		}
		Ok(upstream.check_lightning_payment(req).await?.into_inner())
	}
}

/// Parks the send at `Start`: inputs locked, nothing cosigned.
#[derive(Clone)]
struct GatedHtlcCosign(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedHtlcCosign {
	async fn request_lightning_pay_htlc_cosign(
		&self, upstream: &mut ArkClient, req: protos::LightningPayHtlcCosignRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped request_lightning_pay_htlc_cosign"));
		}
		Ok(upstream.request_lightning_pay_htlc_cosign(req).await?.into_inner())
	}
}

/// HTLCs cosigned under the old release, payment initiated under the new one.
#[tokio::test]
async fn lightning_send_parked_at_htlc_received_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/ln_send_parked_at_htlc_received").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedInitiatePayment(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;
	let invoice_amount = btc(0.5);
	let invoice = lightning.external
		.invoice(Some(invoice_amount), "upgrade_htlc_received", "upgrade test")
		.await;

	// Cut the old release off with the HTLCs cosigned, leaving the checkpoint
	// for the new binary.
	old.set_timeout(cut_off_timeout());
	let _ = old.try_pay_lightning(invoice.clone(), None, false).await;
	old.unset_timeout();

	let parked = old.offchain_balance().await;
	assert_ne!(
		parked.pending_lightning_send, Amount::ZERO,
		"expected the old release to leave a pending lightning send, got {:?}", parked,
	);

	assert_parked_at(&old, "ln_send.HtlcReceived").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "lightning send", || async {
		new.offchain_balance().await.pending_lightning_send == Amount::ZERO
	}).await;

	assert_eq!(
		new.spendable_balance().await, board_amount - invoice_amount,
		"the upgraded build should have completed the payment the old one started",
	);
	assert_action_completed(&new).await;
}

/// Payment initiated under the old release, its outcome learned under the new one.
#[tokio::test]
async fn lightning_send_parked_at_payment_initiated_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/ln_send_parked_at_payment_initiated").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedCheckPayment(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;
	let invoice_amount = btc(0.5);
	let invoice = lightning.external
		.invoice(Some(invoice_amount), "upgrade_payment_initiated", "upgrade test")
		.await;

	old.set_timeout(cut_off_timeout());
	let _ = old.try_pay_lightning(invoice.clone(), None, false).await;
	old.unset_timeout();

	let parked = old.offchain_balance().await;
	assert_ne!(
		parked.pending_lightning_send, Amount::ZERO,
		"expected the old release to leave a pending lightning send, got {:?}", parked,
	);

	assert_parked_at(&old, "ln_send.PaymentInitiated").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "lightning send", || async {
		new.offchain_balance().await.pending_lightning_send == Amount::ZERO
	}).await;

	assert_eq!(
		new.spendable_balance().await, board_amount - invoice_amount,
		"the upgraded build should have settled the payment the old one initiated",
	);
	assert_action_completed(&new).await;
}

/// Nothing committed beyond the input locks, and the upgraded build still
/// carries the send through.
#[tokio::test]
async fn lightning_send_parked_at_start_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/ln_send_parked_at_start").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedHtlcCosign(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;
	let invoice_amount = btc(0.5);
	let invoice = lightning.external
		.invoice(Some(invoice_amount), "upgrade_ln_send_start", "upgrade test")
		.await;

	old.set_timeout(cut_off_timeout());
	let _ = old.try_pay_lightning(invoice.clone(), None, false).await;
	old.unset_timeout();

	assert_parked_at(&old, "ln_send.Start").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "lightning send", || async {
		new.offchain_balance().await.pending_lightning_send == Amount::ZERO
	}).await;

	assert_eq!(
		new.spendable_balance().await, board_amount - invoice_amount,
		"the upgraded build should have completed the payment the old one started",
	);
	assert_action_completed(&new).await;
}
