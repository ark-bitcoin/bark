//! Lightning receive cut off mid-flight across an upgrade.

use server_rpc::protos;

use ark_testing::{btc, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::upgrade_from_exec;

use crate::common::{
	assert_parked_at, assert_upgrade_spans_builds, assert_action_completed, cut_off_timeout,
	maintain_until, Gate,
};

/// Parks the receive at `PreimageRevealed`: the preimage is out, so the payer
/// can settle, but the claim was never finished.
#[derive(Clone)]
struct GatedClaimLightningReceive(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedClaimLightningReceive {
	async fn claim_lightning_receive(
		&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped claim_lightning_receive"));
		}
		Ok(upstream.claim_lightning_receive(req).await?.into_inner())
	}
}

/// Past the point of no return: the preimage is out under the old release, so
/// the payer can settle, and the new one has to finish the claim.
#[tokio::test]
async fn lightning_receive_parked_at_preimage_revealed_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/ln_receive_parked_at_preimage_revealed").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedClaimLightningReceive(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;
	let receive_amount = btc(1);
	let invoice = old.bolt11_invoice(receive_amount).await.invoice;

	// The payment only settles once the receiver claims, so paying and claiming
	// run together. Gating the claim parks the receive at `PreimageRevealed`:
	// past the point of no return, HTLC settleable, VTXOs not yet in the wallet.
	// The payer is bounded too, or it would retry past the test's budget.
	old.set_timeout(cut_off_timeout());
	let (_paid, _claimed) = tokio::join!(
		tokio::time::timeout(cut_off_timeout(), lightning.external.try_pay_bolt11(&invoice)),
		old.try_lightning_receive(&invoice),
	);
	old.unset_timeout();

	assert_eq!(
		old.spendable_balance().await, board_amount,
		"the receive should not have been claimed before the upgrade",
	);

	assert_parked_at(&old, "ln_recv.PreimageRevealed").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "lightning receive", || async {
		new.spendable_balance().await == board_amount + receive_amount
	}).await;

	assert_action_completed(&new).await;
}

/// Invoice minted under the old release, paid and claimed under the new one.
#[tokio::test]
async fn lightning_receive_parked_at_awaiting_payment_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/ln_receive_parked_at_awaiting_payment").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let board_amount = btc(2);
	let old = ctx.bark("bark", &srv)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;
	let receive_amount = btc(1);
	let invoice = old.bolt11_invoice(receive_amount).await.invoice;

	let receives = old.list_lightning_receives().await;
	assert_eq!(receives.len(), 1, "the old release should have checkpointed a receive");
	assert_eq!(
		receives[0].state, "awaiting-payment",
		"the receive should be waiting for payment, not further along",
	);

	assert_parked_at(&old, "ln_recv.AwaitingPayment").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	// The invoice was minted by the old release; the new one has to honour it.
	let (_paid, _claimed) = tokio::join!(
		lightning.external.try_pay_bolt11(&invoice),
		new.try_lightning_receive(&invoice),
	);

	assert_eq!(
		new.spendable_balance().await, board_amount + receive_amount,
		"the upgraded build should have claimed the receive the old one opened",
	);
	assert_action_completed(&new).await;
}
