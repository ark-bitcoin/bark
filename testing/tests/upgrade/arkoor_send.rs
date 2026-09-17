//! Arkoor send cut off mid-flight across an upgrade.

use bitcoin::Amount;

use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use ark_testing::util::upgrade_from_exec;

use crate::common::{
	assert_parked_at, assert_upgrade_spans_builds, assert_action_completed, cut_off_timeout,
	maintain_until, Gate,
};

/// Forwards every Ark RPC untouched, so a test can proxy only the mailbox.
#[derive(Clone)]
struct PassThroughArk;

impl captaind::proxy::ArkRpcProxy for PassThroughArk {}

/// Parks the send at `Cosigning`: inputs locked, nothing signed.
#[derive(Clone)]
struct GatedArkoorCosign(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedArkoorCosign {
	async fn request_arkoor_cosign(
		&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest,
	) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped request_arkoor_cosign"));
		}
		Ok(upstream.request_arkoor_cosign(req).await?.into_inner())
	}
}

/// Parks the send at `Delivery`: the sender's inputs are spent and registered,
/// but the receiver has nothing.
#[derive(Clone)]
struct GatedPostArkoorMessage(Gate);

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for GatedPostArkoorMessage {
	async fn post_arkoor_message(
		&self, upstream: &mut MailboxClient,
		req: protos::mailbox_server::PostArkoorMessageRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped post_arkoor_message"));
		}
		Ok(upstream.post_arkoor_message(req).await?.into_inner())
	}
}

/// Cosigned and registered under the old release, delivered under the new one.
#[tokio::test]
async fn arkoor_send_parked_at_delivery_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/arkoor_send_parked_at_delivery").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_with_mailbox(
		PassThroughArk, GatedPostArkoorMessage(gate.clone()),
	).await;

	let board_amount = btc(2);
	let send_amount = sat(100_000);

	let mut old = ctx.bark("sender", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	// The receiver holds nothing offchain, so its spendable balance goes
	// straight from zero to the delivered arkoor.
	let receiver = ctx.bark("receiver", &proxy).create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	// Cut the old release off at `Delivery`: cosigned and registered, but the
	// receiver has nothing.
	let address = receiver.address().await;
	old.set_timeout(cut_off_timeout());
	let _ = old.try_send_oor(&address, send_amount, false).await;
	old.unset_timeout();

	receiver.sync().await;
	assert_eq!(
		receiver.spendable_balance().await, Amount::ZERO,
		"the arkoor should not have been delivered before the upgrade",
	);

	assert_parked_at(&old, "arkoor.Delivery").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "arkoor delivery", || async {
		receiver.sync().await;
		receiver.spendable_balance().await == send_amount
	}).await;

	assert_action_completed(&new).await;
}

/// Nothing cosigned under the old release.
#[tokio::test]
async fn arkoor_send_parked_at_cosigning_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/arkoor_send_parked_at_cosigning").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedArkoorCosign(gate.clone())).await;

	let board_amount = btc(2);
	let send_amount = sat(100_000);

	let mut old = ctx.bark("sender", &proxy)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;
	let receiver = ctx.bark("receiver", &proxy).create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	let address = receiver.address().await;
	old.set_timeout(cut_off_timeout());
	let _ = old.try_send_oor(&address, send_amount, false).await;
	old.unset_timeout();

	receiver.sync().await;
	assert_eq!(
		receiver.spendable_balance().await, Amount::ZERO,
		"nothing should have been cosigned before the upgrade",
	);

	assert_parked_at(&old, "arkoor.Cosigning").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "arkoor delivery", || async {
		receiver.sync().await;
		receiver.spendable_balance().await == send_amount
	}).await;

	assert_action_completed(&new).await;
}
