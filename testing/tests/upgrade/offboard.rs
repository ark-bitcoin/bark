//! Offboard cut off mid-flight across an upgrade.

use bitcoin::Amount;
use bitcoin_ext::BlockDelta;

use bark_json::primitives::VtxoStateInfo;
use server_rpc::protos;

use ark_testing::{btc, Bark, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::upgrade_from_exec;

use crate::common::{
	assert_parked_at, assert_upgrade_spans_builds, assert_action_completed, cut_off_timeout,
	maintain_until, Gate,
};

/// Parks the offboard at `OffboardTxPrepared`: vtxos committed and the tx
/// built, but nothing signed or broadcast.
#[derive(Clone)]
struct GatedFinishOffboard(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedFinishOffboard {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped finish_offboard"));
		}
		Ok(upstream.finish_offboard(req).await?.into_inner())
	}
}

/// Parks the offboard at `ReadyForOffboard`: vtxos locked, no tx built.
#[derive(Clone)]
struct GatedPrepareOffboard(Gate);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for GatedPrepareOffboard {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		if self.0.is_closed() {
			return Err(tonic::Status::internal("proxy: dropped prepare_offboard"));
		}
		Ok(upstream.prepare_offboard(req).await?.into_inner())
	}
}

/// Whether an offboard finished: bitcoin on-chain *and* VTXO locks released.
/// Generates a block each call, so a multi-confirmation offboard can settle.
async fn offboard_settled(
	ctx: &TestContext, bark: &Bark, address: &bitcoin::Address,
) -> bool {
	ctx.generate_blocks(1).await;
	if ctx.bitcoind().get_received_by_address(address) == Amount::ZERO {
		return false;
	}
	!bark.vtxos().await.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. }))
}

/// Tx built under the old release, signed and broadcast under the new one.
#[tokio::test]
async fn offboard_parked_at_tx_prepared_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/offboard_parked_at_tx_prepared").await;

	// Offboards are funded from the rounds wallet, which trusts its own
	// unconfirmed change, so a pool issuance tx can become a flaky ancestor.
	// With the pool off there is nothing to wait for.
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedFinishOffboard(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.cfg(|c| c.offboard_required_confirmations = BlockDelta::new(1))
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	let address = ctx.bitcoind().get_new_address();

	// Cut the old release off with the offboard tx built but unsigned.
	old.set_timeout(cut_off_timeout());
	let _ = old.try_offboard_all(&address).await;
	old.unset_timeout();

	assert_eq!(
		ctx.bitcoind().get_received_by_address(&address), Amount::ZERO,
		"the offboard should not have been broadcast before the upgrade",
	);

	assert_parked_at(&old, "offboard.OffboardTxPrepared").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "offboard", || async {
		offboard_settled(&ctx, &new, &address).await
	}).await;

	assert_action_completed(&new).await;
}

/// Vtxos locked under the old release, no tx built.
#[tokio::test]
async fn offboard_parked_at_ready_for_offboard_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/offboard_parked_at_ready_for_offboard").await;

	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let gate = Gate::closed();
	let proxy = srv.start_proxy_no_mailbox(GatedPrepareOffboard(gate.clone())).await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &proxy)
		.exec(upgrade_from_exec())
		.cfg(|c| c.offboard_required_confirmations = BlockDelta::new(1))
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	let address = ctx.bitcoind().get_new_address();
	old.set_timeout(cut_off_timeout());
	let _ = old.try_offboard_all(&address).await;
	old.unset_timeout();

	assert_eq!(
		ctx.bitcoind().get_received_by_address(&address), Amount::ZERO,
		"nothing should have been offboarded before the upgrade",
	);

	assert_parked_at(&old, "offboard.ReadyForOffboard").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	gate.open();
	maintain_until(&new, "offboard", || async {
		offboard_settled(&ctx, &new, &address).await
	}).await;

	assert_action_completed(&new).await;
}

/// Broadcast but unconfirmed. No proxy needed: withholding blocks strands it.
#[tokio::test]
async fn offboard_parked_at_awaiting_confirmations_completes_after_upgrade() {
	let ctx = TestContext::new("upgrade/offboard_parked_at_awaiting_confirmations").await;

	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;

	let board_amount = btc(2);
	let mut old = ctx.bark("bark", &srv)
		.exec(upgrade_from_exec())
		.cfg(|c| c.offboard_required_confirmations = BlockDelta::new(2))
		.funded(btc(3))
		.create().await;
	old.board_and_confirm_and_register(&ctx, board_amount).await;

	let address = ctx.bitcoind().get_new_address();
	old.set_timeout(cut_off_timeout());
	let _ = old.try_offboard_all(&address).await;
	old.unset_timeout();

	assert_parked_at(&old, "offboard.AwaitingConfirmations").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	// Only now let it confirm, so the upgraded build is the one that settles it.
	maintain_until(&new, "offboard", || async {
		offboard_settled(&ctx, &new, &address).await
	}).await;

	assert_action_completed(&new).await;
}
