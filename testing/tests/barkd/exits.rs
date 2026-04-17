
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

use super::helpers::{
	wait_for_boards_synced, wait_for_exits_claimable,
	wait_for_onchain_balance, wait_for_rounds_complete,
};

/// Verify `POST /exits/start/all` registers all VTXOs for exit and
/// the daemon auto-progresses them to claimable.
#[tokio::test]
async fn exit_start_all_and_progress_barkd() {
	let ctx = TestContext::new("barkd/exit_start_all_and_progress_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	// Fund, board, confirm, then refresh into a round so the VTXO is fully in-round.
	ctx.fund_barkd(&barkd, sat(500_000)).await;
	wait_for_onchain_balance(&barkd, sat(500_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let balance_before = barkd.bark_balance().await;
	assert!(balance_before.spendable > sat(0));

	// Stop the server so we need an emergency exit.
	srv.stop().await.unwrap();

	// Start exit for all VTXOs.
	barkd.exit_start_all().await;

	// Status should show at least one exit entry.
	let statuses = barkd.get_all_exit_status(None, None).await;
	assert!(!statuses.is_empty(), "should have at least one exit in progress");

	// Fund the on-chain wallet for CPFP fees, then let the daemon drive to completion.
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;
}

/// Verify `POST /exits/claim/all` sweeps claimable exits to an on-chain address.
#[tokio::test]
async fn exit_claim_all_barkd() {
	let ctx = TestContext::new("barkd/exit_claim_all_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(500_000)).await;
	wait_for_onchain_balance(&barkd, sat(500_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	srv.stop().await.unwrap();

	barkd.exit_start_all().await;
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;

	// Claim all exits to a fresh on-chain address.
	let addr = barkd.onchain_address().await;
	barkd.exit_claim_all(&addr.to_string()).await;
	ctx.generate_blocks(1).await;

	let onchain = barkd.onchain_balance().await;
	// On-chain balance includes CPFP funding (100k) plus claimed exit funds.
	// The original board was ~500k, so the total should exceed the CPFP funding alone.
	assert!(
		onchain > sat(100_000),
		"on-chain balance {} should exceed CPFP funding, confirming exit funds were claimed",
		onchain,
	);
}

/// Verify `POST /exits/start/vtxos` exits only the specified VTXO.
#[tokio::test]
async fn exit_start_vtxos_barkd() {
	let ctx = TestContext::new("barkd/exit_start_vtxos_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	// Create two VTXOs.
	ctx.fund_barkd(&barkd, sat(300_000)).await;
	wait_for_onchain_balance(&barkd, sat(300_000)).await;
	barkd.board_amount(sat(100_000)).await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "should have exactly two board VTXOs");

	let target_id = vtxos[0].id.to_string();
	let other_id = vtxos[1].id.to_string();

	srv.stop().await.unwrap();

	// Exit only one VTXO.
	barkd.exit_start_vtxos(vec![target_id.clone()]).await;

	let statuses = barkd.get_all_exit_status(None, None).await;
	assert_eq!(statuses.len(), 1, "only one VTXO should be exiting");
	assert_eq!(statuses[0].vtxo_id.to_string(), target_id);
	assert_ne!(statuses[0].vtxo_id.to_string(), other_id, "the other VTXO should not be exiting");
}

/// Verify `POST /exits/claim/vtxos` claims only the specified exit.
#[tokio::test]
async fn exit_claim_vtxos_barkd() {
	let ctx = TestContext::new("barkd/exit_claim_vtxos_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(300_000)).await;
	wait_for_onchain_balance(&barkd, sat(300_000)).await;
	barkd.board_amount(sat(100_000)).await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "should have exactly two board VTXOs");

	let target_id = vtxos[0].id.to_string();
	let other_id = vtxos[1].id.to_string();

	srv.stop().await.unwrap();

	// Exit only the target VTXO, then let the daemon drive to completion.
	barkd.exit_start_vtxos(vec![target_id.clone()]).await;

	let exit_statuses = barkd.get_all_exit_status(None, None).await;
	assert_eq!(exit_statuses.len(), 1, "only the target VTXO should be exiting");
	assert_eq!(exit_statuses[0].vtxo_id.to_string(), target_id);

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;

	// Claim only the target VTXO.
	let addr = barkd.onchain_address().await;
	barkd.exit_claim_vtxos(&addr.to_string(), vec![target_id]).await;
	ctx.generate_blocks(1).await;

	let onchain = barkd.onchain_balance().await;
	assert!(onchain > sat(0), "should have received claimed exit funds on-chain");

	// The other VTXO should remain in the wallet, unclaimed.
	let remaining = barkd.vtxos(None).await;
	assert_eq!(remaining.len(), 1, "the other VTXO should still be in the wallet");
	assert_eq!(remaining[0].id.to_string(), other_id, "the remaining VTXO should be the one we did not exit");
}

/// Verify that the daemon's background `run_exits` auto-progresses exits
/// even when disconnected from the Ark server.
#[tokio::test]
async fn exit_auto_progress_disconnected_barkd() {
	let ctx = TestContext::new("barkd/exit_auto_progress_disconnected_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	// Setup: fund, board, confirm, refresh into round.
	ctx.fund_barkd(&barkd, sat(500_000)).await;
	wait_for_onchain_balance(&barkd, sat(500_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	// Stop server — barkd becomes disconnected.
	srv.stop().await.unwrap();

	// Start exit + fund on-chain wallet for CPFP fees.
	barkd.exit_start_all().await;
	ctx.fund_barkd(&barkd, sat(100_000)).await;

	// Let the daemon auto-progress. No exit_progress() call — the daemon does it.
	wait_for_exits_claimable(&ctx, &barkd).await;
}
