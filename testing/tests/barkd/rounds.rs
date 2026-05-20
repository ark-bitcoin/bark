use std::time::Duration;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::FutureExt;
use server_log::RoundFinished;

use super::helpers::{wait_for_boards_synced, wait_for_onchain_balance, wait_for_rounds_complete};

/// Verify that the daemon's round-event loop automatically schedules a
/// maintenance refresh for VTXOs approaching expiry. Triggers a round on
/// the server and expects barkd to join it on its own (no REST refresh
/// call) and replace the expiring VTXO.
#[tokio::test]
async fn maintenance_refresh_auto_barkd() {
	let ctx = TestContext::new("barkd/maintenance_refresh_auto_barkd").await;

	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(100_000)).create().await;

	wait_for_onchain_balance(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let vtxos_before = barkd.vtxos(None).await;
	assert_eq!(vtxos_before.len(), 1, "should have one vtxo after boarding");
	let vtxo_id_before = vtxos_before[0].vtxo.id;

	// Push the vtxo within the refresh expiry threshold so the daemon
	// considers it due for maintenance.
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;

	// Subscribe before triggering so we can't miss the log.
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();

	// Trigger a round; the daemon should see the Attempt event and
	// auto-join to refresh the expiring vtxo.
	srv.trigger_round().await;

	let finished = log_round_finished.recv().wait(Duration::from_secs(60)).await.unwrap();
	assert!(
		finished.nb_input_vtxos >= 1,
		"round should include at least one input vtxo from the auto refresh",
	);

	wait_for_rounds_complete(&ctx, &barkd).await;

	let vtxos_after = barkd.vtxos(None).await;
	assert_eq!(vtxos_after.len(), 1, "should still have one vtxo after refresh");
	assert_ne!(
		vtxos_after[0].vtxo.id, vtxo_id_before,
		"vtxo id should change after maintenance refresh",
	);
}
