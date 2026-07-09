
use std::collections::HashSet;

use bitcoin::Txid;

use bark_json::exit::ExitState;
use bark_json::movements::MovementStatus;
use bark_json::primitives::VtxoStateInfo;

use ark_testing::{btc, require_bark_version, sat, TestContext};
use bark_rest_client::apis::exits_api;
use ark_testing::constants::BOARD_CONFIRMATIONS;

use super::helpers::{
	wait_for_boards_synced, wait_for_exits_claimable,
	wait_for_onchain_balance, wait_for_rounds_complete,
};

/// Verify `POST /exits/start/all` registers all VTXOs for exit and
/// the daemon auto-progresses them to claimable.
#[tokio::test]
async fn exit_start_all_and_progress_barkd() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/exit_start_all_and_progress_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	// Board into a VTXO, then refresh into a round so it's fully in-round.
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let balance_before = barkd.bark_balance().await;
	assert!(balance_before.spendable > sat(0));

	// Stop the server so we need an emergency exit.
	srv.stop().await.unwrap();

	// Start exit for all VTXOs.
	barkd.exit_start_all().await;

	// Status should show at least one exit entry.
	let statuses = barkd.get_live_exit_status(None, None).await;
	assert!(!statuses.is_empty(), "should have at least one exit in progress");

	// Fund the on-chain wallet for CPFP fees, then let the daemon drive to completion.
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;

	// The CPFP children recorded against each exit package are the ground truth.
	let statuses = barkd.get_live_exit_status(None, Some(true)).await;
	let expected_cpfp_txids: HashSet<Txid> = statuses.iter()
		.flat_map(|s| s.transactions.iter())
		.filter_map(|pkg| pkg.child.as_ref().map(|c| c.info.txid))
		.collect();
	assert!(
		!expected_cpfp_txids.is_empty(),
		"exit progression should have produced at least one CPFP child",
	);

	// Make sure the on-chain wallet has seen everything before we read its tx list.
	barkd.onchain_sync().await;
	let txs = barkd.onchain_transactions().await;
	let labeled_cpfp_txids: HashSet<Txid> = txs.iter()
		.filter(|t| t.is_cpfp)
		.map(|t| t.txid)
		.collect();
	assert_eq!(
		labeled_cpfp_txids, expected_cpfp_txids,
		"onchain_transactions `is_cpfp` set must match the exit-package child set",
	);
}

/// Verify `POST /exits/claim/all` sweeps claimable exits to an on-chain address.
#[tokio::test]
async fn exit_claim_all_barkd() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/exit_claim_all_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/exit_start_vtxos_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(300_000)).create().await;

	// Create two VTXOs.
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

	let statuses = barkd.get_live_exit_status(None, None).await;
	assert_eq!(statuses.len(), 1, "only one VTXO should be exiting");
	assert_eq!(statuses[0].vtxo_id.to_string(), target_id);
	assert_ne!(statuses[0].vtxo_id.to_string(), other_id, "the other VTXO should not be exiting");
}

/// Verify `POST /exits/claim/vtxos` claims only the specified exit.
#[tokio::test]
async fn exit_claim_vtxos_barkd() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/exit_claim_vtxos_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(300_000)).create().await;

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

	let exit_statuses = barkd.get_live_exit_status(None, None).await;
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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/exit_auto_progress_disconnected_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	// Setup: board and refresh into round.
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

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

#[tokio::test]
async fn cancel_pending_exit_keeps_vtxo_spendable_barkd() {
	require_bark_version!(> "0.3.0");

	let ctx = TestContext::new("barkd/cancel_pending_exit_keeps_vtxo_spendable_barkd").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Sender boards and arkoors to `bark`, giving it a VTXO with a multi-transaction exit chain.
	let sender = ctx.barkd("sender", &srv).boarded(sat(500_000)).create().await;
	// Subject is manual-sync (we control exit broadcasting) and funded for CPFP fees.
	let bark = ctx.barkd("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;

	sender.send(bark.ark_address().await, sat(300_000)).await;
	bark.sync().await;
	let vtxos = bark.vtxos(None).await;
	assert_eq!(vtxos.len(), 1, "bark should have received a single arkoor vtxo");
	let vtxo_id = vtxos[0].id.to_string();

	// Broadcast and confirm the first exit transaction, leaving the final (leaf) tx unbroadcast.
	bark.exit_start_all().await;
	bark.exit_progress().await;
	ctx.generate_blocks(1).await;
	bark.sync().await;

	let statuses = bark.get_live_exit_status(None, None).await;
	assert_eq!(statuses.len(), 1);
	assert!(matches!(statuses[0].state, ExitState::Processing(_)),
		"exit should be mid-chain (Processing), got {:?}", statuses[0].state);

	// Cancellation still succeeds despite the broadcast/confirmed ancestor.
	bark.cancel_exit(&vtxo_id).await;

	// Canceling is idempotent: a second cancel of the same exit is a no-op.
	bark.cancel_exit(&vtxo_id).await;

	// Dropped from the active status list, surfaced under /exits/status/finished in Canceled state.
	assert!(bark.get_live_exit_status(None, None).await.is_empty(),
		"canceled exit should not appear in the active exit status list");
	let finished = bark.get_finished_exits(None, None).await;
	assert_eq!(finished.len(), 1);
	assert_eq!(finished[0].vtxo_id.to_string(), vtxo_id);
	assert!(matches!(finished[0].state, ExitState::Canceled(_)),
		"canceled exit should be in Canceled state, got {:?}", finished[0].state);

	// The VTXO is untouched: still spendable, balance intact.
	let vtxos = bark.vtxos(None).await;
	assert_eq!(vtxos.len(), 1);
	assert_eq!(vtxos[0].id.to_string(), vtxo_id);
	assert!(matches!(vtxos[0].state, VtxoStateInfo::Spendable),
		"vtxo should still be Spendable, got {:?}", vtxos[0].state);
	assert_eq!(bark.bark_balance().await.spendable, sat(300_000));

	// The exit movement was canceled.
	let exit_movement = bark.history(None, None).await.into_iter()
		.find(|m| m.subsystem.name == "bark.exit")
		.expect("exit movement should exist");
	assert_eq!(exit_movement.status, MovementStatus::Canceled);
	assert!(exit_movement.time.completed_at.is_some());
}

/// Once the final exit transaction has been broadcast, cancellation is refused over REST. A board
/// has a single exit transaction, so one progress pass broadcasts it.
#[tokio::test]
async fn cannot_cancel_broadcast_exit_barkd() {
	require_bark_version!(> "0.3.0");

	let ctx = TestContext::new("barkd/cannot_cancel_broadcast_exit_barkd").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	// Manual-sync so we control exactly when the exit tx is broadcast; funded for CPFP fees.
	let bark = ctx.barkd("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;

	// Make the funded coins visible (manual-sync: nothing syncs the onchain wallet for us), then
	// board a portion, leaving the rest on-chain for CPFP fees.
	bark.onchain_sync().await;
	let board = bark.board_amount(sat(500_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let vtxos = bark.vtxos(None).await;
	assert_eq!(vtxos.len(), 1);
	let vtxo_id = vtxos[0].id.to_string();

	// One progress broadcasts the board's single — and therefore final — exit transaction.
	bark.exit_start_all().await;
	bark.exit_progress().await;

	let statuses = bark.get_live_exit_status(None, None).await;
	assert_eq!(statuses.len(), 1);
	assert!(matches!(statuses[0].state, ExitState::Processing(_)),
		"exit should be Processing with its only tx broadcast, got {:?}", statuses[0].state);

	// The final transaction is in the mempool, so cancellation must be refused (REST error).
	assert!(bark.try_cancel_exit(&vtxo_id).await.is_err(),
		"canceling once the final tx is broadcast should fail");

	// Still tracked, not canceled.
	let statuses = bark.get_live_exit_status(None, None).await;
	assert_eq!(statuses.len(), 1);
	assert!(!matches!(statuses[0].state, ExitState::Canceled(_)),
		"exit should not have been canceled, got {:?}", statuses[0].state);
	assert!(bark.get_finished_exits(None, None).await.is_empty());
}

/// A canceled exit can be restarted over REST and driven to completion — even after some of its
/// transactions were already broadcast and confirmed before the cancellation.
#[tokio::test]
async fn restart_exit_after_cancel_barkd() {
	require_bark_version!(> "0.3.0");

	let ctx = TestContext::new("barkd/restart_exit_after_cancel_barkd").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(500_000)).create().await;
	let bark = ctx.barkd("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;

	sender.send(bark.ark_address().await, sat(300_000)).await;
	bark.sync().await;
	let vtxo_id = bark.vtxos(None).await[0].id.to_string();

	// Start, broadcast + confirm the first tx, sync, then cancel mid-chain.
	bark.exit_start_all().await;
	bark.exit_progress().await;
	ctx.generate_blocks(1).await;
	bark.sync().await;
	bark.cancel_exit(&vtxo_id).await;
	assert!(bark.get_live_exit_status(None, None).await.is_empty());

	// Restart the exit for the same VTXO and drive it to claimable (manual-sync: step explicitly).
	bark.exit_start_all().await;
	assert_eq!(bark.get_live_exit_status(None, None).await.len(), 1,
		"a fresh exit should be tracked after restart");

	let mut claimable = false;
	for _ in 0..40 {
		bark.exit_progress().await;
		let statuses = bark.get_live_exit_status(None, None).await;
		if !statuses.is_empty() && statuses.iter().all(|s|
			matches!(s.state, ExitState::Claimable(_) | ExitState::Claimed(_))
		) {
			claimable = true;
			break;
		}
		ctx.generate_blocks(1).await;
	}
	assert!(claimable, "restarted exit should reach a claimable state");

	// Claim the restarted exit and confirm it completes.
	let addr = bark.onchain_address().await;
	bark.exit_claim_all(&addr.to_string()).await;
	ctx.generate_blocks(1).await;
	bark.exit_progress().await;

	// Claimed exits are finished, so they leave the live list.
	assert!(bark.get_live_exit_status(None, None).await.is_empty());
	let finished = bark.get_finished_exits(None, None).await;
	assert_eq!(finished.len(), 1);
	assert!(matches!(finished[0].state, ExitState::Claimed(_)),
		"restarted exit should reach Claimed, got {:?}", finished[0].state);

	// Two exit movements exist now (the canceled one and the restarted one); the restarted exit
	// must have completed successfully. Don't rely on history ordering.
	let exit_statuses = bark.history(None, None).await.into_iter()
		.filter(|m| m.subsystem.name == "bark.exit")
		.map(|m| m.status)
		.collect::<Vec<_>>();
	assert!(exit_statuses.contains(&MovementStatus::Successful),
		"a restarted exit movement should be Successful, got {:?}", exit_statuses);
}

/// The status endpoints split exits by liveness and the deprecated routes remain served.
#[tokio::test]
async fn exit_status_endpoints_barkd() {
	require_bark_version!(> "0.3.0");

	let ctx = TestContext::new("barkd/exit_status_endpoints_barkd").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(500_000)).create().await;
	// Manual sync so no exit transaction is broadcast, keeping cancellation available.
	let bark = ctx.barkd("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;

	sender.send(bark.ark_address().await, sat(200_000)).await;
	sender.send(bark.ark_address().await, sat(100_000)).await;
	bark.sync().await;
	let vtxos = bark.vtxos(None).await;
	assert_eq!(vtxos.len(), 2);
	let live_id = vtxos[0].id.to_string();
	let canceled_id = vtxos[1].id.to_string();

	bark.exit_start_all().await;
	bark.cancel_exit(&canceled_id).await;

	// /status/live and /status/finished split the two exits.
	let live = bark.get_live_exit_status(None, None).await;
	assert_eq!(live.len(), 1);
	assert_eq!(live[0].vtxo_id.to_string(), live_id);
	let finished = bark.get_finished_exits(None, None).await;
	assert_eq!(finished.len(), 1);
	assert_eq!(finished[0].vtxo_id.to_string(), canceled_id);

	// /status/all returns both.
	let all = bark.get_all_exit_status(None, None).await;
	let mut ids = all.iter().map(|s| s.vtxo_id.to_string()).collect::<Vec<_>>();
	ids.sort();
	let mut expected = vec![live_id.clone(), canceled_id.clone()];
	expected.sort();
	assert_eq!(ids, expected);

	// /status/vtxo serves live and finished exits alike.
	let status = bark.get_vtxo_exit_status(&live_id, None, None).await;
	assert!(matches!(status.state, ExitState::Start(_)), "got {:?}", status.state);
	let status = bark.get_vtxo_exit_status(&canceled_id, None, None).await;
	assert!(matches!(status.state, ExitState::Canceled(_)), "got {:?}", status.state);

	// Deprecated /status permanently redirects to /status/all.
	let resp = bark.get_no_redirect("/api/v1/exits/status").await;
	assert_eq!(resp.status(), 308);
	assert_eq!(resp.headers()["location"], "/api/v1/exits/status/all");

	// Deprecated /status/{vtxo_id} serves the same data as /status/vtxo/{vtxo_id}.
	#[allow(deprecated)]
	let deprecated = exits_api::get_exit_status_by_vtxo_id_deprecated(
		&bark.client_config(), &canceled_id, None, None,
	).await.expect("deprecated exit status endpoint failed");
	assert_eq!(deprecated, status);
}
