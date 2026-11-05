
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::{Amount, Txid};

use ark::{ProtocolEncoding, VtxoId};
use bark_json::movements::MovementStatus;
use bark_json::primitives::VtxoStateInfo;

use ark_testing::{btc, require_bark_version, sat, TestContext};
use bark_rest_client::apis::exits_api;
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::barkd::Barkd;
use bark_json::exit::ExitState;
use bark_json::exit::presign::{
	PresignedExitPackage, PresignedExitStatus, PresignedExits, PresignedWave,
};
use bark_json::exit::remaining::RemainingExitTransactions;
use bark_json::exit::states::ExitTxStatus;
use bitcoin_ext::rpc::BitcoinRpcExt;

use super::helpers::{
	progress_exits_until_claimable, wait_for_boards_synced, wait_for_exits_claimable,
	wait_for_onchain_balance, wait_for_rounds_complete,
};

/// Decode the wallet's full VTXO and return its exit chain txids in broadcast order.
async fn expected_exit_txids(barkd: &Barkd, vtxo_id: &str) -> Vec<Txid> {
	let encoded = barkd.get_vtxo_encoded(vtxo_id).await;
	let vtxo: ark::Vtxo = ark::Vtxo::deserialize_hex(&encoded.encoded.0)
		.expect("encoded VTXO should decode");
	vtxo.transactions().map(|item| item.tx.compute_txid()).collect()
}

/// The `(exit, child)` packages of one VTXO, in broadcast order across waves.
fn vtxo_packages<'a>(
	presigned: &'a PresignedExits,
	vtxo_id: &str,
) -> Vec<&'a PresignedExitPackage> {
	presigned.waves.iter()
		.flat_map(|wave| wave.packages.iter())
		.filter(|p| p.vtxo_id.to_string() == vtxo_id)
		.collect()
}

/// An exit's full remaining chain: its signed packages, then its unsigned tail.
fn exit_txids(presigned: &PresignedExits, exit_index: usize) -> Vec<Txid> {
	let exit = &presigned.exits[exit_index];
	vtxo_packages(presigned, &exit.vtxo_id.to_string()).iter().map(|p| p.exit.txid)
		.chain(exit.unsigned.iter().map(|t| t.txid))
		.collect()
}

/// Broadcast every package of one presigned wave, then mine a block so the wave's change
/// confirms before the next wave needs it.
async fn broadcast_presigned_wave(ctx: &TestContext, wave: &PresignedWave) {
	for package in &wave.packages {
		ctx.bitcoind().sync_client()
			.submit_package(&[&package.exit.tx, &package.child.tx])
			.expect("submit_package of presigned exit package failed");
	}
	for package in &wave.packages {
		ctx.await_transaction(package.child.txid).await;
	}
	ctx.generate_blocks(1).await;
}

/// Verify `POST /exits/start/all` registers all VTXOs for exit and
/// the daemon auto-progresses them to claimable.
#[tokio::test]
async fn exit_start_all_and_progress_barkd() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/exit_start_all_and_progress_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	// Board into a VTXO, then refresh into a round so it's fully in-round.
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

	barkd.refresh_all().await;
	srv.trigger_round().await;
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
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/exit_claim_all_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

	barkd.refresh_all().await;
	srv.trigger_round().await;
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
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/exit_auto_progress_disconnected_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	// Setup: board and refresh into round.
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(500_000)).create().await;

	barkd.refresh_all().await;
	srv.trigger_round().await;
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

/// Presign the full exit chains of two shared-ancestry VTXOs, broadcast the
/// packages manually in order, then verify the exits complete and can be claimed.
#[tokio::test]
async fn presign_exit_fully_signed_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/presign_exit_fully_signed_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(1_000_000)).create().await;
	// Manual sync so nothing progresses exits behind the test's back.
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	sender.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	// Two arkoor payments from the same sender: the second spends the change of
	// the first, so both exit chains share a prefix up to the first arkoor tx
	// (each payment's checkpoint tx is unique to its own chain).
	let addr = barkd.ark_address().await;
	sender.send_oor(&addr, sat(100_000)).await;
	sender.send_oor(&addr, sat(200_000)).await;
	barkd.sync().await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "{:?}", vtxos);
	let v1 = vtxos.iter().find(|v| v.amount == sat(100_000)).unwrap().id.to_string();
	let v2 = vtxos.iter().find(|v| v.amount == sat(200_000)).unwrap().id.to_string();

	let v1_txids = expected_exit_txids(&barkd, &v1).await;
	let v2_txids = expected_exit_txids(&barkd, &v2).await;
	assert_eq!(v1_txids.len(), 3, "{:?}", v1_txids);
	assert_eq!(v2_txids.len(), 5, "{:?}", v2_txids);
	assert_eq!(v2_txids[..2], v1_txids[..2], "the VTXOs should share their chain prefix");

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	srv.stop().await.unwrap();

	let presigned = barkd.presign_exits(Some(vec![v1.clone(), v2.clone()]), None).await;
	assert_eq!(presigned.exits.len(), 2);

	// Results follow the requested order; shared transactions only appear under
	// the first exit that needs them.
	let e1 = &presigned.exits[0];
	assert_eq!(e1.vtxo_id.to_string(), v1);
	assert!(
		matches!(e1.status, PresignedExitStatus::FullySigned { exited_in_wave: Some(2), .. }),
		"{:?}", e1.status,
	);
	assert!(e1.unsigned.is_empty());
	assert_eq!(exit_txids(&presigned, 0), v1_txids);
	let e2 = &presigned.exits[1];
	assert_eq!(e2.vtxo_id.to_string(), v2);
	assert!(
		matches!(e2.status, PresignedExitStatus::FullySigned { exited_in_wave: Some(5), .. }),
		"{:?}", e2.status,
	);
	assert!(e2.unsigned.is_empty());
	assert_eq!(exit_txids(&presigned, 1), &v2_txids[2..]);

	// The single funding UTXO forces a fully serial plan: one package per wave, the shared
	// prefix first (the second exit's own packages must wait for it to confirm anyway).
	assert_eq!(presigned.waves.len(), 6, "{:?}", presigned.waves);
	assert!(presigned.waves.iter().all(|w| w.packages.len() == 1));

	// Every package's child commits the package fee; the two-output arkoor parents weigh more
	// than the board and checkpoint txs.
	let fees = presigned.waves.iter()
		.map(|r| r.packages[0].child.fee_info.total_fee.to_sat())
		.collect::<Vec<_>>();
	assert_eq!(fees, [1_382, 1_812, 1_382, 1_382, 1_597, 1_382]);
	// The first arkoor splits its larger change into an extra output, so the first exit's
	// packages weigh more than the second's.
	let totals = presigned.exits.iter()
		.map(|e| match e.status {
			PresignedExitStatus::FullySigned { fee_info, .. } => fee_info.total_fee.to_sat(),
			other => panic!("fully signed exit expected, got {:?}", other),
		})
		.collect::<Vec<_>>();
	assert_eq!(totals, [4_576, 4_361]);

	// With one UTXO the children form one serial chain: each wave's child is funded by the
	// previous wave's change.
	let children = presigned.waves.iter()
		.map(|r| &r.packages[0].child)
		.collect::<Vec<_>>();
	for pair in children.windows(2) {
		assert!(
			pair[1].tx.input.iter().any(|i| i.previous_output.txid == pair[0].txid),
			"child {} should spend the change of child {}", pair[1].txid, pair[0].txid,
		);
	}

	// Broadcast the plan wave by wave.
	for wave in &presigned.waves {
		broadcast_presigned_wave(&ctx, wave).await;
	}

	// All CPFP fees came out of the single funding UTXO: 100_000 − 4_576 − 4_361. Presigning
	// revealed the children's change addresses, so one sync must pick up the whole chain.
	barkd.onchain_sync().await;
	assert_eq!(barkd.onchain_balance().await, sat(91_063));

	// The wallet picks the confirmed chains up and the exits become claimable.
	barkd.exit_start_vtxos(vec![v1, v2]).await;
	progress_exits_until_claimable(&ctx, &barkd).await;

	// Ensure no exit transactions had to be built and broadcast
	assert_eq!(barkd.onchain_balance().await, sat(91_063));

	let claim_addr = barkd.onchain_address().await;
	barkd.exit_claim_all(&claim_addr.to_string()).await;
	ctx.generate_blocks(1).await;
	barkd.onchain_sync().await;
	// CPFP funding change plus the two claimed VTXOs (300k) minus the claim fee.
	assert_eq!(barkd.onchain_balance().await, sat(390_040));
}

/// Presign with only enough confirmed funds for the first two packages: the
/// first exit is partially signed, the second not at all, and after the signed
/// packages confirm the exit can't progress past them on its own.
#[tokio::test]
async fn presign_exit_partially_signed_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/presign_exit_partially_signed_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender1 = ctx.bark("sender1", &srv).funded(sat(1_000_000)).create().await;
	let sender2 = ctx.bark("sender2", &srv).funded(sat(500_000)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	// First VTXO: a five-transaction exit chain (board plus two arkoor hops).
	sender1.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let sender1_addr = sender1.address().await;
	sender1.send_oor(&sender1_addr, sat(800_000)).await;
	let addr = barkd.ark_address().await;
	sender1.send_oor(&addr, sat(300_000)).await;

	// Second VTXO: an independent three-transaction chain from another sender.
	sender2.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	sender2.send_oor(&addr, sat(100_000)).await;

	barkd.sync().await;
	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "{:?}", vtxos);
	let v1 = vtxos.iter().find(|v| v.amount == sat(300_000)).unwrap().id.to_string();
	let v2 = vtxos.iter().find(|v| v.amount == sat(100_000)).unwrap().id.to_string();

	let v1_txids = expected_exit_txids(&barkd, &v1).await;
	let v2_txids = expected_exit_txids(&barkd, &v2).await;
	assert_eq!(v1_txids.len(), 5, "{:?}", v1_txids);
	assert_eq!(v2_txids.len(), 3, "{:?}", v2_txids);

	// Enough confirmed funds for exactly two CPFP children (~1382 sats each,
	// with change staying above dust), so the walk stops inside the first chain.
	ctx.fund_barkd(&barkd, sat(3_300)).await;
	srv.stop().await.unwrap();

	let presigned = barkd.presign_exits(Some(vec![v1.clone(), v2.clone()]), None).await;
	// After two 1_382-sat children, 536 sats of change remain — not enough for
	// the third parent's fee plus a non-dust drain, so signing stops there. The first exit is
	// tried first each wave, so it consumes the funds the second exit would have needed.
	let e1 = &presigned.exits[0];
	assert_eq!(e1.status, PresignedExitStatus::PartiallySigned { last_wave: 1 });
	assert_eq!(exit_txids(&presigned, 0), v1_txids);
	let signed = vtxo_packages(&presigned, &v1);
	assert_eq!(signed.len(), 2, "3300 sats should fund exactly two children");
	assert_eq!(e1.unsigned.iter().map(|t| t.txid).collect::<Vec<_>>(), &v1_txids[2..]);
	for package in &signed {
		assert_eq!(package.child.fee_info.total_fee, sat(1_382));
	}

	let e2 = &presigned.exits[1];
	assert_eq!(e2.status, PresignedExitStatus::Unsigned);
	assert_eq!(exit_txids(&presigned, 1), v2_txids);
	assert!(vtxo_packages(&presigned, &v2).is_empty());

	// Broadcast the two signed waves, confirming each.
	assert_eq!(presigned.waves.len(), 2, "{:?}", presigned.waves);
	broadcast_presigned_wave(&ctx, &presigned.waves[0]).await;
	broadcast_presigned_wave(&ctx, &presigned.waves[1]).await;

	// The exit picks up the broadcast packages, but the leftover change can't
	// fund the third one, so the exits stay in Processing.
	barkd.exit_start_vtxos(vec![v1.clone(), v2.clone()]).await;
	let resp = barkd.exit_progress().await;
	assert!(!resp.done, "{:?}", resp.exits);

	let statuses = barkd.get_all_exit_status(None, Some(true)).await;
	let s1 = statuses.iter().find(|s| s.vtxo_id.to_string() == v1).unwrap();
	let confirmed = match &s1.state {
		ExitState::Processing(p) => p.transactions.iter()
			.filter(|t| matches!(t.status, ExitTxStatus::Confirmed { .. }))
			.map(|t| t.txid)
			.collect::<Vec<_>>(),
		other => panic!("first exit should be Processing, got {:?}", other),
	};
	assert_eq!(confirmed, &v1_txids[..2], "the two broadcast packages should be confirmed");

	// The children tracked for the confirmed packages are the presigned ones.
	let tracked = s1.transactions.iter()
		.filter_map(|p| p.child.as_ref().map(|c| (p.exit.txid, c.info.txid)))
		.collect::<HashMap<_, _>>();
	for package in &signed {
		assert_eq!(tracked.get(&package.exit.txid), Some(&package.child.txid));
	}

	// Still stuck after more blocks and progress attempts.
	ctx.generate_blocks(1).await;
	let resp = barkd.exit_progress().await;
	assert!(!resp.done, "{:?}", resp.exits);
	for s in &barkd.get_all_exit_status(None, None).await {
		assert!(matches!(s.state, ExitState::Processing(_)), "{:?}", s.state);
	}
}

/// Presigning with no confirmed onchain funds signs nothing but still returns
/// every remaining exit package in broadcast order.
#[tokio::test]
async fn presign_exit_unsigned_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/presign_exit_unsigned_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(1_000_000)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	sender.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let addr = barkd.ark_address().await;
	sender.send_oor(&addr, sat(100_000)).await;
	sender.send_oor(&addr, sat(200_000)).await;
	barkd.sync().await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "{:?}", vtxos);
	let v1 = vtxos.iter().find(|v| v.amount == sat(100_000)).unwrap().id.to_string();
	let v2 = vtxos.iter().find(|v| v.amount == sat(200_000)).unwrap().id.to_string();

	let v1_txids = expected_exit_txids(&barkd, &v1).await;
	let v2_txids = expected_exit_txids(&barkd, &v2).await;
	assert_eq!(v2_txids[..2], v1_txids[..2], "the VTXOs should share their chain prefix");

	srv.stop().await.unwrap();
	assert_eq!(barkd.onchain_balance().await, Amount::ZERO);

	let presigned = barkd.presign_exits(Some(vec![v1.clone(), v2.clone()]), None).await;

	// Nothing could be funded: the plan is empty, but both exits keep their full remaining
	// chains (deduped) under `unsigned`.
	assert!(presigned.waves.is_empty(), "{:?}", presigned.waves);
	for (exit, expected) in presigned.exits.iter().zip([&v1_txids[..], &v2_txids[2..]]) {
		assert_eq!(exit.status, PresignedExitStatus::Unsigned);
		assert_eq!(exit.unsigned.iter().map(|t| t.txid).collect::<Vec<_>>(), expected);
	}
}

/// A relayed package is listed in the first wave's `in_mempool`; its dependents wait a wave.
#[tokio::test]
async fn presign_exit_waits_for_mempool_package_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/presign_exit_waits_for_mempool_package_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(1_000_000)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	sender.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let addr = barkd.ark_address().await;
	sender.send_oor(&addr, sat(100_000)).await;
	barkd.sync().await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 1, "{:?}", vtxos);
	let vtxo = vtxos[0].id.to_string();
	let txids = expected_exit_txids(&barkd, &vtxo).await;
	assert_eq!(txids.len(), 3, "{:?}", txids);

	// One UTXO for the relayed package, one for the rest.
	ctx.fund_barkd(&barkd, sat(50_000)).await;
	ctx.fund_barkd(&barkd, sat(50_000)).await;
	srv.stop().await.unwrap();

	let first = barkd.presign_exits(Some(vec![vtxo.clone()]), None).await;
	let relayed = &first.waves[0].packages[0];
	assert_eq!(relayed.exit.txid, txids[0]);
	ctx.bitcoind().sync_client()
		.submit_package(&[&relayed.exit.tx, &relayed.child.tx])
		.expect("submit_package of the first presigned package failed");
	ctx.await_transaction(relayed.child.txid).await;

	// Presigning syncs exits itself.
	let presigned = barkd.presign_exits(Some(vec![vtxo.clone()]), None).await;
	let first_wave = &presigned.waves[0];
	assert!(first_wave.packages.is_empty(), "{:?}", first_wave);
	assert_eq!(first_wave.in_mempool.iter().map(|t| t.txid).collect::<Vec<_>>(), [txids[0]]);
	assert_eq!(exit_txids(&presigned, 0), txids[1..]);
	assert_eq!(presigned.waves.len(), 3, "{:?}", presigned.waves);
	assert!(
		matches!(presigned.exits[0].status, PresignedExitStatus::FullySigned { exited_in_wave: Some(2), .. }),
		"{:?}", presigned.exits[0].status,
	);

	// Execute the plan.
	ctx.generate_blocks(1).await;
	for wave in &presigned.waves[1..] {
		broadcast_presigned_wave(&ctx, wave).await;
	}
	for txid in &txids {
		let status = ctx.bitcoind().sync_client().tx_status(*txid).expect("tx status");
		assert!(status.is_confirmed(), "exit tx {} should be confirmed, is {:?}", txid, status);
	}
}

/// Two exits with independent chains and their own funding UTXOs are presigned into concurrent
/// waves: every wave carries a package from both exits and confirms in a single block.
#[tokio::test]
async fn presign_exit_concurrent_chains_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/presign_exit_concurrent_chains_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender1 = ctx.bark("sender1", &srv).funded(sat(1_000_000)).create().await;
	let sender2 = ctx.bark("sender2", &srv).funded(sat(500_000)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	// Two independent three-transaction chains from different senders.
	let addr = barkd.ark_address().await;
	sender1.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	sender1.send_oor(&addr, sat(100_000)).await;
	sender2.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	sender2.send_oor(&addr, sat(200_000)).await;
	barkd.sync().await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "{:?}", vtxos);
	let v1 = vtxos.iter().find(|v| v.amount == sat(100_000)).unwrap().id.to_string();
	let v2 = vtxos.iter().find(|v| v.amount == sat(200_000)).unwrap().id.to_string();
	let v1_txids = expected_exit_txids(&barkd, &v1).await;
	let v2_txids = expected_exit_txids(&barkd, &v2).await;
	assert_eq!(v1_txids.len(), 3, "{:?}", v1_txids);
	assert_eq!(v2_txids.len(), 3, "{:?}", v2_txids);

	// One confirmed UTXO per chain lets both exits advance in every wave.
	ctx.fund_barkd(&barkd, sat(50_000)).await;
	ctx.fund_barkd(&barkd, sat(50_000)).await;
	srv.stop().await.unwrap();

	let presigned = barkd.presign_exits(Some(vec![v1.clone(), v2.clone()]), None).await;
	// The first sender's arkoor splits its larger change into an extra output, so the first
	// exit's packages weigh more than the second's.
	for (exit, total) in presigned.exits.iter().zip([sat(4_576), sat(4_361)]) {
		assert!(
			matches!(exit.status, PresignedExitStatus::FullySigned { exited_in_wave: Some(2), fee_info }
				if fee_info.total_fee == total),
			"{:?}", exit.status,
		);
	}
	assert_eq!(presigned.waves.len(), 3, "{:?}", presigned.waves);
	for wave in &presigned.waves {
		let vtxo_ids = wave.packages.iter().map(|p| p.vtxo_id.to_string()).collect::<Vec<_>>();
		assert_eq!(vtxo_ids, [v1.clone(), v2.clone()], "each wave advances both exits");
	}
	assert_eq!(exit_txids(&presigned, 0), v1_txids);
	assert_eq!(exit_txids(&presigned, 1), v2_txids);

	// The first wave's children must be funded disjointly to relay in the same block.
	let first = &presigned.waves[0].packages;
	let funding = |p: &PresignedExitPackage| p.child.tx.input.iter()
		.map(|i| i.previous_output)
		.filter(|o| o.txid != p.exit.txid)
		.collect::<HashSet<_>>();
	assert!(funding(&first[0]).is_disjoint(&funding(&first[1])));

	// Each wave broadcasts both packages and confirms in a single block.
	for wave in &presigned.waves {
		broadcast_presigned_wave(&ctx, wave).await;
	}
	barkd.onchain_sync().await;
	assert_eq!(barkd.onchain_balance().await, sat(91_063));

	barkd.exit_start_vtxos(vec![v1, v2]).await;
	progress_exits_until_claimable(&ctx, &barkd).await;
	assert_eq!(barkd.onchain_balance().await, sat(91_063));

	let claim_addr = barkd.onchain_address().await;
	barkd.exit_claim_all(&claim_addr.to_string()).await;
	ctx.generate_blocks(1).await;
	barkd.onchain_sync().await;
	assert_eq!(barkd.onchain_balance().await, sat(390_040));
}

/// The read-only remaining-transactions API lists pending exit transactions per VTXO and
/// de-duplicated, without signing anything or touching the onchain wallet.
#[tokio::test]
async fn remaining_exit_transactions_barkd() {
	require_bark_version!(> "0.8.0");

	let ctx = TestContext::new("barkd/remaining_exit_transactions_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(1_000_000)).create().await;
	let barkd = ctx.barkd("barkd1", &srv).cfg(|c| c.daemon_manual_sync = true).create().await;

	// Two VTXOs sharing a two-transaction chain prefix, as in the presign tests.
	sender.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let addr = barkd.ark_address().await;
	sender.send_oor(&addr, sat(100_000)).await;
	sender.send_oor(&addr, sat(200_000)).await;
	barkd.sync().await;

	let vtxos = barkd.vtxos(None).await;
	let v1 = vtxos.iter().find(|v| v.amount == sat(100_000)).unwrap().id.to_string();
	let v2 = vtxos.iter().find(|v| v.amount == sat(200_000)).unwrap().id.to_string();
	let v1_id = VtxoId::from_str(&v1).unwrap();
	let v2_id = VtxoId::from_str(&v2).unwrap();
	let v1_txids = expected_exit_txids(&barkd, &v1).await;
	let v2_txids = expected_exit_txids(&barkd, &v2).await;
	assert_eq!(v1_txids[..2], v2_txids[..2]);

	let txids = |r: &RemainingExitTransactions| r.transactions.iter()
		.map(|t| t.txid)
		.collect::<Vec<_>>();

	// Read-only: works with no onchain funds and no started exit. Each VTXO lists its full chain
	// while the shared prefix appears once, parents first.
	let remaining = barkd.remaining_exit_transactions(Some(vec![v1.clone(), v2.clone()])).await;
	assert_eq!(remaining.exits.len(), 2);
	assert_eq!(remaining.exits[&v1_id], v1_txids);
	assert_eq!(remaining.exits[&v2_id], v2_txids);
	assert_eq!(txids(&remaining), [&v1_txids[..], &v2_txids[2..]].concat());

	// Confirm the first presigned package and leave the second in the mempool.
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	srv.stop().await.unwrap();
	let presigned = barkd.presign_exits(Some(vec![v1.clone(), v2.clone()]), None).await;
	broadcast_presigned_wave(&ctx, &presigned.waves[0]).await;
	let second = &presigned.waves[1].packages[0];
	ctx.bitcoind().sync_client()
		.submit_package(&[&second.exit.tx, &second.child.tx])
		.expect("submit_package of second presigned package failed");
	ctx.await_transaction(second.child.txid).await;

	// Statuses reflect the last exit sync, so refresh before querying again (a progress call
	// with no started exits only syncs transaction state).
	barkd.exit_progress().await;

	// The confirmed transaction drops off every VTXO; the one in the mempool remains.
	let remaining = barkd.remaining_exit_transactions(Some(vec![v1.clone(), v2.clone()])).await;
	assert_eq!(remaining.exits[&v1_id], v1_txids[1..]);
	assert_eq!(remaining.exits[&v2_id], v2_txids[1..]);
	assert_eq!(txids(&remaining), [&v1_txids[1..], &v2_txids[2..]].concat());

	// A started exit reports from its tracked state instead of querying the chain.
	ctx.generate_blocks(1).await;
	barkd.onchain_sync().await;
	barkd.exit_start_vtxos(vec![v1.clone()]).await;
	barkd.exit_progress().await;
	let remaining = barkd.remaining_exit_transactions(Some(vec![v1.clone(), v2.clone()])).await;
	assert_eq!(remaining.exits[&v1_id], v1_txids[2..]);
	assert_eq!(remaining.exits[&v2_id], v2_txids[2..]);
	assert_eq!(txids(&remaining), [&v1_txids[2..], &v2_txids[2..]].concat());
}
