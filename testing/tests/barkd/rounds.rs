use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark::VtxoId;
use bark_json::movements::MovementStatus;
use server_log::RoundFinished;
use server_rpc::protos;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;

use super::helpers::{wait_for_boards_synced, wait_for_onchain_balance, wait_for_rounds_complete};

/// A captaind proxy that rejects round submissions containing a designated
/// "unusable" VTXO, mimicking the real server's response: `InvalidArgument`
/// carrying the offending id in the `identifiers` metadata. The id is shared so
/// a test can set it after boarding (before then the proxy passes everything
/// through). Lets us exercise how the client handles server-rejected refresh
/// inputs without having to genuinely corrupt server state.
#[derive(Clone)]
struct RejectVtxoProxy {
	bad: Arc<Mutex<Option<VtxoId>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RejectVtxoProxy {
	async fn submit_payment(
		&self,
		upstream: &mut ArkClient,
		req: protos::SubmitPaymentRequest,
	) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
		let bad = *self.bad.lock().unwrap();
		if let Some(bad) = bad {
			if req.input_vtxos.iter().any(|i| i.vtxo_id == bad.to_bytes().to_vec()) {
				let mut status = tonic::Status::invalid_argument(
					format!("input vtxo(s) not spendable: [{}]", bad),
				);
				status.metadata_mut().insert("identifiers", bad.to_string().parse().unwrap());
				return Err(status);
			}
		}
		Ok(upstream.submit_payment(req).await?.into_inner())
	}
}

/// Board two VTXOs and set up the daemon behind a proxy that rejects one of
/// them as unusable. Returns `(barkd, proxy, bad_id, good_id)` with the proxy
/// already poisoned; the caller must keep `proxy` alive (dropping it shuts the
/// proxy down). The bad VTXO is the smaller of the two.
async fn setup_barkd_with_rejected_vtxo(
	ctx: &TestContext,
	srv: &Captaind,
) -> (
	ark_testing::daemon::barkd::Barkd,
	captaind::proxy::ArkRpcProxyServer,
	VtxoId,
	VtxoId,
) {
	let bad = Arc::new(Mutex::new(None::<VtxoId>));
	let proxy = srv.start_proxy_no_mailbox(RejectVtxoProxy { bad: bad.clone() }).await;
	let proxy_url = proxy.address.clone();

	let barkd = ctx.barkd("barkd", srv)
		.funded(sat(1_000_000))
		.cfg(move |c| c.server_address = proxy_url)
		.create().await;

	wait_for_onchain_balance(&barkd, sat(1_000_000)).await;

	// Two independent vtxos so we can poison one and still refresh the other.
	barkd.board_amount(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;
	barkd.board_amount(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let vtxos = barkd.vtxos(None).await;
	assert_eq!(vtxos.len(), 2, "expected two boarded vtxos");
	let bad_id = vtxos.iter().min_by_key(|v| v.vtxo.amount).unwrap().vtxo.id;
	let good_id = vtxos.iter().max_by_key(|v| v.vtxo.amount).unwrap().vtxo.id;

	*bad.lock().unwrap() = Some(bad_id);

	(barkd, proxy, bad_id, good_id)
}

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

/// An explicit, developer-chosen refresh must NOT silently drop an input the
/// server rejects: the whole round fails and nothing is refreshed. Only
/// maintenance is allowed to skip rejected inputs (see the test below).
#[tokio::test]
async fn manual_refresh_does_not_drop_rejected_vtxo_barkd() {
	let ctx = TestContext::new("barkd/manual_refresh_does_not_drop_rejected_vtxo_barkd").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	let (barkd, _proxy, bad_id, good_id) = setup_barkd_with_rejected_vtxo(&ctx, &srv).await;
	barkd.refresh_vtxos(vec![bad_id.to_string(), good_id.to_string()]).await;
	srv.trigger_round().await;
	wait_for_rounds_complete(&ctx, &barkd).await;

	let ids = barkd.vtxos(None).await.into_iter().map(|v| v.vtxo.id).collect::<Vec<_>>();
	assert!(ids.contains(&bad_id), "rejected vtxo should remain after the failed refresh");
	assert!(
		ids.contains(&good_id),
		"healthy vtxo must NOT be silently refreshed when explicitly batched with a \
		rejected one; got {ids:?}",
	);
}

/// Non-delegated (interactive) maintenance must make forward progress around a
/// VTXO the server rejects as unusable.
#[tokio::test]
async fn maintenance_refresh_skips_rejected_vtxo_barkd() {
	let ctx = TestContext::new("barkd/maintenance_refresh_skips_rejected_vtxo_barkd").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	let (barkd, _proxy, bad_id, good_id) = setup_barkd_with_rejected_vtxo(&ctx, &srv).await;

	// Age both so the daemon's auto-maintenance considers them due for refresh.
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;

	// A SINGLE round must refresh the healthy vtxo: the daemon submits
	// [bad, good], the server rejects `bad`, and the daemon re-submits just
	// `good` to the SAME round (the submit window stays open after a rejection
	// and the in-flight attempt is replayed to the new participation). We trigger
	// exactly one round, then only mine blocks to confirm its funding tx — we
	// never trigger a second round, so a pass proves same-round recovery.
	srv.trigger_round().await;
	let mut refreshed = false;
	for _ in 0..30 {
		ctx.generate_blocks(1).await;
		tokio::time::sleep(Duration::from_secs(1)).await;
		let ids = barkd.vtxos(None).await.into_iter().map(|v| v.vtxo.id).collect::<Vec<_>>();
		if !ids.contains(&good_id) {
			refreshed = true;
			break;
		}
	}

	let final_ids = barkd.vtxos(None).await.into_iter().map(|v| v.vtxo.id).collect::<Vec<_>>();
	assert!(refreshed,
		"healthy vtxo should have been refreshed within a single round; final vtxos: {final_ids:?}");
	assert!(
		final_ids.contains(&bad_id),
		"the rejected vtxo should be left untouched (still spendable locally); got {final_ids:?}",
	);
	assert_eq!(final_ids.len(), 2, "should have the old VTXO and a new one");
	assert!(!final_ids.contains(&good_id), "the good vtxo should have been refreshed");

	// The recovery is recorded as two distinct refresh movements — a failed
	// attempt that included the rejected input, and a successful one that
	// dropped it — rather than a single movement mutated in place.
	let refreshes = barkd.history(None, None).await.into_iter()
		.filter(|m| m.subsystem.name == "bark.round" && m.subsystem.kind == "refresh")
		.collect::<Vec<_>>();

	let failed = refreshes.iter()
		.find(|m| m.status == MovementStatus::Failed)
		.expect("expected a failed refresh movement for the rejected batch");
	assert!(
		failed.input_vtxos.contains(&bad_id) && failed.input_vtxos.contains(&good_id),
		"the failed refresh movement should have attempted both inputs; got {:?}",
		failed.input_vtxos,
	);

	let succeeded = refreshes.iter()
		.find(|m| m.status == MovementStatus::Successful)
		.expect("expected a successful refresh movement for the healthy input");
	assert!(
		succeeded.input_vtxos.contains(&good_id) && !succeeded.input_vtxos.contains(&bad_id),
		"the successful refresh movement should have dropped the rejected input; got {:?}",
		succeeded.input_vtxos,
	);

	assert_ne!(failed.id, succeeded.id, "the two refreshes should be distinct movements");
	assert_ne!(
		failed.input_vtxos, succeeded.input_vtxos,
		"the failed and successful refresh movements should have different inputs",
	);
}
