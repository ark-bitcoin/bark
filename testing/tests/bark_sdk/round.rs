use std::sync::{Arc, Mutex};
use std::time::Duration;

use ark::VtxoId;
use bark::movement::MovementStatus;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient, Captaind};

/// A captaind proxy that rejects any round submission — interactive
/// (`submit_payment`) or delegated (`submit_round_participation`) — whose inputs
/// include one of the armed `bad` vtxos, mimicking the real server:
/// `InvalidArgument` carrying every offending id in the `identifiers` metadata.
/// The list is shared and set *after* boarding (boards flow through while it's
/// empty), so we can board through the proxy and only then poison inputs.
#[derive(Clone)]
struct RejectVtxoProxy {
	bad: Arc<Mutex<Vec<VtxoId>>>,
}

impl RejectVtxoProxy {
	/// The rejection the real server returns, naming every unusable input in the
	/// `identifiers` metadata (comma-separated).
	fn rejection(bad: &[VtxoId]) -> tonic::Status {
		let ids = bad.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
		let mut status = tonic::Status::invalid_argument(
			format!("input vtxo(s) not spendable: [{}]", ids),
		);
		status.metadata_mut().insert("identifiers", ids.parse().unwrap());
		status
	}

	/// The armed bad vtxos that appear in `inputs`.
	fn rejected(&self, inputs: &[protos::InputVtxo]) -> Vec<VtxoId> {
		self.bad.lock().unwrap().iter().copied()
			.filter(|bad| inputs.iter().any(|i| i.vtxo_id == bad.to_bytes().to_vec()))
			.collect()
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RejectVtxoProxy {
	async fn submit_payment(
		&self, upstream: &mut ArkClient, req: protos::SubmitPaymentRequest,
	) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
		let bad = self.rejected(&req.input_vtxos);
		if !bad.is_empty() {
			return Err(Self::rejection(&bad));
		}
		Ok(upstream.submit_payment(req).await?.into_inner())
	}

	async fn submit_round_participation(
		&self, upstream: &mut ArkClient, req: protos::RoundParticipationRequest,
	) -> Result<protos::RoundParticipationResponse, tonic::Status> {
		let bad = self.rejected(&req.input_vtxos);
		if !bad.is_empty() {
			return Err(Self::rejection(&bad));
		}
		Ok(upstream.submit_round_participation(req).await?.into_inner())
	}
}

/// Board two independent vtxos into an in-process SDK [`bark::Wallet`] that talks
/// to the server through a [RejectVtxoProxy], then arm the proxy to reject the
/// smaller one as unusable. Returns `(wallet, proxy, bad_id, good_id)`; keep
/// `proxy` alive (dropping it shuts it down).
///
/// The wallet runs in `daemon_manual_sync` mode: the background daemon's
/// round-event process is disabled so it can't race the test's own refresh
/// calls to join the same attempt for the same vtxos.
async fn setup_bark_sdk_with_rejected_vtxo(
	ctx: &TestContext,
	srv: &Captaind,
) -> (bark::Wallet, captaind::proxy::ArkRpcProxyServer, VtxoId, VtxoId) {
	let bad = Arc::new(Mutex::new(Vec::<VtxoId>::new()));
	let proxy = srv.start_proxy_no_mailbox(RejectVtxoProxy { bad: bad.clone() }).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 2, "expected two boarded vtxos");
	let bad_id = vtxos.iter().min_by_key(|v| v.amount()).unwrap().id();
	let good_id = vtxos.iter().max_by_key(|v| v.amount()).unwrap().id();

	*bad.lock().unwrap() = vec![bad_id];
	(wallet, proxy, bad_id, good_id)
}

/// Assert the drop-and-retry recovery is recorded as two distinct refresh
/// movements: a failed one that attempted both `bad` and `good`, and a successful
/// one that dropped `bad` and kept `good`.
async fn assert_dropped_and_retried_movements(
	wallet: &bark::Wallet,
	bad_id: VtxoId,
	good_id: VtxoId,
) {
	let refreshes = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.round" && m.subsystem.kind == "refresh")
		.collect::<Vec<_>>();

	// Match by inputs, not just status: a retry that re-submits and is rejected again can
	// leave extra failed refresh movements around.
	let failed = refreshes.iter()
		.find(|m| m.status == MovementStatus::Failed
			&& m.input_vtxos.contains(&bad_id) && m.input_vtxos.contains(&good_id))
		.expect("expected a failed refresh movement that attempted both the rejected and healthy inputs");

	let succeeded = refreshes.iter()
		.find(|m| m.status == MovementStatus::Successful
			&& m.input_vtxos.contains(&good_id) && !m.input_vtxos.contains(&bad_id))
		.expect("expected a successful refresh movement that dropped the rejected input");

	assert_ne!(failed.id, succeeded.id, "the two refreshes should be distinct movements");
}

/// An explicit, developer-chosen delegated refresh must fail wholesale when the
/// server rejects an input, rather than silently dropping the caller's selection.
/// Only maintenance is allowed to drop-and-retry.
#[tokio::test]
async fn manual_refresh_delegated_does_not_drop_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/manual_refresh_delegated_does_not_drop_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	// An explicit delegated refresh of BOTH vtxos must error out, not silently drop the
	// rejected input and submit the rest.
	let res = wallet.refresh_vtxos_delegated(vec![bad_id, good_id]).await;
	assert!(
		res.is_err(),
		"explicit delegated refresh including a server-rejected vtxo must fail wholesale",
	);

	let ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(
		ids.contains(&bad_id) && ids.contains(&good_id),
		"neither vtxo should be refreshed when an explicit delegated refresh fails; got {ids:?}",
	);
}

/// The blocking interactive maintenance entry point [`bark::Wallet::maintenance_refresh`]
/// must make forward progress around a VTXO the server rejects as unusable: it
/// joins the round, drops the rejected input and re-submits the rest to the
/// *same* attempt, rather than letting one bad VTXO block the healthy ones until
/// they expire.
#[tokio::test]
async fn manual_maintenance_refresh_drops_server_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/manual_maintenance_refresh_drops_server_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	// Age both vtxos so they are due for refresh.
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;

	// `maintenance_refresh` blocks until the round it joins finishes, so trigger a round
	// alongside it (after a short delay so it subscribes first). It should submit
	// [bad, good], have `bad` rejected, then re-submit just [good] to the same attempt.
	let (res, _) = tokio::join!(
		wallet.maintenance_refresh(),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	let status = res.expect("maintenance refresh must not fail wholesale around a rejected input");
	assert!(status.is_some(), "maintenance refresh should have refreshed the healthy vtxo");

	// Confirm the round and sync until the refresh settles: `good` is forfeited and replaced
	// by the round output (back to two spendable vtxos), while `bad` is left untouched. We
	// wait for the output to actually appear — `good` disappearing alone is too early, the
	// round tx may not have confirmed yet.
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut refreshed = false;
	for _ in 0..30 {
		wallet.sync().await;
		let ids = wallet.spendable_vtxos().await.expect("list vtxos")
			.into_iter().map(|v| v.id()).collect::<Vec<_>>();
		if ids.contains(&bad_id) && !ids.contains(&good_id) && ids.len() == 2 {
			refreshed = true;
			break;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	let final_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(refreshed,
		"healthy vtxo {good_id} should be refreshed while rejected vtxo {bad_id} is left \
		untouched; final vtxos: {final_ids:?}");

	assert_dropped_and_retried_movements(&wallet, bad_id, good_id).await;
}

/// When *every* VTXO due for refresh is rejected by the server as unusable, the
/// delegated maintenance retry loop drops them all and is left with an empty
/// batch. It must surface that as an error rather than silently reporting
/// success (`Ok(None)`), so an operator whose wallet only holds unspendable
/// inputs finds out instead of seeing maintenance quietly no-op forever.
#[tokio::test]
async fn maintenance_refresh_delegated_errors_when_all_inputs_unspendable() {
	let ctx = TestContext::new("bark_sdk/maintenance_refresh_delegated_errors_when_all_inputs_unspendable").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	let bad = Arc::new(Mutex::new(Vec::<VtxoId>::new()));
	let proxy = srv.start_proxy_no_mailbox(RejectVtxoProxy { bad: bad.clone() }).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(300_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 2, "expected two boarded vtxos");

	// Age both vtxos so they are due for refresh, then poison the whole batch.
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;
	*bad.lock().unwrap() = vtxos.iter().map(|v| v.id()).collect();

	// The batch is submitted, every input is rejected and excluded, and the loop
	// then finds nothing left to refresh — which must be an error, not `Ok(None)`.
	let res = wallet.maybe_schedule_maintenance_refresh_delegated().await;
	assert!(
		res.is_err(),
		"delegated maintenance must error when every input is rejected as unusable; got {res:?}",
	);
}

/// A delegated maintenance refresh batch that includes a VTXO the server rejects
/// as unusable must not fail wholesale: it drops exactly the rejected input and
/// refreshes the rest, so one bad VTXO can no longer block refreshing healthy
/// ones until they expire.
#[tokio::test]
async fn maintenance_refresh_delegated_drops_server_rejected_vtxo() {
	let ctx = TestContext::new("bark_sdk/maintenance_refresh_delegated_drops_server_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let (wallet, _proxy, bad_id, good_id) = setup_bark_sdk_with_rejected_vtxo(&ctx, &srv).await;

	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;
	wallet.maybe_schedule_maintenance_refresh_delegated().await
		.expect("delegated maintenance should schedule a refresh, dropping the rejected input");
	srv.trigger_round().await;

	// Confirm the round and sync until the refresh settles: `good` is forfeited and replaced
	// by the round output (back to two spendable vtxos), while `bad` is left untouched.
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut refreshed = false;
	for _ in 0..100 {
		wallet.sync().await;
		let ids = wallet.spendable_vtxos().await.expect("list vtxos")
			.into_iter().map(|v| v.id()).collect::<Vec<_>>();
		if ids.contains(&bad_id) && !ids.contains(&good_id) && ids.len() == 2 {
			refreshed = true;
			break;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	let final_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(refreshed,
		"healthy vtxo {good_id} should have been refreshed while rejected vtxo \
		{bad_id} was skipped; final vtxos: {final_ids:?}",
	);

	assert_dropped_and_retried_movements(&wallet, bad_id, good_id).await;
}
