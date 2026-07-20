
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::{Amount, SignedAmount};
use server_rpc::protos;

use bark::movement::MovementStatus;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};

/// The error [AbandonOffboardProxy] fails prepare_offboard with.
const ABANDON_ERROR: &str = "proxy: abandoning the offboard session";

/// Forwards prepare_offboard upstream, so the server creates its pending
/// session, but reports [ABANDON_ERROR] to the client, which abandons the
/// offboard. Server-side errors pass through untouched. Every forwarded
/// request is recorded so the test can re-send it directly.
#[derive(Clone)]
struct AbandonOffboardProxy {
	requests: Arc<Mutex<Vec<protos::PrepareOffboardRequest>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for AbandonOffboardProxy {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		self.requests.lock().unwrap().push(req.clone());
		upstream.prepare_offboard(req).await?;
		Err(tonic::Status::invalid_argument(ABANDON_ERROR))
	}
}

/// Sends every finish_offboard request to the server twice, like a client
/// that lost the first response and retries. The server must replay the
/// same signed tx instead of rejecting the retry as an unknown session.
#[derive(Clone)]
struct ReplayFinishOffboardProxy;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ReplayFinishOffboardProxy {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let first = upstream.finish_offboard(req.clone()).await?.into_inner();
		let retry = upstream.finish_offboard(req).await?.into_inner();
		if first != retry {
			return Err(tonic::Status::internal(format!(
				"finish_offboard retry got a different response: {:?} vs {:?}",
				first, retry,
			)));
		}
		Ok(retry)
	}
}

/// An abandoned offboard session must release the wallet UTXOs it locked
/// once it expires, so that pending offboards cannot starve the rounds
/// wallet (and with it round funding) until a restart.
///
/// Each 6btc offboard needs more than half of the rounds wallet's coins
/// (asserted below), so while the abandoned session for the first vtxo is
/// pending, offboarding the second vtxo fails on the server for lack of
/// funds — the starvation itself. Once the session expires, that same
/// offboard must be accepted. It shares no vtxos with the abandoned
/// session, only wallet funding, so its acceptance is only possible if the
/// expired session released the wallet UTXOs it had locked.
#[tokio::test]
async fn utxos_unlock_after_pending_offboard_expiry() {
	const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

	let ctx = TestContext::new("server/utxos_unlock_after_pending_offboard_expiry").await;
	let srv = ctx.captaind("server")
		.no_vtxo_pool()
		.funded(btc(10))
		.cfg(|c| c.offboard_session_timeout = SESSION_TIMEOUT)
		.create().await;

	let requests = Arc::new(Mutex::new(Vec::new()));
	let proxy = srv.start_proxy_no_mailbox(AbandonOffboardProxy {
		requests: requests.clone(),
	}).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.boarded(btc(6))
		.boarded(btc(6))
		.create().await;

	// Premise: the 10btc rounds wallet cannot fund two 6btc offboard txs at
	// the same time.
	let status = srv.wallet_status().await;
	assert!(status.rounds.trusted_balance < btc(11),
		"rounds wallet is rich enough to fund two offboards, breaking the \
		test's premise: {}", status.rounds.trusted_balance,
	);

	let [vtxo1, vtxo2] = wallet.spendable_vtxos().await.expect("list vtxos")
		.try_into().expect("should have two boarded vtxos");

	// Offboard the first vtxo; the proxy abandons the session right after
	// the server has created it.
	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_vtxos([vtxo1.id()], address.clone()).await
		.expect_err("the proxy should have failed the first offboard");
	assert!(format!("{err:#}").contains(ABANDON_ERROR), "unexpected error: {err:#}");

	// The rejected offboard leaves a failed movement recording the intent,
	// with a zero effective balance: its vtxos went back to spendable, so
	// the wallet's balance never actually changed.
	let movements = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.offboard")
		.collect::<Vec<_>>();
	assert_eq!(movements.len(), 1);
	assert_eq!(movements[0].status, MovementStatus::Failed);
	assert_ne!(movements[0].intended_balance, SignedAmount::ZERO);
	assert_eq!(movements[0].effective_balance, SignedAmount::ZERO);

	// While the session is pending it keeps its wallet UTXOs locked, so
	// the server cannot fund an offboard of the second vtxo: this is the
	// starvation. Note this error comes from the server, not the proxy.
	let err = wallet.offboard_vtxos([vtxo2.id()], address).await
		.expect_err("the second offboard should fail while the wallet UTXOs are locked");
	let err = format!("{err:#}");
	assert!(err.contains("bdk failed to create offboard tx"), "unexpected error: {err}");
	assert!(!err.contains(ABANDON_ERROR), "the error should come from the server: {err}");

	// Once the abandoned session expires, the same offboard must be
	// accepted again.
	let req = requests.lock().unwrap().last().cloned()
		.expect("the second prepare_offboard request should have been recorded");
	let mut direct = srv.get_public_rpc().await;
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		tokio::time::sleep(SESSION_TIMEOUT).await;
		match direct.prepare_offboard(req.clone()).await {
			Ok(_) => break,
			Err(e) => assert!(Instant::now() < deadline,
				"expired offboard session did not release its wallet UTXOs: {e}"),
		}
	}
}

#[tokio::test]
async fn finish_offboard_replays_for_identical_retry() {
	let ctx = TestContext::new("server/finish_offboard_replays_for_identical_retry").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(ReplayFinishOffboardProxy).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.boarded(sat(800_000))
		.create().await;

	// A server without finish replay rejects the proxy's second call with
	// "unknown offboard txid", failing the whole offboard.
	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await
		.expect("offboard should succeed despite the doubled finish request");

	// And the replayed response was the real signed tx: it confirms and
	// pays out.
	ctx.generate_blocks(1).await;
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO);
}
