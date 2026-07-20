
use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};
use std::time::Duration;

use bitcoin::{Amount, FeeRate, Transaction, Witness};
use bitcoin_ext::rpc::RpcApi;

use bark::actions::offboard::Progress;
use bark::movement::{Movement, MovementStatus, PaymentMethod};
use server_rpc::protos;

use ark_testing::{btc, constants, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::action_drive_factor;

/// Sends every prepare_offboard request to the server twice, like a
/// client that lost the first response and retries. The server must
/// replay the same session instead of rejecting the retry because
/// the vtxos are locked by the first request's session.
#[derive(Clone)]
struct ReplayPrepareOffboardProxy;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ReplayPrepareOffboardProxy {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		let first = upstream.prepare_offboard(req.clone()).await?.into_inner();
		let retry = upstream.prepare_offboard(req).await?.into_inner();
		if first != retry {
			return Err(tonic::Status::internal(format!(
				"prepare_offboard retry got a different response: {:?} vs {:?}",
				first, retry,
			)));
		}
		Ok(retry)
	}
}

/// Strips the witnesses from the first `action_drive_factor()`
/// finish_offboard responses, like a server that returns the unsigned tx
/// instead of the signed one (the double-drive reentrancy mode runs each
/// advance step twice, so both calls of the first step must behave the
/// same). Later calls pass through.
#[derive(Clone)]
struct UnsignedFinishResponseProxy(Arc<AtomicUsize>);

impl UnsignedFinishResponseProxy {
	fn new() -> Self {
		Self(Arc::new(AtomicUsize::new(action_drive_factor())))
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for UnsignedFinishResponseProxy {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let mut resp = upstream.finish_offboard(req).await?.into_inner();
		let strip = self.0.fetch_update(
			atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |n| n.checked_sub(1),
		).is_ok();
		if strip {
			let mut tx = bitcoin::consensus::deserialize::<Transaction>(&resp.signed_offboard_tx)
				.expect("server sent a valid tx");
			for input in &mut tx.input {
				input.witness = Witness::new();
			}
			resp.signed_offboard_tx = bitcoin::consensus::serialize(&tx);
		}
		Ok(resp)
	}
}

/// Swallows the first `action_drive_factor()` finish_offboard requests
/// without forwarding them, like a network failure on the way to the
/// server (the double-drive reentrancy mode runs each advance step twice,
/// so both calls of the first step must behave the same). Later calls
/// pass through.
#[derive(Clone)]
struct DropFirstFinishRequestProxy(Arc<AtomicUsize>);

impl DropFirstFinishRequestProxy {
	fn new() -> Self {
		Self(Arc::new(AtomicUsize::new(action_drive_factor())))
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for DropFirstFinishRequestProxy {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let dropped = self.0.fetch_update(
			atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |n| n.checked_sub(1),
		).is_ok();
		if dropped {
			return Err(tonic::Status::internal("proxy: dropped the finish_offboard request"));
		}
		Ok(upstream.finish_offboard(req).await?.into_inner())
	}
}

/// Forwards the first `action_drive_factor()` finish_offboard requests
/// upstream but reports an error instead of the response, like a client
/// that crashed before it could process it (the double-drive reentrancy
/// mode runs each advance step twice, so both calls of the first step
/// must behave the same). Later calls pass through.
#[derive(Clone)]
struct LoseFirstFinishResponseProxy(Arc<AtomicUsize>);

impl LoseFirstFinishResponseProxy {
	fn new() -> Self {
		Self(Arc::new(AtomicUsize::new(action_drive_factor())))
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for LoseFirstFinishResponseProxy {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let resp = upstream.finish_offboard(req).await?.into_inner();
		let lost = self.0.fetch_update(
			atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |n| n.checked_sub(1),
		).is_ok();
		if lost {
			return Err(tonic::Status::internal("proxy: lost the finish_offboard response"));
		}
		Ok(resp)
	}
}

/// The offboard movement of the given wallet.
async fn offboard_movement(wallet: &bark::Wallet) -> Movement {
	let movements = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.offboard" && m.subsystem.kind == "offboard")
		.collect::<Vec<_>>();
	assert_eq!(movements.len(), 1);
	movements[0].clone()
}

#[tokio::test]
async fn offboard_replays_identical_prepare_request() {
	const OFFBOARD_CONFIRMATIONS: u32 = 2;

	let ctx = TestContext::new("bark_sdk/offboard_replays_identical_prepare_request").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(ReplayPrepareOffboardProxy).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.offboard_required_confirmations = OFFBOARD_CONFIRMATIONS)
		.boarded(sat(800_000))
		.create().await;

	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.expect("offboard should succeed");

	assert_eq!(wallet.balance().await.expect("balance").spendable, Amount::ZERO);

	// The offboard went through the replayed session; its movement stays
	// pending until the offboard tx confirms.
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Pending);

	// Confirm the offboard tx and sync so the movement settles.
	ctx.generate_blocks(OFFBOARD_CONFIRMATIONS).await;
	wallet.sync().await;

	let movement = offboard_movement(&wallet).await;
	assert_eq!(movement.status, MovementStatus::Successful);
	let sent = movement.sent_to.first().expect("offboard has a destination");
	assert_eq!(sent.destination, PaymentMethod::Bitcoin(address.clone().into_unchecked()));

	// And the destination address received the funds onchain.
	assert_eq!(ctx.bitcoind().get_received_by_address(&address), sent.amount);
}

/// A finish response whose tx matches the session txid but carries no
/// signatures must be rejected: the txid doesn't commit to the witnesses,
/// so an unsigned tx would sail through the txid check and strand the
/// action at broadcast. The server's session is still intact, so the
/// finish retry replays the real signed tx and the offboard completes.
#[tokio::test]
async fn offboard_rejects_unsigned_finish_response() {
	let ctx = TestContext::new("bark_sdk/offboard_rejects_unsigned_finish_response").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(UnsignedFinishResponseProxy::new()).await;

	// Manual sync only, so the test controls the finish retry.
	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| {
			c.offboard_required_confirmations = 1;
			c.daemon_manual_sync = true;
		})
		.boarded(sat(800_000))
		.create().await;

	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_all(address.clone()).await
		.expect_err("the unsigned finish response should be rejected");
	let err = format!("{err:#}");
	assert!(err.contains("unsigned input"), "unexpected error: {err}");

	// The rejected response must not have advanced the checkpoint.
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(
		matches!(pending[0].progress, Progress::OffboardTxPrepared { .. }),
		"expected the offboard to stay at the finish step: {:?}", pending[0].progress,
	);

	// The retry replays the stored response, now unmangled, and the
	// offboard settles like any other.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	ctx.generate_blocks(1).await;
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Successful);
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO);
}

/// A wallet whose finish_offboard request never reached the server comes
/// back after the session expired: nothing was signed or broadcast, so
/// the wallet must fall back and prepare a fresh session.
#[tokio::test]
async fn offboard_recovers_expired_session_by_repreparing() {
	const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

	let ctx = TestContext::new("bark_sdk/offboard_recovers_expired_session_by_repreparing").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.funded(btc(10))
		.cfg(|c| c.offboard_session_timeout = SESSION_TIMEOUT)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(DropFirstFinishRequestProxy::new()).await;

	// Manual sync only: the daemon's periodic sync would retry the finish
	// before the session expires, sidestepping the recovery under test.
	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| {
			c.offboard_required_confirmations = 1;
			c.daemon_manual_sync = true;
		})
		.boarded(sat(800_000))
		.create().await;

	// The proxy swallows the finish request; the offboard parks for retry,
	// reporting the failure that parked it.
	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_all(address.clone()).await
		.expect_err("the proxy should have dropped the finish request");
	let err = format!("{err:#}");
	assert!(err.contains("dropped the finish_offboard request"), "unexpected error: {err}");

	// Wait until the server has expired the session, releasing its locks.
	tokio::time::sleep(2 * SESSION_TIMEOUT).await;

	// First sync: the finish retry is rejected (unknown session), the tx
	// is not on chain, so the wallet falls back to a fresh prepare.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(
		matches!(pending[0].progress, Progress::ReadyForOffboard { prior_txid: Some(..), .. }),
		"expected fallback to a fresh prepare: {:?}", pending[0].progress,
	);

	// Second sync: the fresh session goes through end to end.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(
		matches!(pending[0].progress, Progress::AwaitingConfirmations { .. }),
		"expected the fresh session to reach broadcast: {:?}", pending[0].progress,
	);

	ctx.generate_blocks(1).await;
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Successful);
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO);
}

/// A broadcast offboard tx can drop out of the mempool, e.g. when the
/// wallet's node restarts without persisting it. Within the lost-tx
/// grace period the wallet just re-broadcasts it on the next sync.
#[tokio::test]
async fn offboard_rebroadcasts_evicted_tx_within_grace_period() {
	let ctx = TestContext::new("bark_sdk/offboard_rebroadcasts_evicted_tx_within_grace_period").await;
	let srv = ctx.captaind("server")
		.funded(btc(10))
		// The server re-broadcasts committed offboard txs on this interval;
		// keep it out of the picture so the wallet's own re-broadcast is
		// the only way the tx can come back. The check interval may not
		// exceed the session timeout, so push that out too.
		.no_vtxo_pool()
		.cfg(|c| {
			c.offboard_session_timeout = Duration::from_secs(3600);
			c.offboard_check_interval = Duration::from_secs(3600);
		})
		.create().await;

	// Give the wallet its own node, so evicting the tx from its mempool
	// doesn't touch the server's chain source.
	let bark_node = ctx.new_bitcoind("bark_bitcoind").await;
	let node_url = bark_node.rpc_url();
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(move |c| {
			c.esplora_address = None;
			c.bitcoind_address = Some(node_url);
			// Not the cookie file: it changes when the node restarts, the
			// fixed rpcauth credentials don't.
			c.bitcoind_cookiefile = None;
			c.bitcoind_user = Some(constants::bitcoind::BITCOINRPC_TEST_USER.into());
			c.bitcoind_pass = Some(constants::bitcoind::BITCOINRPC_TEST_PASSWORD.into());
			c.offboard_required_confirmations = 1;
			c.daemon_manual_sync = true;
		})
		.boarded(sat(800_000))
		.create().await;

	let address = ctx.bitcoind().get_new_address();
	let txid = wallet.offboard_all(address.clone()).await.expect("offboard");
	// Make sure the tx relayed to the mining node before evicting it.
	ctx.bitcoind().await_transaction(txid).await;

	// Evict the broadcast tx from the wallet node's mempool.
	bark_node.restart_wiping_mempool().await;
	assert!(!bark_node.sync_client().get_raw_mempool().expect("mempool").contains(&txid));

	// Within the grace period (an hour by default), the next sync
	// re-broadcasts the tx instead of reporting the offboard lost.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert!(bark_node.sync_client().get_raw_mempool().expect("mempool").contains(&txid),
		"the wallet should have re-broadcast the evicted offboard tx");

	// From here the offboard settles like any other.
	ctx.generate_blocks(1).await;
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Successful);
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO);
}

/// Past the grace period, a vanished offboard tx is reported as lost:
/// the offboard parks with an error and keeps its vtxos locked — the
/// server still holds the signed tx and the forfeits become valid the
/// moment it confirms, so the inputs must not come back as spendable.
#[tokio::test]
async fn offboard_reports_lost_tx_after_grace_period() {
	let ctx = TestContext::new("bark_sdk/offboard_reports_lost_tx_after_grace_period").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.funded(btc(10))
		// Keep the server from re-broadcasting the evicted tx. The check
		// interval may not exceed the session timeout, so push that out too.
		.cfg(|c| {
			c.offboard_session_timeout = Duration::from_secs(3600);
			c.offboard_check_interval = Duration::from_secs(3600);
		})
		.create().await;

	// Give the wallet its own node, so evicting the tx from its mempool
	// doesn't touch the server's chain source.
	let bark_node = ctx.new_bitcoind("bark_bitcoind").await;
	let node_url = bark_node.rpc_url();
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(move |c| {
			c.esplora_address = None;
			c.bitcoind_address = Some(node_url);
			// Not the cookie file: it changes when the node restarts, the
			// fixed rpcauth credentials don't.
			c.bitcoind_cookiefile = None;
			c.bitcoind_user = Some(constants::bitcoind::BITCOINRPC_TEST_USER.into());
			c.bitcoind_pass = Some(constants::bitcoind::BITCOINRPC_TEST_PASSWORD.into());
			c.offboard_required_confirmations = 1;
			// Any tx missing from chain and mempool is immediately lost.
			c.offboard_lost_tx_grace_period_secs = 0;
			c.daemon_manual_sync = true;
		})
		.boarded(sat(800_000))
		.create().await;

	let address = ctx.bitcoind().get_new_address();
	let txid = wallet.offboard_all(address.clone()).await.expect("offboard");

	// While the tx sits in the mempool, syncs keep waiting patiently,
	// even with a zero grace period.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(matches!(pending[0].progress, Progress::AwaitingConfirmations { .. }));

	// Evict the broadcast tx from the wallet node's mempool. The grace
	// period has passed, so the next sync reports the offboard as lost:
	// no re-broadcast, and the checkpoint and its locked vtxos stay
	// exactly where they are.
	bark_node.restart_wiping_mempool().await;
	wallet.sync_pending_offboards().await.expect("sync pending offboards");

	assert!(!bark_node.sync_client().get_raw_mempool().expect("mempool").contains(&txid),
		"a lost tx must not be re-broadcast");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(matches!(pending[0].progress, Progress::AwaitingConfirmations { .. }));
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Pending);
	assert_eq!(wallet.balance().await.expect("balance").spendable, Amount::ZERO,
		"forfeited vtxos must never be released");
}

/// A wallet that loses the finish_offboard response and only comes back
/// after the server session expired cannot have the finish replayed. But
/// the server did broadcast the offboard tx, so the wallet must find it
/// on chain and adopt it — failing instead would strand the action while
/// its vtxos are already forfeited.
#[tokio::test]
async fn offboard_recovers_lost_finish_by_adopting_chain_tx() {
	const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

	let ctx = TestContext::new("bark_sdk/offboard_recovers_lost_finish_by_adopting_chain_tx").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.funded(btc(10))
		.cfg(|c| c.offboard_session_timeout = SESSION_TIMEOUT)
		.create().await;
	let proxy = srv.start_proxy_no_mailbox(LoseFirstFinishResponseProxy::new()).await;

	// Manual sync only: the daemon's periodic sync would retry the finish
	// before the session expires, sidestepping the recovery under test.
	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| {
			c.offboard_required_confirmations = 1;
			c.daemon_manual_sync = true;
		})
		.boarded(sat(800_000))
		.create().await;

	// The proxy eats the finish response; the offboard parks for retry,
	// reporting the failure that parked it.
	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_all(address.clone()).await
		.expect_err("the proxy should have lost the finish response");
	let err = format!("{err:#}");
	assert!(err.contains("lost the finish_offboard response"), "unexpected error: {err}");

	// Wait until the server has dropped the finished session, so the retry
	// cannot be replayed and has to recover through the chain.
	tokio::time::sleep(2 * SESSION_TIMEOUT).await;

	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(
		matches!(pending[0].progress, Progress::AwaitingConfirmations { .. }),
		"expected the offboard to adopt the broadcast tx: {:?}", pending[0].progress,
	);

	// From here the offboard settles like any other.
	ctx.generate_blocks(1).await;
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Successful);
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO);
}

/// A wallet whose finish request never reached the server re-prepares
/// once the server session is gone — but by then the server's fee rates
/// have moved and the fee rate committed at start is no longer
/// acceptable, so the fresh prepare can never succeed. The server only
/// rejects the request parameters after checking that the inputs are
/// still spendable, which proves the prior session died unfinished:
/// the wallet cancels the offboard and releases the vtxos instead of
/// retrying forever.
#[tokio::test]
async fn offboard_cancels_when_fees_change_after_lost_session() {
	let ctx = TestContext::new("bark_sdk/offboard_cancels_when_fees_change_after_lost_session").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(DropFirstFinishRequestProxy::new()).await;

	// Manual sync only, so the test controls each recovery step.
	let wallet = ctx.bark_sdk("bark", &proxy)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(sat(800_000))
		.create().await;

	// The proxy swallows the finish request; the offboard parks with the
	// unsigned session tx in its checkpoint.
	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_all(address.clone()).await
		.expect_err("the proxy should have dropped the finish request");
	let err = format!("{err:#}");
	assert!(err.contains("dropped the finish_offboard request"), "unexpected error: {err}");

	// Drop the server's regular fee rate. The restart wipes the fee
	// estimator's history (so the committed rate is no longer a recent
	// regular rate) and the pending offboard session (so the finish
	// retry cannot be replayed).
	srv.stop().await.expect("server stops");
	srv.config_mut().fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(2);
	srv.start().await.expect("server starts");
	// The restart moved the server to fresh ports; repoint the proxy.
	proxy.set_ark_upstream(srv.get_public_rpc().await);

	// First sync: the finish retry is rejected (unknown session), the tx
	// is not on chain, so the wallet falls back to a fresh prepare.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	let pending = wallet.pending_offboards().await.expect("pending offboards");
	assert_eq!(pending.len(), 1);
	assert!(
		matches!(pending[0].progress, Progress::ReadyForOffboard { prior_txid: Some(..), .. }),
		"expected fallback to a fresh prepare: {:?}", pending[0].progress,
	);

	// Second sync: the fresh prepare is rejected for the stale fee rate,
	// proving the inputs are still spendable on the server, so the
	// offboard is cancelled.
	wallet.sync_pending_offboards().await.expect("sync pending offboards");
	assert!(wallet.pending_offboards().await.expect("pending offboards").is_empty(),
		"the offboard should have been cancelled");
	assert_eq!(offboard_movement(&wallet).await.status, MovementStatus::Failed);
	assert_eq!(wallet.balance().await.expect("balance").spendable, sat(800_000),
		"the cancelled offboard should have released its vtxos");

	// And the vtxos are actually spendable: offboard them again at the
	// new fee rate and check the funds arrive onchain.
	wallet.offboard_all(address.clone()).await
		.expect("offboarding again at the new fee rate should succeed");
	ctx.generate_blocks(1).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&address), sat(799_756));
	assert_eq!(wallet.balance().await.expect("balance").spendable, sat(0));
}
