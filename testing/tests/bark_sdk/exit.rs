use std::time::Duration;

use bitcoincore_rpc::RpcApi;

use bark::exit::{ExitError, ExitState};
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::BitcoinRpcExt;
use server_log::ClaimBroadcast;

use ark_testing::{TestContext, btc, sat};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::util::FutureExt;

fn chain_tip(ctx: &TestContext) -> BlockHeight {
	let count = ctx.bitcoind().sync_client().get_block_count().expect("block count should succeed");
	BlockHeight::new(count as u32)
}

/// How many blocks past the current tip `height` is, zero if the tip is already there.
fn blocks_until(ctx: &TestContext, height: BlockHeight) -> u32 {
	height.checked_blocks_since(chain_tip(ctx)).unwrap_or(0)
}

/// A VTXO consumed outside the exit flow (e.g. spent via arkoor) has no exit entry; the
/// estimate must still reject it as already spent.
#[tokio::test]
async fn exit_estimate_rejects_spent_vtxo() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_spent_vtxo").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [boarded] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let spent_id = boarded.vtxo.id();

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");

	let err = sender.estimate_emergency_exit_fee(&[spent_id], None, None, None).await
		.expect_err("estimating a spent VTXO must fail");
	assert_eq!(err, ExitError::VtxoAlreadySpent { vtxo: spent_id });
}

/// An invalid fee margin is a typed error, not a panic — including one that scales the fee out
/// of range.
#[tokio::test]
async fn exit_estimate_rejects_invalid_fee_margin() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_invalid_fee_margin").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	for margin in [f64::NAN, f64::INFINITY, -0.5, f64::MAX] {
		let err = wallet.estimate_emergency_exit_fee(&[vtxo_id], None, None, Some(margin)).await
			.expect_err("an invalid fee margin must be rejected");
		assert!(matches!(err, ExitError::InvalidFeeMargin { .. }), "{:?}", err);
	}
}

/// A client exiting a board vtxo whose funding output the watchman already swept
/// must be told the exit cannot proceed, and must be left able to refresh the
/// vtxo instead, since the server still honours it offchain.
///
/// Exiting a board vtxo broadcasts its off-chain funding tx, which spends the
/// on-chain board output. Let the vtxo expire while the client is away and the
/// watchman sweeps that output, leaving the exit tx nothing to spend. Two ways
/// this must not fail: retrying the broadcast forever, and reporting `Claimed`
/// off the watchman's sweep tx, which `ExitClaimableState::progress` would adopt
/// as its own claim without checking who made it.
#[tokio::test]
async fn watchman_sweeps_funding_tx_during_exit() {
	let ctx = TestContext::new("bark_sdk/watchman_sweeps_funding_tx_during_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// fund the watchman so it can pay CPFP fees for anything it broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.boarded(sat(400_000))
		.create().await;

	let vtxos = wallet.vtxos().await.expect("listing vtxos");
	assert_eq!(vtxos.len(), 1, "the wallet should hold exactly one board vtxo");
	let vtxo = vtxos[0].id();
	let amount = vtxos[0].amount();
	let expiry = vtxos[0].vtxo.expiry_height();
	// The exit hangs off this on-chain output, which is what the watchman sweeps.
	let anchor = vtxos[0].vtxo.chain_anchor();

	// The client is away, so the watchman sweeps the anchor before the exit starts.
	let tip = ctx.generate_blocks(blocks_until(&ctx, expiry) + 1).await;
	wm.wait_for_sync_height(tip).await;
	assert!(tip >= expiry, "the vtxo should be expired, tip {} expiry {}", tip, expiry);

	wm.trigger_sweep().await;
	let claim = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	let swept = claim.vtxo_ids.iter().map(|v| v.to_point()).collect::<Vec<_>>();

	// Guard against a vacuous pass: no sweep of the needed output, no race tested.
	assert!(swept.contains(&anchor),
		"the watchman never swept the anchor {} of vtxo {}, so this test proves nothing; \
		swept {:?}", anchor, vtxo, swept,
	);

	wallet.exit_mgr().start_exit_for_entire_wallet().await.expect("starting the exit");

	// Confirm the sweep, but only just. Ending an exit can't be undone, so a spend a reorg could
	// still take back must not end one: the exit has to keep going until the sweep is buried.
	// Progressing repeatedly without new blocks keeps it one deep while the exit reaches the
	// state that does the checking, so this can't pass by never getting that far.
	ctx.generate_blocks(1).await;
	let mut shallow = None;
	for _ in 0..3 {
		wallet.sync_onchain().await.expect("onchain sync");
		let _ = wallet.progress_exits().await;
		shallow = wallet.exit_mgr().get_exit_vtxo(vtxo).await.map(|e| e.state().clone());
	}
	assert!(matches!(shallow, Some(ExitState::Processing(_))),
		"a sweep one block deep must leave the exit running, was {:?}", shallow,
	);

	// Give the client every chance to finish the exit and take the money.
	let mut claimable = false;
	let mut state = None;
	for _ in 0..15 {
		wallet.sync_onchain().await.expect("onchain sync");
		// The broadcast cannot succeed once the output is gone, which is the point.
		let _ = wallet.progress_exits().await;
		state = wallet.exit_mgr().get_exit_vtxo(vtxo).await.map(|e| e.state().clone());
		claimable |= matches!(state, Some(ExitState::Claimable(_)));
		ctx.generate_blocks(1).await;
	}

	assert!(matches!(state, Some(ExitState::VtxoSwept(_))),
		"exit of a swept vtxo must terminate as VtxoSwept, was {:?}", state,
	);
	// A swept output can never be claimed, so the exit must never have offered it.
	assert!(!claimable, "the exit of a swept vtxo must never become claimable");

	// The server still honours the swept vtxo offchain, so the dead exit must have left it
	// spendable for a refresh.
	let leftover = wallet.vtxos().await.expect("listing vtxos");
	assert_eq!(leftover.len(), 1, "exactly one vtxo should be left, got {:?}", leftover);
	assert_eq!(leftover[0].id(), vtxo,
		"the swept vtxo {} is still owed to the client offchain, so it must stay spendable", vtxo,
	);

	// Round output only lands once the funding tx confirms.
	let (refresh, _) = tokio::join!(
		wallet.refresh_vtxos(vec![vtxo]),
		srv.trigger_round(),
	);
	refresh.expect("refreshing the swept vtxo");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	let refreshed = wallet.vtxos().await.expect("listing vtxos");
	assert_eq!(refreshed.len(), 1, "the refresh should leave one vtxo, got {:?}", refreshed);
	assert_ne!(refreshed[0].id(), vtxo, "the refresh should have replaced the expired vtxo");
	assert!(refreshed[0].vtxo.expiry_height() > expiry,
		"the replacement should expire later than {}, got {}",
		expiry, refreshed[0].vtxo.expiry_height(),
	);
	assert_eq!(refreshed[0].amount(), amount,
		"the refresh should preserve the amount the server still owes",
	);
}

/// The same ending, reached the other way: the client confirms the top of its
/// exit chain before expiry, so the watchman is not sweeping an untouched vtxo
/// but racing a live exit.
///
/// With part of the chain on chain the watchman knows the next tx, so it acts
/// as watchtower and broadcasts the exit onward rather than sweeping it. Once
/// the chain matures it takes the output, and the client's exit dies on an
/// input that is gone. That surfaces as `MissingOrSpentInputs`, which the
/// progress code would otherwise read as "ask for a fresh CPFP" and retry.
///
/// The exit must terminate and leave the vtxo refreshable, as in the funding-tx
/// case. Driving blocks in a loop is load-bearing: the watchman only claims
/// after it has progressed the chain, so a single sweep trigger is too early.
#[tokio::test]
async fn watchman_sweeps_vtxo_chain_during_exit() {
	let ctx = TestContext::new("bark_sdk/watchman_sweeps_vtxo_chain_during_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// fund the watchman so it can pay CPFP fees for anything it broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	// the receiver needs a vtxo with a chain under it, so the sender sends it an arkoor.
	let sender = ctx.bark_sdk("bark1", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(1_000_000))
		.create().await;
	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");
	// The receiver only learns about the arkoor once it drains its mailbox.
	receiver.maintenance().await.expect("receiver maintenance");

	let vtxos = receiver.vtxos().await.expect("listing vtxos");
	assert_eq!(vtxos.len(), 1, "the receiver should hold exactly the received vtxo");
	let vtxo = vtxos[0].id();
	let amount = vtxos[0].amount();
	let expiry = vtxos[0].vtxo.expiry_height();
	let anchor = vtxos[0].vtxo.chain_anchor();

	// Start the exit one block before expiry so that only the top of the chain
	// can confirm in time. Each exit tx is broadcast only once its parent
	// confirms, so one progress plus one block leaves the chain confirmed exactly
	// one tx deep with the rest unbroadcast.
	let tip = ctx.generate_blocks(blocks_until(&ctx, expiry) - 1).await;
	assert!(tip < expiry, "should not have expired the vtxo yet, tip {}", tip);
	receiver.exit_mgr().start_exit_for_entire_wallet().await.expect("starting the exit");
	receiver.progress_exits().await.expect("progressing the exit");
	ctx.generate_blocks(1).await;

	// Record the chain while the exit is live: a finished exit no longer lists its txs.
	let exit = receiver.exit_mgr().get_exit_vtxo(vtxo).await
		.expect("the exit we started should be tracked");
	let chain = exit.txids().expect("a live exit lists its txs").to_vec();
	let confirmed = chain.iter().filter(|txid| {
		let status = ctx.bitcoind().sync_client().tx_status(**txid)
			.expect("tx status should succeed");
		status.is_confirmed()
	}).count();
	assert!(confirmed > 0 && confirmed < chain.len(),
		"the exit chain should be partially on chain, {}/{} txs confirmed",
		confirmed, chain.len(),
	);

	// Expiring the vtxo unlocks the sweep, the rest of the chain still unbroadcast. The watchman
	// won't act on the confirmed top of the chain until `vtxo_exit_delta` has passed since the
	// block it confirmed in, so clear that too.
	let sweepable = expiry + srv.config().vtxo_exit_delta;
	let tip = ctx.generate_blocks(blocks_until(&ctx, sweepable) + 1).await;
	wm.wait_for_sync_height(tip).await;
	assert!(tip >= expiry, "the vtxo should be expired, tip {} expiry {}", tip, expiry);

	let mut swept = Vec::new();
	for _ in 0..15 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		while let Ok(claim) = log_claim.try_recv() {
			swept.extend(claim.vtxo_ids.iter().map(|v| v.to_point()));
		}
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
	}

	// Guard against a vacuous pass: the sweep has to have taken an output of the
	// half-broadcast chain, or the exit was never broken.
	assert!(swept.iter().any(|p| *p == anchor || chain.contains(&p.txid)),
		"the watchman never swept the chain {:?} or anchor {} of exiting vtxo {}, so this \
		test proves nothing; swept {:?}", chain, anchor, vtxo, swept,
	);

	// Give the client every chance to finish the exit and take the money.
	let mut claimable = false;
	let mut state = None;
	for _ in 0..15 {
		receiver.sync_onchain().await.expect("onchain sync");
		// The broadcast cannot succeed once the output is gone, which is the point.
		let _ = receiver.progress_exits().await;
		state = receiver.exit_mgr().get_exit_vtxo(vtxo).await.map(|e| e.state().clone());
		claimable |= matches!(state, Some(ExitState::Claimable(_)));
		ctx.generate_blocks(1).await;
	}

	assert!(matches!(state, Some(ExitState::VtxoSwept(_))),
		"exit whose chain was swept must terminate as VtxoSwept, was {:?}", state,
	);
	// A swept output can never be claimed, so the exit must never have offered it.
	assert!(!claimable, "the exit of a swept vtxo must never become claimable");

	// The server still honours the swept vtxo offchain, so the dead exit must have left it
	// spendable for a refresh.
	let leftover = receiver.vtxos().await.expect("listing vtxos");
	assert_eq!(leftover.len(), 1, "exactly one vtxo should be left, got {:?}", leftover);
	assert_eq!(leftover[0].id(), vtxo,
		"the swept vtxo {} is still owed to the client offchain, so it must stay spendable", vtxo,
	);

	// Round output only lands once the funding tx confirms.
	let (refresh, _) = tokio::join!(
		receiver.refresh_vtxos(vec![vtxo]),
		srv.trigger_round(),
	);
	refresh.expect("refreshing the swept vtxo");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	receiver.sync().await;

	let refreshed = receiver.vtxos().await.expect("listing vtxos");
	assert_eq!(refreshed.len(), 1, "the refresh should leave one vtxo, got {:?}", refreshed);
	assert_ne!(refreshed[0].id(), vtxo, "the refresh should have replaced the expired vtxo");
	assert!(refreshed[0].vtxo.expiry_height() > expiry,
		"the replacement should expire later than {}, got {}",
		expiry, refreshed[0].vtxo.expiry_height(),
	);
	assert_eq!(refreshed[0].amount(), amount,
		"the refresh should preserve the amount the server still owes",
	);
}
