//! Tests for [bark::Balance]: every VTXO is counted once and in the right field.

use std::time::Duration;

use bitcoin::Amount;
use bitcoin_ext::BlockDelta;
use server_log::RoundFinished;

use ark_testing::{btc, TestContext};
use ark_testing::balance::assert_balance_consistent;
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::Captaind;
use ark_testing::util::{FutureExt, poll_interval};

const AMOUNT: Amount = Amount::from_sat(800_000);

/// Sync until `done` holds, mining a block per attempt, with the balance
/// checked for consistency on every attempt.
async fn sync_until(
	ctx: &TestContext,
	wallet: &bark::Wallet,
	done: impl Fn(&bark::Balance) -> bool,
) -> bark::Balance {
	for _ in 0..30 {
		wallet.chain().invalidate_caches().await;
		let balance = assert_balance_consistent(wallet, true).await;
		if done(&balance) {
			return balance;
		}
		ctx.generate_blocks(1).await;
		tokio::time::sleep(poll_interval()).await;
	}
	panic!("balance did not reach the expected state: {:?}", wallet.balance().await);
}

/// Board through the SDK with the background daemon's own syncing disabled, so
/// every state transition in the test is driven by the test itself.
async fn boarded_wallet(ctx: &TestContext, srv: &Captaind) -> bark::Wallet {
	ctx.bark_sdk("bark", srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.boarded(AMOUNT)
		.create().await
}

/// The inputs of an interactive round are pending in round from the moment the
/// round finishes until its funding tx is confirmed and the new VTXOs replace
/// them as spendable. They are never spendable and pending at the same time.
#[tokio::test]
async fn balance_follows_interactive_round() {
	let ctx = TestContext::new("bark_sdk/balance_follows_interactive_round").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let wallet = boarded_wallet(&ctx, &srv).await;

	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	let (res, _) = tokio::join!(
		wallet.refresh_vtxos(vtxos.iter()),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	res.expect("refresh").expect("a round was joined");

	// The round finished but its funding tx is not confirmed yet.
	let balance = assert_balance_consistent(&wallet, false).await;
	assert_eq!(balance.pending_in_round, AMOUNT, "unconfirmed round: {balance:?}");
	assert_eq!(balance.spendable, Amount::ZERO, "unconfirmed round: {balance:?}");

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let balance = sync_until(&ctx, &wallet, |b| b.pending_in_round == Amount::ZERO).await;
	assert_eq!(balance.spendable, AMOUNT, "confirmed round: {balance:?}");
}

/// A delegated participation the server has not picked up yet does not lock
/// its inputs: they stay spendable and nothing is pending in round, while the
/// round subsystem still reports the requested outputs. Once the server has
/// issued the round and its funding tx is in the mempool, a sync locks the
/// inputs and they are pending in round until the round confirms and the new
/// VTXOs take their place.
#[tokio::test]
async fn balance_follows_delegated_round() {
	let ctx = TestContext::new("bark_sdk/balance_follows_delegated_round").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let wallet = boarded_wallet(&ctx, &srv).await;

	let ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	wallet.refresh_vtxos_delegated(ids.clone()).await
		.expect("submit the delegated participation")
		.expect("a participation was submitted");

	let balance = assert_balance_consistent(&wallet, true).await;
	assert_eq!(balance.spendable, AMOUNT, "pending delegated round: {balance:?}");
	assert_eq!(balance.pending_in_round, Amount::ZERO, "pending delegated round: {balance:?}");
	assert!(wallet.pending_round_balance().await.expect("pending round balance") > Amount::ZERO,
		"the round subsystem still reports the requested outputs",
	);

	// The server issues the round; once its funding tx reaches our mempool a
	// sync locks the inputs.
	let mut log_finished = srv.subscribe_log::<RoundFinished>();
	srv.trigger_round().await;
	let finished = log_finished.recv().wait(Duration::from_secs(30)).await
		.expect("the round must finish");
	ctx.await_transaction(finished.txid).await;
	wallet.chain().invalidate_caches().await;

	let balance = assert_balance_consistent(&wallet, true).await;
	assert_eq!(balance.pending_in_round, AMOUNT, "issued delegated round: {balance:?}");
	assert_eq!(balance.spendable, Amount::ZERO, "issued delegated round: {balance:?}");

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let balance = sync_until(&ctx, &wallet, |b| b.pending_in_round == Amount::ZERO).await;
	assert_eq!(balance.spendable, AMOUNT, "confirmed delegated round: {balance:?}");
	assert!(wallet.pending_round_states().await.expect("round states").is_empty(),
		"the delegated participation must be finished",
	);
	let new_ids = wallet.spendable_vtxos().await.expect("list vtxos")
		.into_iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(new_ids.iter().all(|id| !ids.contains(id)),
		"the inputs must be replaced by the round outputs: {ids:?} -> {new_ids:?}",
	);
}

/// A VTXO that has expired is no longer spendable: the server refuses it as
/// an input until a round has refreshed it. Nothing holds it, so it is reported
/// as needing a refresh and still counts towards the total. Once maintenance
/// has refreshed it, the replacement is spendable again.
#[tokio::test]
async fn balance_sets_aside_expired_vtxos() {
	const VTXO_LIFETIME: u16 = 144;

	let ctx = TestContext::new("bark_sdk/balance_sets_aside_expired_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|cfg| cfg.vtxo_lifetime = BlockDelta::new(VTXO_LIFETIME))
		.create().await;
	let wallet = boarded_wallet(&ctx, &srv).await;

	let balance = assert_balance_consistent(&wallet, true).await;
	assert_eq!(balance.spendable, AMOUNT, "fresh board: {balance:?}");
	assert_eq!(balance.needs_refresh, Amount::ZERO, "fresh board: {balance:?}");

	ctx.generate_blocks(VTXO_LIFETIME as u32).await;
	wallet.chain().invalidate_caches().await;
	let balance = assert_balance_consistent(&wallet, true).await;
	assert_eq!(balance.needs_refresh, AMOUNT, "expired: {balance:?}");
	assert_eq!(balance.spendable, Amount::ZERO, "expired: {balance:?}");
	assert_eq!(balance.total(), AMOUNT, "expired: {balance:?}");
	assert!(!balance.has_pending(), "nothing holds an expired VTXO: {balance:?}");

	// Maintenance refreshes it in the next round.
	let (res, _) = tokio::join!(
		wallet.maintenance_refresh(),
		async {
			tokio::time::sleep(Duration::from_secs(2)).await;
			srv.trigger_round().await;
		},
	);
	res.expect("maintenance refresh");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let balance = sync_until(&ctx, &wallet, |b| b.pending_in_round == Amount::ZERO).await;
	assert_eq!(balance.spendable, AMOUNT, "refreshed: {balance:?}");
	assert_eq!(balance.needs_refresh, Amount::ZERO, "refreshed: {balance:?}");
}
