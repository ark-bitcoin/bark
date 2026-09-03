
use std::time::Duration;

use log::info;
use serde_json::json;

use bitcoin_ext::rpc::RpcApi;
use server_log::{NurseryTxConfirmed, NurseryTxMissedTarget, RoundFinished};

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::FutureExt;

#[tokio::test]
async fn nursery_confirms_round_funding_tx() {
	let ctx = TestContext::new("server/nursery_confirms_round_funding_tx").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	let mut log_confirmed = srv.subscribe_log::<NurseryTxConfirmed>();

	ctx.refresh_all(&srv, &[&bark]).await;
	let funding_txid = log_round_finished.recv().wait(Duration::from_secs(30)).await
		.expect("timed out waiting for round to finish").txid;
	info!("Round finished with funding txid: {}", funding_txid);

	srv.bitcoind().await_transaction(funding_txid).await;
	ctx.generate_blocks(1).await;

	// The nursery should register the confirmation of the funding tx.
	loop {
		let confirmed = log_confirmed.recv().wait(Duration::from_secs(30)).await
			.expect("timed out waiting for nursery to confirm the funding tx");
		if confirmed.txid == funding_txid {
			break;
		}
	}

	// A confirmed tx can't be abandoned: it has to stay active so the
	// nursery can follow it up if a reorg evicts its confirmation.
	let err = srv.abandon(funding_txid).await.expect_err("abandon of confirmed tx should fail");
	assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn nursery_warns_until_tx_is_abandoned() {
	let ctx = TestContext::new("server/nursery_warns_until_tx_is_abandoned").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		// warn quickly after the round tx fails to confirm
		cfg.nursery_confirm_target_blocks = 2;
		// No watchman top-up: it would spend the round change and get
		// stuck alongside it, warning on its own.
		cfg.watchman_min_balance = sat(0);
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	let mut log_missed = srv.subscribe_log::<NurseryTxMissedTarget>();

	ctx.refresh_all(&srv, &[&bark]).await;
	let funding_txid = log_round_finished.recv().wait(Duration::from_secs(30)).await
		.expect("timed out waiting for round to finish").txid;
	info!("Round finished with funding txid: {}", funding_txid);

	// Deprioritize the funding tx on the mining node (the RPC is
	// node-local) so it misses its target.
	ctx.bitcoind().await_transaction(funding_txid).await;
	ctx.bitcoind().sync_client().call::<bool>("prioritisetransaction", &[
		json!(funding_txid.to_string()), json!(0), json!(-10_000_000_000i64),
	]).expect("prioritisetransaction failed");

	// The target is two blocks after broadcast, so with three new blocks
	// the tx is overdue on the last two: the operator is warned once per
	// block until they intervene.
	ctx.generate_blocks(3).await;
	for _ in 0..2 {
		let missed = log_missed.recv().wait(Duration::from_secs(30)).await
			.expect("timed out waiting for missed-target warning");
		assert_eq!(missed.txid, funding_txid);
		assert!(missed.current_height >= missed.confirm_target_height);
	}

	// The operator abandons the tx, which silences the warning.
	srv.abandon(funding_txid).await.expect("abandon failed");

	// Doing so twice fails: the tx is no longer active in the nursery.
	let err = srv.abandon(funding_txid).await.expect_err("second abandon should fail");
	assert_eq!(err.code(), tonic::Code::NotFound);

	// New blocks no longer trigger warnings for the abandoned tx.
	ctx.generate_blocks(2).await;
	let res = log_missed.recv().try_wait(Duration::from_secs(3)).await;
	assert!(res.is_err(), "got missed-target warning after the tx was abandoned");
}

/// The operator can inspect the nursery through ListNurseryTxs: the
/// default report shows what still needs follow-up, the full one keeps
/// confirmed txs.
#[tokio::test]
async fn nursery_reports_tracked_txs() {
	let ctx = TestContext::new("server/nursery_reports_tracked_txs").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.refresh_all(&srv, &[&bark]).await;
	let funding_txid = log_round_finished.recv().wait(Duration::from_secs(30)).await
		.expect("timed out waiting for round to finish").txid;
	srv.bitcoind().await_transaction(funding_txid).await;

	// The report shows the unconfirmed round tx.
	let txs = srv.list_nursery_txs(false, false).await;
	let entry = txs.iter().find(|t| t.txid == funding_txid.to_string())
		.expect("round tx missing from nursery report");
	assert_eq!(entry.kind, "round");
	assert!(entry.in_mempool);
	assert!(entry.confirmed_at_height.is_none());

	// Everything confirms; the confirmed tx leaves the default report
	// but stays in the full one.
	let mut log_confirmed = srv.subscribe_log::<NurseryTxConfirmed>();
	ctx.await_transaction(funding_txid).await;
	ctx.generate_blocks(1).await;
	loop {
		let confirmed = log_confirmed.recv().wait(Duration::from_secs(30)).await
			.expect("timed out waiting for nursery confirmation");
		if confirmed.txid == funding_txid {
			break;
		}
	}
	let txs = srv.list_nursery_txs(false, false).await;
	assert!(!txs.iter().any(|t| t.txid == funding_txid.to_string()),
		"confirmed tx still in the default report");
	let txs = srv.list_nursery_txs(true, false).await;
	let entry = txs.iter().find(|t| t.txid == funding_txid.to_string())
		.expect("confirmed tx missing from full report");
	assert!(entry.confirmed_at_height.is_some());
}

/// Every wallet-funded tx keeps a change output, so a stuck one can be
/// CPFP bumped later.
#[tokio::test]
async fn wallet_txs_keep_a_change_output() {
	let ctx = TestContext::new("server/wallet_txs_keep_a_change_output").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let issuance_txid = srv.vtxopool_last_issuance().expect("pool issued a funding tx");

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.refresh_all(&srv, &[&bark]).await;
	let funding_txid = log_round_finished.recv().wait(Duration::from_secs(30)).await
		.expect("timed out waiting for the round").txid;

	for txid in [funding_txid, issuance_txid] {
		let tx = srv.bitcoind().await_transaction(txid).await;
		assert!(tx.output.len() >= 2, "tx {} must keep a change output", txid);
	}
}
