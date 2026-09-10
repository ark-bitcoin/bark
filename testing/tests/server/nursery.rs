
use std::time::Duration;

use bitcoin::{
	Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Weight, Witness,
};
use bitcoin::absolute::LockTime;
use log::info;
use serde_json::json;

use bitcoin_ext::FeeRateExt;
use bitcoin_ext::rpc::RpcApi;
use server::bitcoind::MempoolEntry;
use server_log::{NurseryTxConfirmed, NurseryTxMissedTarget, RoundFinished};

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::Captaind;
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
			assert_eq!(confirmed.kind, "round");
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
		assert_eq!(missed.kind, "round");
		assert!(missed.current_height >= missed.confirm_target_height);
		assert!(missed.chunk_fee_rate.is_some(), "feerate of an in-mempool tx is unknown");
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
	assert_eq!(entry.chunk_fee_rate_kwu, Some(chunk_fee_rate_kwu(&srv, funding_txid)));

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
	assert!(!entry.in_mempool);
	assert!(entry.chunk_fee_rate_kwu.is_none());
}

/// The reported feerate follows the chunk bitcoind mines the tx in. A
/// low-fee child leaves it alone, and a high-fee grandchild raises it,
/// which the ancestor feerate of the tx and its children never shows.
#[tokio::test]
async fn nursery_reports_chunk_fee_rate() {
	let ctx = TestContext::new("server/nursery_reports_chunk_fee_rate").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	// Offboard to the central bitcoind's wallet so the test can spend the output.
	let address = ctx.bitcoind().get_new_address();
	let offboard_txid = bark.offboard_all(&address).await.offboard_txid;
	let offboard_tx = srv.bitcoind().await_transaction(offboard_txid).await;
	let alone = nursery_chunk_fee_rate_kwu(&srv, offboard_txid).await;
	assert_eq!(alone, chunk_fee_rate_kwu(&srv, offboard_txid));

	// A child at a lower feerate than the offboard tx forms its own chunk,
	// so the report doesn't move.
	let vout = offboard_tx.output.iter()
		.position(|o| o.script_pubkey == address.script_pubkey())
		.expect("offboard output missing") as u32;
	let child_txid = spend_from_wallet(&ctx, OutPoint::new(offboard_txid, vout), sat(200)).await;
	srv.bitcoind().await_transaction(child_txid).await;
	let with_child = nursery_chunk_fee_rate_kwu(&srv, offboard_txid).await;
	assert_eq!(with_child, alone, "a low-fee child must not change the chunk feerate");

	// A grandchild at a much higher feerate pulls the whole chain into one
	// chunk, so the report rises to what the grandchild pays for it.
	let grandchild_txid = spend_from_wallet(&ctx, OutPoint::new(child_txid, 0), sat(50_000)).await;
	srv.bitcoind().await_transaction(grandchild_txid).await;
	let with_grandchild = nursery_chunk_fee_rate_kwu(&srv, offboard_txid).await;
	assert!(with_grandchild > alone, "grandchild at a higher feerate must raise the chunk feerate");
	assert_eq!(with_grandchild, chunk_fee_rate_kwu(&srv, offboard_txid));

	// The ancestor feerate of the tx and of its child are both below the
	// chunk feerate, so a report based on them would have missed the bump.
	let child_entry = srv.bitcoind().sync_client().get_mempool_entry(&child_txid)
		.expect("server bitcoind has the child");
	let child_ancestor_kwu = FeeRate::from_amount_and_weight_ceil(
		child_entry.fees.ancestor, Weight::from_vb(child_entry.ancestor_size).unwrap(),
	).unwrap().to_sat_per_kwu();
	assert!(with_grandchild > child_ancestor_kwu);
}

/// Spend the outpoint, owned by the central bitcoind's wallet, to a fresh
/// address of that wallet, paying the given fee.
async fn spend_from_wallet(ctx: &TestContext, outpoint: OutPoint, fee: Amount) -> Txid {
	let client = ctx.bitcoind().sync_client();
	let prev_tx = client.get_raw_transaction(&outpoint.txid, None)
		.expect("get_raw_transaction failed");
	let prev_out = &prev_tx.output[outpoint.vout as usize];
	let unsigned = Transaction {
		version: prev_tx.version,
		lock_time: LockTime::ZERO,
		input: vec![TxIn {
			previous_output: outpoint,
			script_sig: ScriptBuf::new(),
			sequence: Sequence::ZERO,
			witness: Witness::new(),
		}],
		output: vec![TxOut {
			value: prev_out.value - fee,
			script_pubkey: ctx.bitcoind().get_new_address().script_pubkey(),
		}],
	};
	let signed = client.sign_raw_transaction_with_wallet(&unsigned, None, None)
		.expect("sign_raw_transaction_with_wallet failed")
		.transaction().expect("failed to deserialize signed tx");
	client.send_raw_transaction(&signed).expect("send_raw_transaction failed")
}

/// The chunk feerate the nursery report shows for an in-mempool tx.
async fn nursery_chunk_fee_rate_kwu(srv: &Captaind, txid: Txid) -> u64 {
	let txs = srv.list_nursery_txs(false, false).await;
	let entry = txs.iter().find(|t| t.txid == txid.to_string())
		.expect("tx missing from nursery report");
	assert!(entry.in_mempool);
	entry.chunk_fee_rate_kwu.expect("feerate of an in-mempool tx is unknown")
}

/// The chunk feerate the server's bitcoind reports for a mempool tx, in sat/kwu.
fn chunk_fee_rate_kwu(srv: &Captaind, txid: Txid) -> u64 {
	let entry: MempoolEntry = srv.bitcoind().sync_client()
		.call("getmempoolentry", &[json!(txid)])
		.expect("server bitcoind has the tx");
	entry.fees.chunk.div_by_weight_floor(Weight::from_wu(entry.chunk_weight)).unwrap().to_sat_per_kwu()
}

/// Every wallet-funded tx keeps a change output, so a stuck one can be
/// CPFP bumped later.
#[tokio::test]
async fn wallet_txs_keep_a_change_output() {
	let ctx = TestContext::new("server/wallet_txs_keep_a_change_output").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;

	// Each tx may spend the change of the one before it, so check every
	// tx right after it is broadcast.
	srv.wait_for_vtxopool(&ctx).await;
	let issuance_txid = srv.vtxopool_last_issuance().expect("pool issued a funding tx");
	assert_has_wallet_change(&srv, issuance_txid).await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	ctx.refresh_all(&srv, &[&bark]).await;
	let funding_txid = log_round_finished.recv().wait(Duration::from_secs(30)).await
		.expect("timed out waiting for the round").txid;
	assert_has_wallet_change(&srv, funding_txid).await;

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark.sync().await;
	let address = ctx.bitcoind().get_new_address();
	let offboard_txid = bark.offboard_all(&address).await.offboard_txid;
	assert_has_wallet_change(&srv, offboard_txid).await;
}

/// Asserts that one of the outputs of the tx is a UTXO of the rounds
/// wallet, i.e. that the tx kept a change output.
async fn assert_has_wallet_change(srv: &Captaind, txid: Txid) {
	let rounds = srv.wallet_status().await.rounds;
	let has_change = rounds.confirmed_utxos.iter()
		.chain(rounds.unconfirmed_utxos.iter())
		.any(|utxo| utxo.txid == txid);
	assert!(has_change, "tx {} must keep a change output", txid);
}
