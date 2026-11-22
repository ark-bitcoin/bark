
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use parking_lot::Mutex;
use bitcoincore_rpc::RpcApi;

use ark::lightning::PaymentHash;
use bark::exit::ExitState;
use bark_json::primitives::VtxoStateInfo;
use bitcoin::{
	absolute, transaction, Address, Amount, FeeRate, OutPoint, Sequence, Transaction, TxIn, TxOut,
	Txid, Weight,
};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoin_ext::{BlockDelta, BlockHeight, TxStatus};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use server::database::Db;
use server::vtxopool::VtxoTarget;
use server_log::{
	BroadcastingDependentTx, ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure, RoundFinished,
	ProgressBroadcast, ProgressCpfpFailure, FrontierReindexComplete, FrontierRepairedSpend,
};

use ark_testing::{TestContext, btc, require_bark_version, require_bitcoind_chain_source, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::SlogHandler;
use ark_testing::daemon::watchmand::Watchmand;
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};
use ark_testing::util::FutureExt;

/// Struct that captures all watchman related failures so that we
/// can ensure our tests don't produce any
#[derive(Clone, Default)]
struct WatchmanFailureCollector {
	failures: Arc<Mutex<Vec<String>>>,
}

impl SlogHandler for WatchmanFailureCollector {
	fn process_slog(&mut self, log: &server_log::ParsedRecord) -> bool {
		if log.is::<ClaimChunkBroadcastFailure>()
			|| log.is::<ClaimBroadcastFailure>()
			|| log.is::<ProgressCpfpFailure>()
		{
			warn!("Captured watchman failure log: {:?}", log);
			self.failures.lock().push(format!("{:?}", log));
		}

		false
	}
}

impl WatchmanFailureCollector {
	fn assert_empty(&self) {
		let guard = self.failures.lock();
		if !guard.is_empty() {
			for msg in guard.iter() {
				error!("Watchman failure log: {}", msg);
			}
			panic!("watchman had failures");
		}
	}
}


#[tokio::test]
async fn watchman_sweeps_boards() {
	let ctx = TestContext::new("server/watchman_sweeps_boards").await;
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(10)).cfg(|cfg| {
		// Short, so the boards expire after few blocks.
		cfg.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		// The watchman only acts when the test triggers it.
		cfg.watchman.reaction_interval = Duration::from_secs(3600);
		cfg.watchman.sweep_interval = Duration::from_secs(3600);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let wallet = ctx.bark_sdk("bark", &srv).funded(btc(1)).create().await;

	// Boarded in the same block, so both expire at the same height.
	let [refreshed, kept] = ctx.board(&wallet, &[sat(100_000), sat(110_000)]).await
		.try_into().unwrap();
	let boards = [
		wallet.get_full_vtxo(refreshed.id()).await.unwrap().chain_anchor(),
		wallet.get_full_vtxo(kept.id()).await.unwrap().chain_anchor(),
	];
	let expiry = refreshed.expiry_height();
	assert_eq!(kept.expiry_height(), expiry);

	// One vtxo moves into a round. Its board utxo stays onchain until it expires.
	let mut finished = srv.subscribe_log::<RoundFinished>();
	wallet.refresh_vtxos_delegated([refreshed.id()]).await.unwrap();
	srv.trigger_round().await;
	finished.recv().await.unwrap();

	// When the boards expire, the watchman sweeps both board utxos into the rounds
	// wallet. The round's vtxos expire later, so it leaves them.
	let mut claims = wm.subscribe_log::<ClaimBroadcast>();
	let height = u32::try_from(ctx.bitcoind().get_block_count().await).unwrap();
	ctx.bitcoind().generate(expiry.to_u32().checked_sub(height).unwrap()).await;
	wm.wait_for_sync_height(expiry).await;
	srv.wait_for_sync_height(expiry).await;
	let rounds_balance = srv.wallet_status().await.rounds.total_balance;
	wm.trigger_sweep().await;
	let sweep = claims.recv().await.unwrap();
	let swept = sweep.vtxo_ids.iter().map(|id| id.to_point()).collect::<HashSet<_>>();
	assert_eq!(swept, HashSet::from(boards), "{sweep:?}");
	assert_eq!(sweep.total_input_value, sat(210_000));
	// The sweep tx pays 1_439 sat in fees.
	assert_eq!(sweep.total_output_value, sat(208_561));
	ctx.bitcoind().await_transaction(sweep.txid).await;
	ctx.bitcoind().generate(1).await;
	let tip = BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
	srv.wait_for_sync_height(tip).await;
	assert_eq!(srv.wallet_status().await.rounds.total_balance, rounds_balance + sweep.total_output_value);
	failures.assert_empty();
}

#[tokio::test]
async fn watchman_sweeps_round_vtxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_round_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;

	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	// Create round vtxos by doing a payment
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;

	// Wait for round to be confirmed so watchman can track the vtxos
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;

	// Wait for vtxos to expire (144 blocks from their creation)
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired server-owned vtxos from the round
	// (checkpoint vtxos or other intermediate vtxos created during round processing)
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Round vtxo sweep: {:#?}", msg);
	assert_eq!(3, msg.vtxo_ids.len());
	assert_eq!(800_000, msg.total_input_value.to_sat());
	assert_eq!(798_029, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_sender_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_sender_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	bark1.send_oor(bark2.address().await, sat(50_000)).await;

	bark1.sync().await;
	bark2.sync().await;

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
	bark1.claim_all_exits(bark1.get_onchain_address().await).await;

	// Wait for the HTLC vtxos to expire
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired HTLC vtxos
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("arkoor vtxo sweep: {:#?}", msg);
	// 1 boards and 1 change
	assert_eq!(2, msg.vtxo_ids.len());
	assert_eq!(350_000, msg.total_input_value.to_sat());
	assert_eq!(348_561, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_receiver_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_receiver_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	bark1.send_oor(bark2.address().await, sat(50_000)).await;

	bark1.sync().await;
	bark2.sync().await;

	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;
	bark2.claim_all_exits(bark2.get_onchain_address().await).await;

	// Wait for the HTLC vtxos to expire
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired HTLC vtxos
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(5000).await.expect("no claim log");
	failures.assert_empty();
	println!("arkoor vtxo sweep: {:#?}", msg);
	// only change, split in two pieces; these are the checkpoint vtxos of the
	// pieces, not the change vtxos bark1 holds
	assert_eq!(2, msg.vtxo_ids.len());
	assert_eq!(250_000, msg.total_input_value.to_sat());
	assert_eq!(248_561, msg.total_output_value.to_sat());
}

/// The watchman correctly rebuilds a frontier with erased state through the
/// ReindexFrontier admin RPC.
///
/// The watchman first processes a unilateral exit correctly. We then stop it,
/// erase parts of what it learned directly in the database, and restart it:
/// the block table is still current, so nothing gets replayed and the
/// in-memory frontier loads the broken state. A reorg the watchman never
/// sees leaves a stale confirmation height behind as well. The reindex
/// must repair all of it.
#[tokio::test]
async fn watchman_reindexes_frontier() {
	let ctx = TestContext::new("server/watchman_reindexes_frontier").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = 144.into();
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	bark1.send_oor(bark2.address().await, sat(50_000)).await;

	bark1.sync().await;
	bark2.sync().await;

	// bark1 exits its change vtxo unilaterally and claims it, so the watchman
	// tracks a whole exit chain: the spent board vtxo, the spent change
	// checkpoint, and bark1's claimed change vtxo, plus the remaining
	// unspent payment checkpoint.
	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
	bark1.claim_all_exits(bark1.get_onchain_address().await).await;

	// Wait until the watchman has registered all three on-chain spends of
	// the exit chain (bark1's claim tx may take a block or two to propagate
	// to the mining node).
	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let mut attempts = 0;
	loop {
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
		let nb_spent = db.read(async |t| {
			let row = t.query_one(
				"SELECT COUNT(*) FROM vtxo WHERE onchain_spent_height IS NOT NULL", &[],
			).await?;
			Ok(row.get::<_, i64>(0))
		}).await.unwrap();
		if nb_spent >= 3 {
			break;
		}
		attempts += 1;
		assert!(attempts < 20, "exit chain spends never fully registered");
	}
	failures.assert_empty();

	// bark3 boards, so the frontier holds a confirmed board vtxo whose
	// block we can invalidate below. The frontier entry is the board output
	// itself, on the funding tx.
	let bark3 = ctx.bark("bark3", &srv).funded(sat(1_000_000)).create().await;
	let board3_txid = bark3.board(sat(100_000)).await.funding_tx.txid;
	let tip = ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark3.sync().await;
	wm.wait_for_sync_height(tip).await;
	let (board3_id, board3_height) = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo_id, confirmed_height FROM vtxo \
			WHERE vtxo_txid = $1 AND frontier_at IS NOT NULL",
			&[&board3_txid.to_string()],
		).await?;
		let height = row.get::<_, Option<i32>>(1).expect("board vtxo not confirmed");
		Ok((row.get::<_, String>(0), BlockHeight::from(height as u32)))
	}).await.unwrap();

	// Stop the watchman and erase parts of what it learned.
	wm.stop().await.unwrap();

	// Reorg bark3's board tx back into the mempool of the watchman's own
	// bitcoind: invalidate its block and mine empty blocks in its place, so
	// the chain doesn't get shorter. We forget the invalidated blocks from
	// the watchman's block index, so it never sees the reorg and syncs the
	// replacement blocks as new ones. Its startup rollback to the highest
	// stored block clears the stale state above it, so we write that back
	// after the restart. The other nodes stay on the original chain until the
	// watchman's node mines the longer one at the end.
	let wm_bitcoind = wm.bitcoind().sync_client();
	let board3_block = wm_bitcoind.get_block_hash(board3_height.to_u32() as u64).unwrap();
	wm_bitcoind.invalidate_block(&board3_block).unwrap();
	generate_empty_blocks(&wm_bitcoind, tip.to_u32() - board3_height.to_u32() + 1);
	assert_eq!(tip.to_u32(), wm_bitcoind.get_block_count().unwrap() as u32);
	assert!(wm_bitcoind.get_raw_mempool().unwrap().contains(&board3_txid),
		"board tx should be back in the mempool",
	);
	db.write(async |t| {
		t.execute(
			"DELETE FROM watchmand_block WHERE height >= $1",
			&[&(board3_height.to_u32() as i64)],
		).await?;
		Ok(())
	}).await.unwrap();

	// A spent mid-chain checkpoint vtxo (the change is split in two pieces,
	// each with its own checkpoint): forget its on-chain spend.
	let checkpoint_id = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo_id FROM vtxo \
			WHERE policy_type = 'checkpoint' AND onchain_spent_height IS NOT NULL \
			ORDER BY vtxo_id LIMIT 1",
			&[],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	// The child created by the checkpoint spend (bark1's exited and claimed
	// change vtxo): drop it from the frontier entirely.
	let change_id = db.read(async |t| {
		let row = t.query_one(
			"SELECT v.vtxo_id FROM vtxo v \
			JOIN vtxo p ON p.onchain_spent_txid = v.vtxo_txid \
			WHERE p.vtxo_id = $1 AND v.onchain_spent_height IS NOT NULL",
			&[&checkpoint_id],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	// The unspent payment checkpoint: forget its confirmation and record a
	// spend by bark3's board tx, which the reorg above unconfirms. The
	// reindex must undo that spend and then repair the confirmation.
	let payment_id = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo_id FROM vtxo \
			WHERE policy_type = 'checkpoint' AND onchain_spent_height IS NULL \
				AND frontier_at IS NOT NULL AND confirmed_height IS NOT NULL",
			&[],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	// bark2's unspent board vtxo: drop it from the frontier.
	let board_id = db.read(async |t| {
		let row = t.query_one(
			"SELECT v.vtxo_id FROM vtxo v \
			JOIN virtual_transaction vt ON vt.txid = v.vtxo_txid AND vt.is_funding \
			WHERE v.frontier_at IS NOT NULL AND v.onchain_spent_height IS NULL \
				AND v.vtxo_id != $1",
			&[&board3_id],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	// bark1's spent board vtxo: erase both its spend and its frontier
	// membership. The reindex registers it from its funding tx first and
	// must then repair its missed spend in the same pass.
	let board1_id = db.read(async |t| {
		let row = t.query_one(
			"SELECT v.vtxo_id FROM vtxo v \
			JOIN virtual_transaction vt ON vt.txid = v.vtxo_txid AND vt.is_funding \
			WHERE v.onchain_spent_height IS NOT NULL",
			&[],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	db.write(async |t| {
		t.execute(
			"UPDATE vtxo SET onchain_spent_height = NULL, onchain_spent_txid = NULL, \
			updated_at = NOW() WHERE vtxo_id = $1",
			&[&checkpoint_id],
		).await?;
		t.execute(
			"UPDATE vtxo SET frontier_at = NULL, onchain_spent_height = NULL, \
			onchain_spent_txid = NULL, updated_at = NOW() WHERE vtxo_id = $1",
			&[&change_id],
		).await?;
		t.execute(
			"UPDATE vtxo SET confirmed_height = NULL, onchain_spent_height = $2, \
			onchain_spent_txid = $3, updated_at = NOW() WHERE vtxo_id = $1",
			&[&payment_id, &(board3_height.to_u32() as i32), &board3_txid.to_string()],
		).await?;
		t.execute(
			"UPDATE vtxo SET frontier_at = NULL, onchain_spent_height = NULL, \
			onchain_spent_txid = NULL, updated_at = NOW() WHERE vtxo_id = $1",
			&[&board1_id],
		).await?;
		t.execute(
			"UPDATE vtxo SET frontier_at = NULL, updated_at = NOW() WHERE vtxo_id = $1",
			&[&board_id],
		).await?;
		Ok(())
	}).await.unwrap();

	wm.start().await.unwrap();
	wm.add_slog_handler(failures.clone());
	let mut log_repaired = wm.subscribe_log::<FrontierRepairedSpend>();
	let mut log_complete = wm.subscribe_log::<FrontierReindexComplete>();
	// An empty block, so that bark3's board tx stays in the mempool.
	generate_empty_blocks(&wm_bitcoind, 1);
	wm.wait_for_sync_height(tip + 1).await;

	// What the reorg the watchman never saw leaves behind: bark3's board vtxo
	// keeps its confirmation, and the payment checkpoint its spend by bark3's
	// board tx.
	db.write(async |t| {
		t.execute(
			"UPDATE vtxo SET confirmed_height = $2, updated_at = NOW() WHERE vtxo_id = $1",
			&[&board3_id, &(board3_height.to_u32() as i32)],
		).await?;
		t.execute(
			"UPDATE vtxo SET onchain_spent_height = $2, onchain_spent_txid = $3, \
			updated_at = NOW() WHERE vtxo_id = $1",
			&[&payment_id, &(board3_height.to_u32() as i32), &board3_txid.to_string()],
		).await?;
		Ok(())
	}).await.unwrap();

	let stats = wm.reindex_frontier().await;
	println!("Reindex stats: {:#?}", stats);
	assert_eq!(1, stats.confirmations_repaired, "payment checkpoint confirmation");
	assert_eq!(1, stats.confirmations_cleared, "bark3's reorged board confirmation");
	assert_eq!(1, stats.spends_cleared, "payment checkpoint spent by bark3's board tx");
	assert_eq!(3, stats.spends_repaired, "board, checkpoint and change spends");
	assert_eq!(1, stats.vtxos_added, "change vtxo re-added as checkpoint spend child");
	assert_eq!(2, stats.funding_txs_added, "both board funding txs");
	assert_eq!(2, stats.funding_vtxos_added, "bark1's and bark2's board vtxos");
	assert_eq!(0, stats.unresolved_spends);
	assert!(stats.entries_checked > 0);
	assert!(stats.blocks_scanned > 0);

	// The forward scan repairs the spends in block order: bark1's board vtxo
	// was spent by the exit tx that created the checkpoints.
	let msg = log_repaired.recv().wait_millis(15_000).await.expect("no repaired spend log");
	assert_eq!(msg.vtxo_id.to_string(), board1_id);
	let msg = log_repaired.recv().wait_millis(15_000).await.expect("no second repaired spend log");
	assert_eq!(msg.vtxo_id.to_string(), checkpoint_id);
	let msg = log_complete.recv().wait_millis(15_000).await.expect("no reindex complete log");
	assert_eq!(3, msg.spends_repaired);

	// Verify the database was repaired.
	let repaired = db.read(async |t| {
		let row = t.query_one(
			"SELECT \
			(SELECT frontier_at IS NOT NULL AND onchain_spent_height IS NOT NULL \
				FROM vtxo WHERE vtxo_id = $1) AND \
			(SELECT onchain_spent_height IS NOT NULL FROM vtxo WHERE vtxo_id = $2) AND \
			(SELECT frontier_at IS NOT NULL AND confirmed_height IS NOT NULL \
				AND onchain_spent_height IS NULL AND onchain_spent_txid IS NULL \
				FROM vtxo WHERE vtxo_id = $3) AND \
			(SELECT frontier_at IS NOT NULL FROM vtxo WHERE vtxo_id = $4) AND \
			(SELECT frontier_at IS NOT NULL AND onchain_spent_height IS NOT NULL \
				FROM vtxo WHERE vtxo_id = $5) AND \
			(SELECT confirmed_height IS NULL FROM vtxo WHERE vtxo_id = $6)",
			&[&change_id, &checkpoint_id, &payment_id, &board_id, &board1_id, &board3_id],
		).await?;
		Ok(row.get::<_, bool>(0))
	}).await.unwrap();
	assert!(repaired, "all corrupted rows must be repaired");

	// A second reindex has nothing left to repair.
	let stats = wm.reindex_frontier().await;
	assert_eq!(0, stats.confirmations_repaired);
	assert_eq!(0, stats.confirmations_cleared);
	assert_eq!(0, stats.spends_cleared);
	assert_eq!(0, stats.spends_repaired);
	assert_eq!(0, stats.vtxos_added);
	assert_eq!(0, stats.funding_txs_added);
	assert_eq!(0, stats.funding_vtxos_added);
	assert_eq!(0, stats.unresolved_spends);
	assert_eq!(0, stats.blocks_scanned);
	assert!(stats.entries_checked > 0);

	// The same RPC is reachable through the watchmand CLI.
	let output = wm.get_custom_command(&["rpc", "reindex-frontier"]).await.unwrap()
		.output().await.expect("failed to run watchmand rpc");
	let stdout = String::from_utf8(output.stdout).unwrap();
	let stderr = String::from_utf8(output.stderr).unwrap();
	info!("watchmand rpc stdout: {}", stdout);
	info!("watchmand rpc stderr: {}", stderr);
	assert!(output.status.success(), "watchmand rpc exited with status {}", output.status);
	let cli_stats: serde_json::Value = serde_json::from_str(&stdout).expect("invalid json output");
	assert_eq!(Some(0), cli_stats["spends_repaired"].as_u64());
	assert_eq!(Some(stats.entries_checked), cli_stats["entries_checked"].as_u64());

	// The repaired frontier is actionable: after expiry, the watchman sweeps
	// the re-added board vtxo, the repaired payment checkpoint and bark3's
	// board vtxo, which confirms again in the first of these blocks. Mine
	// them on the watchman's node, so that its chain becomes the longest.
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	wm_bitcoind.generate_to_address(150, &miner_address()).unwrap();
	let tip = BlockHeight::try_from(wm_bitcoind.get_block_count().unwrap()).unwrap();
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15_000).await.expect("no claim log");
	failures.assert_empty();
	println!("Post-reindex sweep: {:#?}", msg);
	assert_eq!(3, msg.vtxo_ids.len());
	assert_eq!(450_000, msg.total_input_value.to_sat());
}

/// An address to mine to on a bitcoind without a wallet.
fn miner_address() -> bitcoin::Address {
	bitcoin::Address::from_str("mzU8XRVhUdXtdxmSA3Vw8XeU2FDV4iBDRW").unwrap().assume_checked()
}

/// Mine blocks that don't include any mempool tx.
fn generate_empty_blocks(client: &BitcoinRpcClient, nb_blocks: u32) {
	for _ in 0..nb_blocks {
		client.call::<serde_json::Value>("generateblock", &[
			serde_json::json!(miner_address().to_string()), serde_json::json!([]),
		]).expect("generateblock failed");
	}
}

#[tokio::test]
async fn watchman_sweeps_lightning_vtxos() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_lightning_vtxos").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 10, amount: sat(10_000) },
		];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	// Create a lightning payment that creates HTLC vtxos
	let invoice = bark2.bolt11_invoice(sat(50_000)).await.invoice;
	let bark1_clone = bark1.clone();
	srv.wait_for_vtxopool(&ctx).await;
	tokio::join!(
		async move {
			bark1_clone.pay_lightning_wait(&invoice, None).await;
		},
		async move {
			bark2.lightning_receive_all().wait_millis(60_000).await;
		},
	);

	// Wait for the HTLC vtxos to expire
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired HTLC vtxos
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(5000).await.expect("no claim log");
	failures.assert_empty();
	println!("Lightning vtxo sweep: {:#?}", msg);
	// 2 boards and 1 vtxopool root
	assert_eq!(3, msg.vtxo_ids.len());
	assert_eq!(700_000, msg.total_input_value.to_sat());
	assert_eq!(698_029, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_round_leftovers_after_exits() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_round_leftovers_after_exits").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
		cfg.watchman.claim_chunksize = 20.try_into().unwrap();
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Create 10 barks
	let mut barks = Vec::new();
	let mut board_funding_txids = Vec::new();
	for i in 0..10 {
		let bark = ctx.bark(&format!("bark{}", i), &srv).funded(sat(500_000)).create().await;
		let board = bark.board(sat(200_000)).await;
		barks.push(bark);
		assert_eq!(1, board.vtxos.len());
		board_funding_txids.push(board.funding_tx.txid);
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Sync all barks so they see their board vtxos
	for bark in &barks {
		bark.sync().await;
	}

	// Create a round with all 10 barks
	let bark_refs = barks.iter().collect::<Vec<_>>();
	ctx.refresh_all(&srv, &bark_refs).await;

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	for bark in &barks {
		bark.sync().await;
	}

	// All barks should have exactly 1 vtxo now
	let mut all_vtxo_ids = Vec::new();
	for bark in &barks {
		let vtxo_ids = bark.vtxo_ids().await;
		assert_eq!(vtxo_ids.len(), 1);
		all_vtxo_ids.extend(vtxo_ids);
	}
	assert_eq!(all_vtxo_ids.len(), 10);

	// 2 barks exit their vtxos
	barks[0].start_exit_all().await;
	barks[1].start_exit_all().await;
	tokio::join!(
		async {
			complete_exit(&ctx, &barks[0]).await;
			barks[0].claim_all_exits(barks[0].get_onchain_address().await).await;
		},
		async {
			complete_exit(&ctx, &barks[1]).await;
		},
	);

	// Wait for remaining vtxos to expire
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired server-owned vtxos from the round
	// After exits, there are still server-side vtxos (checkpoints, connectors, etc.) to sweep
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Round leftovers sweep: {:#?}", msg);
	for txid in board_funding_txids {
		assert!(msg.vtxo_ids.iter().any(|v| v.to_point().txid == txid),
			"missing funding txid {} in sweep", txid,
		);
	}
	assert_eq!(3_600_000, msg.total_input_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_vtxopool_with_exit() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_vtxopool_with_exit").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").funded(btc(10)).lightningd(&ln.internal).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![
			// total: 300_099_000
			VtxoTarget { count: 9, amount: sat(1_000) },
			VtxoTarget { count: 9, amount: sat(10_000) },
			VtxoTarget { count: 3, amount: btc(1) },
		];
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await);
	let bark2 = Arc::new(ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	// Create a lightning payment that creates HTLC vtxos
	let invoice = bark2.bolt11_invoice(sat(50_000)).await.invoice;
	let bark1_clone = bark1.clone();
	srv.wait_for_vtxopool(&ctx).await;
	tokio::join!(
		async {
			bark1_clone.pay_lightning_wait(&invoice, None).await;
		},
		async {
			bark2.lightning_receive_all().wait_millis(60_000).await;
		},
	);

	bark1.sync().await;
	bark2.sync().await;
	bark1.start_exit_all().await;
	bark2.start_exit_all().await;
	tokio::join!(
		async {
			// should exit the two 125k change pieces
			complete_exit(&ctx, &bark1).await;
			bark1.claim_all_exits(bark1.get_onchain_address().await).await;
		},
		async {
			// should exit 300k board + 50k htlc
			complete_exit(&ctx, &bark2).await;
		},
	);

	// Wait for the HTLC vtxos to expire
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;

	// Watchman should sweep the expired HTLC vtxos
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(10000).await.expect("no claim log");
	failures.assert_empty();
	println!("Lightning vtxo sweep: {:#?}", msg);
	assert_eq!(300_099_000, msg.total_input_value.to_sat());
	assert_eq!(300_094_901, msg.total_output_value.to_sat());
}

/// After an offboard whose input gets maliciously exited, the watchman
/// confiscates the exit output with the presigned forfeit tx. The forfeit
/// output — the input amount plus the connector dust it accumulates — is a
/// plain server keyspend that the watchman must sweep once the input vtxo
/// expires.
#[tokio::test]
async fn watchman_sweeps_offboard_forfeit_after_confiscation() {
	sweep_offboard_forfeit("watchman_sweeps_offboard_forfeit_after_confiscation", false).await;
}

#[tokio::test]
async fn watchman_sweeps_offboard_forfeit_and_pays_expired_board() {
	sweep_offboard_forfeit("watchman_sweeps_offboard_forfeit_and_pays_expired_board", true).await;
}

async fn sweep_offboard_forfeit(name: &str, expiry_payouts: bool) {
	let ctx = TestContext::new(&format!("server/{name}")).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(move |cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		cfg.vtxopool.vtxo_targets = vec![];
		cfg.expiry_payouts = expiry_payouts;
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// fund the watchman so it can pay CPFP fees for the forfeit broadcast
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark.sync().await;
	let exit_point = bark.vtxo_ids().await[0].to_point();

	// snapshot the wallet before offboarding; the attacker keeps the stale vtxo
	let evil = bark.full_clone("evil").await;

	let payout = ctx.bitcoind().get_new_address();
	bark.offboard_all(&payout).await;
	ctx.generate_blocks(1).await;

	let owner_payout = if expiry_payouts {
		let owner = ctx.bark_sdk("owner", &srv).boarded(sat(100_000))
			.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
		Some((owner.spendable_vtxos().await.unwrap()[0].id(), owner.payout_script()))
	} else {
		None
	};

	// the attacker exits the now-forfeited vtxo
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	// drive the watchman until it confiscates the exit output
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let client = ctx.bitcoind().sync_client();
	for _ in 0..25 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
		if client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none() {
			break;
		}
	}
	assert!(
		client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none(),
		"the watchman should have confiscated the exit output",
	);

	// Wait for the input vtxo to expire, then the watchman should sweep the
	// confiscated forfeit output. The exit output, the connector and the board
	// output are all spent by now, so the forfeit output is the only sweep:
	// the input amount plus the connector dust.
	let tip = ctx.generate_blocks(200).await;
	wm.wait_for_sync_height(tip).await;
	let rounds_balance = srv.wallet_status().await.rounds.total_balance;

	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Offboard forfeit sweep: {:#?}", msg);
	assert_eq!(400_330, msg.total_input_value.to_sat());
	let owner_payout = if let Some((id, script)) = owner_payout {
		let db = Db::connect(&srv.config().postgres).await.unwrap();
		let (_, payout) = super::expiry_payout::wait_payout(&db, id).await;
		Some((payout, script))
	} else {
		None
	};

	// the forfeit output must actually be gone from the utxo set
	let forfeit_point = msg.vtxo_ids[0].to_point();
	let tip = ctx.generate_blocks(1).await;
	srv.wait_for_sync_height(tip).await;
	assert!(
		client.get_tx_out(&forfeit_point.txid, forfeit_point.vout, Some(true)).unwrap().is_none(),
		"forfeit output {} should be spent by the sweep", forfeit_point,
	);

	// With no payout, the confiscated funds must land in the rounds wallet.
	// A payout also pays an on-chain fee from that wallet, changing its net balance.
	if !expiry_payouts {
		assert_eq!(srv.wallet_status().await.rounds.total_balance,
			rounds_balance + msg.total_output_value,
			"forfeit sweep must pay out to the rounds wallet",
		);
	}
	if let Some((payout, script)) = owner_payout {
		super::expiry_payout::assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	}
}

#[tokio::test]
async fn watchman_sweeps_exit_after_forfeit() {
	let ctx = TestContext::new("server/watchman_sweeps_exit_after_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Board some funds with bark1 and bark2
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	// Fund the watchman with two UTXOs, one for each forfeit's CPFP
	let wm_addr = wm.wait_wallet_address().await;
	ctx.bitcoind().fund_addr(&wm_addr, sat(100_000)).await;
	ctx.bitcoind().fund_addr(&wm_addr, sat(100_000)).await;

	// Clone both before refresh; the clones retain the stale board vtxo state
	let bark1_old = bark1.full_clone("bark1_old").await;
	let bark2_old = bark2.full_clone("bark2_old").await;

	// Both refresh their board vtxo into a round vtxo
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;

	// The clones, holding the stale board vtxos, start malicious exits
	bark1_old.start_exit_all().await;
	bark2_old.start_exit_all().await;

	// Progress until the exit transactions are confirmed on-chain (AwaitingDelta state).
	tokio::join!(
		progress_exit_until_awaiting_delta(&ctx, &bark1_old),
		progress_exit_until_awaiting_delta(&ctx, &bark2_old),
	);

	// Advance past watchman's progress grace period
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	// first sweep: the watchman broadcasts both forfeit (progress) txs via
	// CPFP, each CPFP with its own fee input.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress1 = log_progress.recv().wait_millis(10_000).await
		.expect("watchman should broadcast progress (forfeit) tx");
	let progress2 = log_progress.recv().wait_millis(10_000).await
		.expect("watchman should broadcast the second progress (forfeit) tx");
	assert_ne!(progress1.txid, progress2.txid);

	// Confirm the forfeit txs so the resulting HarkForfeit vtxos enter the frontier.
	ctx.await_transactions_across_nodes(
		[progress1.cpfp_txid, progress2.cpfp_txid], [wm.bitcoind().as_ref()],
	).await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	// third sweep: the watchman claims the HarkForfeit vtxos.
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15_000).await.expect("no claim log");
	failures.assert_empty();
	println!("malicious exit sweep: {:#?}", msg);
	let mut claimed = msg.vtxo_ids.iter().map(|v| v.to_point().txid).collect::<Vec<_>>();
	claimed.sort();
	let mut forfeits = vec![progress1.txid, progress2.txid];
	forfeits.sort();
	assert_eq!(forfeits, claimed);
}

/// Cross-domain hash reuse: the same 32-byte secret exists in two tables at once.
///
/// - `round_participation`: the hArk unlock preimage, stored when a user
///   participates in a round;
/// - `htlc_settlement`: a Lightning preimage, stored when a payment with the
///   same payment hash settles.
///
/// This state is reachable through entirely legitimate flows: a user learns
/// their unlock preimage when they forfeit, so nothing stops them from
/// settling a Lightning payment (send or receive) whose payment hash equals
/// their unlock hash afterwards. Here we plant the state directly.
///
/// The watchman must keep claiming hArk forfeit outputs in this state: the
/// forfeit claim's `HashSign` clause belongs to the hArk domain, and the
/// participation preimage is the only secret that can satisfy it. Refusing to
/// sign "because the hash is ambiguous" leaves the forfeit output unclaimed
/// until the user's `exit_delta` clause matures, letting a malicious user
/// reclaim the forfeited coins while keeping their new round vtxos.
#[tokio::test]
async fn watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table() {
	require_bark_version!(> "0.5.0");

	let ctx =
		TestContext::new("server/watchman_sweeps_forfeit_with_preimage_in_ln_settlement_table")
			.await;
	let srv = ctx
		.captaind("server")
		.funded(btc(10))
		.cfg(|cfg| {
			cfg.vtxopool.vtxo_targets = vec![];
		})
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
			cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
		})
		.create()
		.await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Board some funds with bark1
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1
		.board_and_confirm_and_register(&ctx, sat(200_000))
		.await;

	// fund the watchman
	ctx.bitcoind()
		.fund_addr(wm.wait_wallet_address().await, sat(100_000))
		.await;

	// Clone bark1 before refresh — bark2 retains the stale board vtxo state
	let bark1_old = bark1.full_clone("bark2").await;

	// bark1 refreshes its board vtxo into a round vtxo. The hArk round stores
	// the participation's unlock hash and preimage in round_participation.
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;

	// Plant the cross-domain state: record the same preimage as a settled
	// Lightning payment hash.
	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let unlock_preimage = db
		.read(async |t| {
			let row = t
				.query_one(
					"SELECT unlock_preimage FROM round_participation ORDER BY id DESC LIMIT 1",
					&[],
				)
				.await?;
			let hex: String = row.get(0);
			Ok(ark::lightning::Preimage::from_str(&hex).expect("invalid unlock preimage"))
		})
		.await
		.unwrap();
	db.write(async |t| t.store_htlc_settlement(unlock_preimage).await)
		.await
		.unwrap();

	// bark1_old, holding the stale board vtxo, starts a malicious exit
	bark1_old.start_exit_all().await;

	// Progress until the exit transaction is confirmed on-chain (AwaitingDelta state).
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Advance past watchman's progress grace period
	let tip = ctx
		.generate_blocks(wm.config().watchman.progress_grace_period.to_u32())
		.await;
	wm.wait_for_sync_height(tip).await;

	// first sweep: the watchman broadcasts the forfeit (progress) transaction via CPFP.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress_log = log_progress
		.recv()
		.wait_millis(10_000)
		.await
		.expect("watchman should broadcast progress (forfeit) tx");

	// Confirm the forfeit tx so the resulting HarkForfeit vtxo enters the frontier.
	ctx.await_transactions_across_nodes([progress_log.cpfp_txid], [wm.bitcoind().as_ref()])
		.await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	// second sweep: the watchman must claim the HarkForfeit vtxo. The preimage
	// for its HashSign clause is the hArk unlock preimage; the Lightning
	// settlement row for the same hash must not block this.
	wm.trigger_sweep().await;
	let msg = log_claim
		.recv()
		.wait_millis(15_000)
		.await
		.expect("watchman must claim the HarkForfeit vtxo despite the cross-domain preimage");
	failures.assert_empty();
	println!("malicious exit sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	assert_eq!(msg.vtxo_ids[0].to_point().txid, progress_log.txid);
}

/// One clone sends an OOR payment to bark2 and bark2 refreshes (forfeiting the OOR vtxo
/// in a round), which makes the server store the signed OOR transaction and set
/// server_may_own_descendant on bark1's round vtxo exit tx. The other clone (bark1_old)
/// then attempts a malicious exit with its stale round vtxo. The watchman detects this
/// and blocks the exit by broadcasting the OOR transaction as a progress step via CPFP.
#[tokio::test]
async fn watchman_sweeps_exit_after_oor_then_forfeit() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_exit_after_oor_then_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	// Fund the watchman wallet upfront so it can pay CPFP fees for the OOR tx progress
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(100_000)).await;

	// Both barks board and refresh together so both have confirmed round vtxos
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;

	// Clone bark1 before the OOR — bark1_old retains the stale round vtxo state
	let bark1_old = bark1.full_clone("bark1_old").await;

	// bark1 sends an OOR payment to bark2; the server co-signs and records the OOR tx,
	// marking bark1's round vtxo as OOR-spent in the server DB
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	bark2.sync().await;

	// bark2 refreshes its received OOR vtxo in a new round. Once the round tx confirms,
	// bark2 syncs to complete the hArk forfeit protocol. During forfeit processing the
	// server stores the signed OOR tx (via register_vtxo_transactions) and marks
	// server_may_own_descendant on bark1's round vtxo exit tx.
	ctx.refresh_all(&srv, &[&bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark2.sync().await;

	// bark1_old, holding the stale round vtxo, starts a malicious exit
	bark1_old.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Advance past watchman's progress grace period
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	// The watchman should broadcast the checkpoint transaction as a progress step, spending
	// bark1's round vtxo exit output on-chain and blocking the malicious exit.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress = log_progress.recv().wait_millis(10_000).await.expect("no progress");
	ctx.await_transactions_across_nodes([progress.cpfp_txid], [wm.bitcoind().as_ref()]).await;

	// now let's expire the vtxo and claim the checkpoint
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let tip = ctx.generate_blocks(
		srv.config().vtxo_lifetime.to_u32() - 2 * ROUND_CONFIRMATIONS + 3,
	).await;
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let claim = log_claim.recv().wait_millis(10_000).await.expect("no claim");
	assert!(claim.vtxo_ids.iter().any(|v| v.to_point().txid == progress.txid));

	failures.assert_empty();
}


/// `getmempoolentry` as JSON, as the bitcoincore_rpc type expects fields bitcoind dropped.
fn mempool_entry(rpc: &BitcoinRpcClient, txid: Txid) -> serde_json::Value {
	rpc.call("getmempoolentry", &[txid.to_string().into()]).unwrap()
}

/// The children of `parent` in the mempool.
fn mempool_children(rpc: &BitcoinRpcClient, parent: Txid) -> Vec<Txid> {
	mempool_entry(rpc, parent)["spentby"].as_array().unwrap().iter()
		.map(|t| Txid::from_str(t.as_str().unwrap()).unwrap())
		.collect()
}

/// Replace the CPFP child of `parent` with a large child on its fee anchor, as anyone can.
/// The package pays 9 sat/vB, a bit more than the watchman's 7 sat/vB, so a much higher
/// absolute fee. The child spends the confirmed coin of `coin_addr`.
async fn attach_large_cheap_child(
	ctx: &TestContext,
	wm: &Watchmand,
	parent: Txid,
	coin_addr: &Address,
) -> Txid {
	let rpc = ctx.bitcoind().sync_client();
	let parent_tx = rpc.get_raw_transaction(&parent, None).unwrap();
	let parent_vsize = mempool_entry(&rpc, parent)["vsize"].as_u64().unwrap();
	let anchor_vout = parent_tx.output.iter()
		.position(|o| o.script_pubkey == *bitcoin_ext::fee::P2A_SCRIPT)
		.expect("parent has no anchor") as u32;
	let coin = rpc.list_unspent(Some(1), None, Some(&[coin_addr]), None, None).unwrap()
		.pop().expect("coin not confirmed");
	let padding = (0..25).map(|_| TxOut {
		value: sat(1_000),
		script_pubkey: ctx.bitcoind().get_new_address().script_pubkey(),
	}).collect::<Vec<_>>();
	let sign = |change: Amount| {
		let tx = Transaction {
			version: transaction::Version(3),
			lock_time: absolute::LockTime::ZERO,
			input: vec![
				TxIn {
					previous_output: OutPoint::new(parent, anchor_vout),
					sequence: Sequence::ZERO,
					..Default::default()
				},
				TxIn {
					previous_output: OutPoint::new(coin.txid, coin.vout),
					sequence: Sequence::ZERO,
					..Default::default()
				},
			],
			output: padding.iter().cloned().chain([TxOut {
				value: change,
				script_pubkey: coin_addr.script_pubkey(),
			}]).collect(),
		};
		let anchor = SignRawTransactionInput {
			txid: parent,
			vout: anchor_vout,
			script_pub_key: bitcoin_ext::fee::P2A_SCRIPT.clone(),
			redeem_script: None,
			amount: Some(Amount::ZERO),
		};
		rpc.sign_raw_transaction_with_wallet(&tx, Some(&[anchor]), None).unwrap()
			.transaction().unwrap()
	};
	let padding_value = padding.iter().map(|o| o.value).sum::<Amount>();
	let child_vsize = sign(coin.amount - padding_value).vsize() as u64;
	let fee = FeeRate::from_sat_per_vb_u32(9)
		* Weight::from_vb_unchecked(parent_vsize + child_vsize + 2);
	let child = sign(coin.amount - padding_value - fee);
	let txid = rpc.send_raw_transaction(&child).unwrap();
	ctx.await_transactions_across_nodes([txid], [wm.bitcoind().as_ref()]).await;
	txid
}

/// Restart the watchman wanting 15 sat/vB, so a package at 9 sat/vB pays too little.
async fn raise_watchman_fee_rate(wm: &Watchmand, failures: &WatchmanFailureCollector) {
	let fee_rate = FeeRate::from_sat_per_vb_u32(15);
	wm.stop().await.unwrap();
	{
		let mut cfg = wm.config_mut();
		cfg.fee_estimator.fallback_fee_rate_regular = fee_rate;
		// A higher estimate is capped to the same rate.
		cfg.fee_estimator.max_fee_rate = Some(fee_rate);
	}
	wm.start().await.unwrap();
	wm.add_slog_handler(failures.clone());

	// A lower estimate would replace the fallback. The 3-block target is the
	// watchman's regular rate, and no block comes in before the bump.
	let estimate: serde_json::Value = wm.bitcoind().sync_client()
		.call("estimatesmartfee", &[3.into(), "economical".into()]).unwrap();
	if let Some(btc_per_kvb) = estimate["feerate"].as_f64() {
		let estimate = FeeRate::from_sat_per_kwu((btc_per_kvb * 100_000_000.0 / 4.0) as u64);
		assert!(estimate >= fee_rate, "node estimates {} below the test's {}", estimate, fee_rate);
	}
}

/// Trigger the watchman until `parent`'s child in its mempool is no longer `old_child`,
/// and return the new child.
async fn wait_for_child_replaced(wm: &Watchmand, parent: Txid, old_child: Txid) -> Txid {
	let rpc = wm.bitcoind().sync_client();
	for _ in 0..20 {
		wm.trigger_sweep().await;
		let children = mempool_children(&rpc, parent);
		if let Some(child) = children.iter().find(|c| **c != old_child) {
			assert!(!children.contains(&old_child));
			return *child;
		}
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
	panic!("the watchman didn't replace child {} of {}", old_child, parent);
}

/// A progress package in the mempool that pays too little but has a large child, for example
/// one an attacker attached to the progress tx's anchor, must still be replaced by the watchman.
/// The replacement has to pay more than the child it evicts, not just a higher feerate than the
/// package, or bitcoind rejects it and the progress stays stuck while a timelock runs out.
#[tokio::test]
async fn watchman_replaces_large_cheap_progress_child() {
	require_bark_version!(> "0.5.0");
	require_bitcoind_chain_source!();

	let ctx = TestContext::new("server/watchman_replaces_large_cheap_progress_child").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(100_000)).await;

	// Make the watchman progress a stale exit, as in watchman_sweeps_exit_after_oor_then_forfeit.
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;
	let bark1_old = bark1.full_clone("bark1_old").await;
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	bark2.sync().await;
	ctx.refresh_all(&srv, &[&bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark2.sync().await;
	bark1_old.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// A confirmed coin for the attacker's child.
	let attacker_addr = ctx.bitcoind().get_new_address();
	ctx.bitcoind().fund_addr(&attacker_addr, sat(100_000)).await;

	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress = log_progress.recv().wait_millis(10_000).await.expect("no progress");
	ctx.await_transactions_across_nodes([progress.cpfp_txid], [wm.bitcoind().as_ref()]).await;

	// The package now pays less than the watchman wants, so it has to replace the
	// attacker's child, which pays more than a package at the watchman's feerate would.
	let attacker_child = attach_large_cheap_child(&ctx, &wm, progress.txid, &attacker_addr).await;
	raise_watchman_fee_rate(&wm, &failures).await;
	let watchman_child = wait_for_child_replaced(&wm, progress.txid, attacker_child).await;

	// Without a restart, the chunk of the same spender pays less than the watchman wants:
	// make bitcoind count the watchman's child for almost nothing, as if a descendant that
	// paid for the chunk left. The watchman must notice and bump again.
	let wm_rpc = wm.bitcoind().sync_client();
	let child_fee = Amount::from_btc(
		mempool_entry(&wm_rpc, watchman_child)["fees"]["modified"].as_f64().unwrap(),
	).unwrap();
	let delta = -(child_fee.to_sat() as i64 - 100);
	let _: bool = wm_rpc.call(
		"prioritisetransaction", &[watchman_child.to_string().into(), 0.into(), delta.into()],
	).unwrap();
	wait_for_child_replaced(&wm, progress.txid, watchman_child).await;

	failures.assert_empty();
}

/// The same for a forfeit tx's connector: the watchman broadcasts it before the forfeit tx,
/// and it doesn't spend the vtxo that is being exited. A connector in the mempool with a large
/// cheap child must be found and replaced just the same.
#[tokio::test]
async fn watchman_replaces_large_cheap_connector_child() {
	require_bitcoind_chain_source!();

	let ctx = TestContext::new("server/watchman_replaces_large_cheap_connector_child").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	// Offboarding two vtxos puts their connectors in a separate connector tx.
	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark.sync().await;
	let evil = bark.full_clone("evil").await;
	bark.offboard_all(&ctx.bitcoind().get_new_address()).await;
	ctx.generate_blocks(1).await;
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	let attacker_addr = ctx.bitcoind().get_new_address();
	ctx.bitcoind().fund_addr(&attacker_addr, sat(100_000)).await;

	let mut log_dependent = wm.subscribe_log::<BroadcastingDependentTx>();
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let dependent = log_dependent.recv().wait_millis(10_000).await.expect("no connector");
	let progress = log_progress.recv().wait_millis(10_000).await.expect("no progress");
	assert_eq!(progress.txid, dependent.parent_txid);
	ctx.await_transactions_across_nodes([progress.cpfp_txid], [wm.bitcoind().as_ref()]).await;

	let attacker_child = attach_large_cheap_child(&ctx, &wm, progress.txid, &attacker_addr).await;
	raise_watchman_fee_rate(&wm, &failures).await;
	wait_for_child_replaced(&wm, progress.txid, attacker_child).await;

	failures.assert_empty();
}

/// The vtxopool funds each lightning receive from the change of the previous one, so all the
/// receives hang off a single allocation chain. When a user exits the oldest receive, the txs
/// it shares with the others hit the chain, but the checkpoint caps how far that reaches: the
/// watchman broadcasts nothing, and the pool remainder is swept once the pool vtxos expire.
#[tokio::test]
async fn watchman_doesnt_broadcast_htlc_recv_chain() {
	let ctx = TestContext::new("server/watchman_doesnt_broadcast_htlc_recv_chain").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.vtxo_lifetime = BlockDelta::new(144);
		// The pool never issues a single vtxo at a time, so ask for the minimum of two.
		cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		cfg.vtxopool.vtxo_lifetime = BlockDelta::new(144);
		// Keep the change in the pool so all the receives share one allocation chain.
		cfg.vtxopool.max_vtxo_exit_depth = 100;
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Fund the watchman so it can pay CPFP fees for progress broadcasts.
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let wallet = ctx.bark_sdk("bark", &srv).funded(sat(1_000_000)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	// Receive sequentially so each allocation spends the change of the previous one.
	for _ in 0..20 {
		let invoice = wallet.bolt11_invoice(sat(1_000), None, None).await
			.expect("creating the invoice");
		let (pay, _) = tokio::join!(
			ln.external.try_pay_bolt11(invoice.to_string()),
			wallet.try_claim_lightning_receive(PaymentHash::from(&invoice), true),
		);
		pay.expect("the lightning payment should succeed");
	}

	// The shortest exit chain belongs to the oldest receive. Exiting it drags the txs it
	// shares with the other receives on-chain.
	let oldest = wallet.vtxos().await.expect("listing vtxos").into_iter()
		.min_by_key(|v| v.exit_depth)
		.expect("there should be receives")
		.vtxo;
	wallet.exit_mgr().start_exit_for_vtxos(&[oldest.clone()]).await
		.expect("starting the exit");
	let mut state = None;
	for _ in 0..30 {
		wallet.sync_onchain().await.expect("onchain sync");
		wallet.progress_exits().await.expect("progressing the exit");
		state = wallet.exit_mgr().get_exit_vtxo(oldest.id()).await
			.map(|exit| exit.state().clone());
		if matches!(state, Some(ExitState::AwaitingDelta(_))) {
			break;
		}
		ctx.generate_blocks(1).await;
	}
	assert!(matches!(state, Some(ExitState::AwaitingDelta(_))),
		"the exit should have confirmed on-chain, was {:?}", state,
	);

	let grace = u32::from(wm.config().watchman.progress_grace_period);
	let tip = ctx.generate_blocks(grace).await;
	wm.wait_for_sync_height(tip).await;

	// Give the watchman its chance to broadcast the receive chain; it must not take it.
	wm.trigger_sweep().await;

	// Once the pool vtxos expire, the watchman claims the pool remainder in one tx.
	let tip = ctx.generate_blocks(150).await;
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let claim = log_claim.recv().wait_millis(30_000).await.expect("no claim log");
	println!("vtxopool sweep: {:#?}", claim);
	assert!(log_claim.try_recv().is_err(), "the watchman should sweep in a single claim");

	// The watchman broadcast none of the txs in the receive chain.
	if let Ok(p) = log_progress.try_recv() {
		panic!("watchman broadcast progress tx {} for vtxo {}", p.txid, p.vtxo_id);
	}

	failures.assert_empty();
}

/// Safety guard for the *checkpointed* arkoor case (counterpart to the lightning bug
/// above). A bark-to-bark OOR inserts a checkpoint between the sender's vtxo and the
/// recipient's leaf, and the watchman treats a `Checkpoint`-policy vtxo as
/// expiry-claimable (`decide_action_expiry`) rather than progressing to the leaf. So even
/// when the OOR parent is force-exited on-chain, bark2's received vtxo is NOT dragged
/// on-chain and must stay `Spendable` on the client. This pins that down so the
/// force-exit fix (or any watchman change) doesn't start force-exiting checkpointed
/// arkoors.
#[tokio::test]
async fn watchman_force_exit_checkpointed_arkoor_stays_spendable() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_force_exit_checkpointed_arkoor_stays_spendable").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = srv.watchmand();
	wm.add_slog_handler(failures.clone());

	// Fund the watchman so it can pay CPFP fees for its progress broadcasts.
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

	// bark1 boards and refreshes into a round vtxo P - the parent of bark2's future vtxo.
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	assert_eq!(bark1.vtxo_ids().await.len(), 1, "bark1 should hold one round vtxo");

	// Clone bark1 before the OOR; bark1_old keeps the stale round vtxo P.
	let bark1_old = bark1.full_clone("bark1_old").await;

	// bark1 sends an OOR to bark2. On sync bark2 registers the signed chain with the
	// server. Because the OOR is checkpointed, bark2's leaf sits below a checkpoint.
	bark1.send_oor(bark2.address().await, sat(100_000)).await;
	bark2.sync().await;
	let victim = {
		let vtxos = bark2.vtxos().await;
		assert_eq!(vtxos.len(), 1, "bark2 should hold exactly the received vtxo");
		assert!(matches!(vtxos[0].state, VtxoStateInfo::Spendable));
		vtxos[0].id
	};
	let victim_txid = victim.to_point().txid;

	// A stale clone of bark1 unilaterally exits P, dragging the OOR parent on-chain.
	bark1_old.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Drive the watchman. It will broadcast the checkpoint tx (progressing P), but must
	// stop there - a checkpoint is expiry-claimed, never progressed to bark2's leaf.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	let mut forced = false;
	let mut any_progress = false;
	for _ in 0..15 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		while let Ok(p) = log_progress.try_recv() {
			println!("ProgressBroadcast vtxo_id={} txid={}", p.vtxo_id, p.txid);
			any_progress = true;
			ctx.await_transactions_across_nodes([p.cpfp_txid], [wm.bitcoind().as_ref()]).await;
			if p.txid == victim_txid {
				forced = true;
			}
		}
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
	}
	failures.assert_empty();

	// Guard against a vacuous pass: the watchman must have actually progressed the
	// dragged-on-chain parent (broadcasting the checkpoint tx), otherwise `!forced`
	// proves nothing about the checkpoint stopping it short of bark2's leaf.
	assert!(any_progress,
		"watchman never broadcast any progress; the checkpoint-stop assertion is vacuous",
	);

	// The watchman must NOT have broadcast bark2's leaf: checkpointed arkoors aren't
	// force-exited.
	assert!(!forced,
		"watchman unexpectedly broadcast bark2's checkpointed leaf {}; it must not force-exit it",
		victim_txid,
	);

	// bark2's vtxo must remain Spendable on the client (not marked Exited).
	let vtxos = bark2.vtxos().await; // syncs
	let v = vtxos.iter().find(|v| v.id == victim).expect("victim vtxo disappeared from bark2");
	assert!(matches!(v.state, VtxoStateInfo::Spendable),
		"checkpointed arkoor must remain Spendable on the client, was {:?}", v.state,
	);
	let status = ctx.bitcoind().sync_client().tx_status(v.id.to_point().txid)
		.expect("status should succeed");
	assert!(matches!(status, TxStatus::NotFound),
		"client VTXO must not be onchain, status was: {:?}", status,
	);
}
