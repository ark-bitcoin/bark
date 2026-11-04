
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use parking_lot::Mutex;
use bitcoincore_rpc::RpcApi;

use ark::fees::{BoardFees, PpmFeeRate};
use ark::lightning::PaymentHash;
use bark::exit::ExitState;
use bark_json::primitives::VtxoStateInfo;
use bitcoin::Amount;
use bitcoin_ext::{BlockDelta, BlockHeight, TxStatus};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use server::database::Db;
use server::vtxopool::VtxoTarget;
use server_log::{
	ArkFeeRecorded, ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure,
	ProgressBroadcast, ProgressCpfpFailure, FrontierReindexComplete, FrontierRepairedSpend,
};

use ark_testing::{TestContext, btc, require_bark_version, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::SlogHandler;
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
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("server/watchman_sweeps_boards").await;
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
	let bark1 = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	let _ = bark1.board(sat(100_000)).await;
	ctx.generate_blocks(2 * BOARD_CONFIRMATIONS).await;
	let _ = bark1.offchain_balance().await;

	ctx.refresh_all(&srv, &[&bark1]).await;

	// expire only the board, not the refresh
	let tip = ctx.generate_blocks(
		srv.config().vtxo_lifetime.to_u32() - 2 * BOARD_CONFIRMATIONS + 2,
	).await;
	wm.wait_for_sync_height(tip).await;

	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Board sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	// rounds didnt' expire yet
	assert_eq!(100_000, msg.total_input_value.to_sat());
	assert_eq!(99_093, msg.total_output_value.to_sat());
}

/// End-to-end check that `ArkFeeRecorded` fires from `record_ark_fee` on a
/// real board flow. Configures non-zero board fees so the assertion
/// exercises the recording wiring and not just `0 == 0`.
///
/// NB: the slog fires from `register_board` (post-confirmation), not from
/// `cosign_board`, so the test must confirm + register the board.
#[tokio::test]
async fn ark_fee_recorded_slog_on_board() {
	// Sized so that base + ppm are both non-trivial:
	//   base_fee = 100 sat, ppm = 1000 (0.1%)
	//   for amount = 100_000 sat -> 100 + 100 = 200 sat
	let board_fees = BoardFees {
		min_fee: Amount::ZERO,
		base_fee: Amount::from_sat(100),
		ppm: PpmFeeRate(1000),
	};
	let board_amount = sat(100_000);
	let expected_fee = board_fees.calculate(board_amount)
		.expect("BoardFees::calculate should not overflow on test inputs");

	let ctx = TestContext::new("server/ark_fee_recorded_slog_on_board").await;
	let cfg_board_fees = board_fees.clone();
	let srv = ctx.captaind("server").funded(btc(10)).cfg(move |cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
		cfg.fees.board = cfg_board_fees.clone();
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	let mut fee_logs = srv.subscribe_log::<ArkFeeRecorded>();
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let fee = fee_logs.recv().wait_millis(15_000).await
		.expect("no ArkFeeRecorded slog received from board");
	assert_eq!(fee.op_type, "board", "board should record op_type=board");
	assert_eq!(fee.net_fee_sat, expected_fee.to_sat(),
		"recorded board fee should match BoardFees::calculate for the boarded amount");
	assert_eq!(fee.user_fee_sat, expected_fee.to_sat(),
		"board has no routing component so user_fee == net_fee");
	assert_eq!(fee.routing_fee_sat, None,
		"board has no routing component");
	assert_eq!(fee.round_seq, None,
		"board does not run through a round");
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
	// replacement blocks as new ones: the board vtxo keeps its now stale
	// confirmation height. The other nodes stay on the original chain
	// until the watchman's node mines the longer one at the end.
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
				AND onchain_spent_height IS NULL FROM vtxo WHERE vtxo_id = $3) AND \
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

/// Offboard connectors pay a plain keyspend of the server key, but they must
/// only be swept CONNECTOR_EXPIRY_DELTA (144) blocks after the input vtxos
/// expire: sweeping earlier would invalidate a forfeit tx the watchman might
/// still need. So once the input vtxos expire, the watchman sweeps the board
/// outputs but leaves the connector alone, and only after the full delta it
/// sweeps the connector dust too.
#[tokio::test]
async fn watchman_sweeps_offboard_connectors() {
	let ctx = TestContext::new("server/watchman_sweeps_offboard_connectors").await;
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

	// Board four vtxos and offboard them together, so the offboard uses the
	// multi-connector fanout root output. Four inputs also make the connector
	// output large enough (4 * 330 sat) to pay for its own solo sweep.
	let bark = ctx.bark_sdk("bark1", &srv)
		.funded(sat(1_000_000))
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.create().await;
	bark.sync().await;
	let vtxos = bark.vtxos().await.unwrap();
	assert_eq!(vtxos.len(), 4, "should hold four board vtxos");
	let max_expiry = vtxos.iter().map(|v| v.vtxo.expiry_height()).max().unwrap();

	let payout = ctx.bitcoind().get_new_address();
	let offboard_txid = bark.offboard_all(payout).await.unwrap().txid;
	let tip = ctx.generate_blocks(1).await;
	// the connector output is the second output of the offboard tx
	let connector_point = bitcoin::OutPoint::new(offboard_txid, 1);

	// Let the input vtxos expire plus half the connector expiry delta:
	// the board outputs get swept, but the connector must be left alone.
	let tip = ctx.generate_blocks(max_expiry.to_u32() + 72 - tip.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let rounds_balance = srv.wallet_status().await.rounds.total_balance;

	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Expired board output sweep: {:#?}", msg);
	assert!(!msg.vtxo_ids.iter().any(|v| v.to_point() == connector_point),
		"connector {} must not be swept before its expiry delta passed", connector_point,
	);
	// the four board outputs
	assert_eq!(800_000, msg.total_input_value.to_sat());

	let client = ctx.bitcoind().sync_client();
	let tip = ctx.generate_blocks(1).await;
	srv.wait_for_sync_height(tip).await;
	assert!(
		client.get_tx_out(&connector_point.txid, connector_point.vout, Some(true)).unwrap().is_some(),
		"connector output {} must still be unspent", connector_point,
	);

	// the swept board outputs must land in the rounds wallet
	let rounds_balance = {
		let new_balance = srv.wallet_status().await.rounds.total_balance;
		assert_eq!(new_balance, rounds_balance + msg.total_output_value,
			"board output sweep must pay out to the rounds wallet",
		);
		new_balance
	};

	// After the other half of the connector expiry delta, the connector
	// dust gets swept as well.
	let tip = ctx.generate_blocks(72).await;
	wm.wait_for_sync_height(tip).await;

	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Offboard connector sweep: {:#?}", msg);
	assert!(msg.vtxo_ids.iter().any(|v| v.to_point() == connector_point),
		"connector {} missing from sweep: {:?}", connector_point, msg.vtxo_ids,
	);
	// the 4 * 330 sat connector output
	assert_eq!(1_320, msg.total_input_value.to_sat());

	// the connector output must actually be gone from the utxo set
	let tip = ctx.generate_blocks(1).await;
	srv.wait_for_sync_height(tip).await;
	assert!(
		client.get_tx_out(&connector_point.txid, connector_point.vout, Some(true)).unwrap().is_none(),
		"connector output {} should be spent by the sweep", connector_point,
	);

	// the connector dust must land in the rounds wallet as well
	assert_eq!(srv.wallet_status().await.rounds.total_balance,
		rounds_balance + msg.total_output_value,
		"connector sweep must pay out to the rounds wallet",
	);
}

/// After an offboard whose input gets maliciously exited, the watchman
/// confiscates the exit output with the presigned forfeit tx. The forfeit
/// output — the input amount plus the connector dust it accumulates — is a
/// plain server keyspend that the watchman must sweep once the input vtxo
/// expires.
#[tokio::test]
async fn watchman_sweeps_offboard_forfeit_after_confiscation() {
	let ctx = TestContext::new("server/watchman_sweeps_offboard_forfeit_after_confiscation").await;
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

	// the forfeit output must actually be gone from the utxo set
	let forfeit_point = msg.vtxo_ids[0].to_point();
	let tip = ctx.generate_blocks(1).await;
	srv.wait_for_sync_height(tip).await;
	assert!(
		client.get_tx_out(&forfeit_point.txid, forfeit_point.vout, Some(true)).unwrap().is_none(),
		"forfeit output {} should be spent by the sweep", forfeit_point,
	);

	// the confiscated funds must land in the rounds wallet
	assert_eq!(srv.wallet_status().await.rounds.total_balance,
		rounds_balance + msg.total_output_value,
		"forfeit sweep must pay out to the rounds wallet",
	);
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

	// Board some funds with bark1
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	// fund the watchman
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(100_000)).await;

	// Clone bark1 before refresh — bark2 retains the stale board vtxo state
	let bark1_old = bark1.full_clone("bark2").await;

	// bark1 refreshes its board vtxo into a round vtxo
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;

	// bark2, holding the stale board vtxo, starts a malicious exit
	bark1_old.start_exit_all().await;

	// Progress until the exit transaction is confirmed on-chain (AwaitingDelta state).
	progress_exit_until_awaiting_delta(&ctx, &bark1_old).await;

	// Advance past watchman's progress grace period
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;

	// first sweep: the watchman broadcasts the forfeit (progress) transaction via CPFP.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	wm.trigger_sweep().await;
	let progress_log = log_progress.recv().wait_millis(10_000).await
		.expect("watchman should broadcast progress (forfeit) tx");

	// Confirm the forfeit tx so the resulting HarkForfeit vtxo enters the frontier.
	ctx.await_transactions_across_nodes([progress_log.cpfp_txid], [wm.bitcoind().as_ref()]).await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	// third sweep: the watchman claims the HarkForfeit vtxo.
	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15_000).await.expect("no claim log");
	failures.assert_empty();
	println!("malicious exit sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	assert_eq!(msg.vtxo_ids[0].to_point().txid, progress_log.txid);
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

/// Runs one deposit -> offboard -> malicious-exit attack and returns how much the
/// attacker managed to claim on-chain ("stole") on top of the offboard payout.
///
/// It boards `n_vtxos`, offboards them all in a single offboard (so for `n >= 2`
/// the server builds a multi-input forfeit), clones the wallet beforehand, then
/// has the clone unilaterally exit the now-forfeited vtxos. It then drives the
/// watchman patiently — interleaving `trigger_sweep` with block confirmations so
/// the watchman can run its full multi-step confiscation (broadcast the connector
/// fanout tx, confirm it, then broadcast the forfeit that spends each exit output).
///
/// If the watchman confiscates every exit output, the attacker cannot double-spend
/// and this returns 0. Otherwise the attacker completes its exit and claims the
/// stranded outputs, and this returns the stolen amount.
async fn offboard_exit_attack(test_name: &str, n_vtxos: usize) -> bitcoin::Amount {
	let ctx = TestContext::new(test_name).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();

	// fund the watchman so it can pay CPFP fees for its forfeit/connector broadcasts
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	// honest wallet boards n vtxos
	let bark = ctx.bark("bark1", &srv).funded(sat(5_000_000)).create().await;
	for _ in 0..n_vtxos {
		bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	}
	bark.sync().await;
	assert_eq!(bark.vtxos().await.len(), n_vtxos, "should hold {} board vtxos", n_vtxos);

	// the board vtxo outputs that a unilateral exit will put on-chain
	let exit_points = bark.vtxo_ids().await.iter().map(|id| id.to_point()).collect::<Vec<_>>();

	// snapshot the wallet BEFORE offboarding; the attacker keeps the stale vtxos
	let evil = bark.full_clone("evil").await;

	// honest offboard: forfeits all n vtxos and receives the payout
	let payout = ctx.bitcoind().get_new_address();
	bark.offboard_all(&payout).await;
	ctx.generate_blocks(1).await;
	let payout_received = ctx.bitcoind().get_received_by_address(&payout);
	assert!(payout_received > sat(0), "server should have paid out the offboard");

	// attacker exits the now-forfeited vtxos (puts the exit outputs on-chain)
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	// Patiently drive the watchman's multi-step confiscation. For a multi-input
	// offboard it must first broadcast the connector fanout tx, get it confirmed,
	// then broadcast the forfeit that spends each exit output. Each sweep it
	// re-CPFPs the shared fanout tx, so only the LAST cpfp txid in a cycle is live
	// (earlier ones get RBF-replaced); we await that one so the package has
	// propagated to the node we mine on before mining.
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
	wm.wait_for_sync_height(tip).await;
	let client = ctx.bitcoind().sync_client();
	// Give the watchman ample, repeated opportunity to run its confiscation. Each
	// cycle triggers a sweep and confirms a block, so it can advance through any
	// multi-step (connector fanout -> forfeit) confiscation. We stop early once the
	// watchman has spent every exit output (single-input offboards), and run the
	// full budget if it never manages to (the multi-input offboard bug).
	for _ in 0..25 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
		if exit_points.iter().all(|p|
			client.get_tx_out(&p.txid, p.vout, Some(true)).unwrap().is_none())
		{
			break;
		}
	}

	// how many exit outputs did the watchman fail to confiscate (still spendable
	// by the attacker)? With a valid forfeit this is 0.
	let unconfiscated = exit_points.iter()
		.filter(|p| client.get_tx_out(&p.txid, p.vout, Some(true)).unwrap().is_some())
		.count();
	println!("{}: {}/{} exit outputs left unconfiscated by the watchman; offboard payout {}",
		test_name, unconfiscated, n_vtxos, payout_received);

	if unconfiscated == 0 {
		return sat(0);
	}

	// the watchman failed: attacker completes the double-spend and claims the funds
	complete_exit(&ctx, &evil).await;
	let thief = ctx.bitcoind().get_new_address();
	evil.claim_all_exits(thief.clone()).await;
	ctx.generate_blocks(1).await;
	let stolen = ctx.bitcoind().get_received_by_address(&thief);
	println!("{}: attacker double-spent {} on top of the {} offboard payout",
		test_name, stolen, payout_received);
	stolen
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

/// Driver sanity check: a SINGLE-input offboard forfeit is valid, so the watchman
/// MUST be able to confiscate a malicious post-offboard exit. If this fails, the
/// test harness (not the protocol) is at fault — so it guards the meaning of
/// `multi_input_offboard_double_spend` below.
#[tokio::test]
async fn watchman_defends_single_input_offboard_exit() {
	let stolen = offboard_exit_attack("server/watchman_defends_single_input_offboard_exit", 1).await;
	assert_eq!(stolen, sat(0),
		"single-input offboard: watchman should have confiscated the exit, attacker got {}", stolen);
}

/// The bug, end-to-end: a MULTI-input offboard forfeit is consensus-invalid, so the
/// watchman cannot confiscate a malicious post-offboard exit and the attacker
/// double-spends (keeps both the offboard payout and the exited vtxo value).
///
/// This asserts the SECURE outcome, so it is RED on the bug and GREEN once the
/// forfeit-prevout fix is applied — which is how we confirm the fix is a real
/// end-to-end fix, paired with `watchman_defends_single_input_offboard_exit`
/// proving the watchman can defend at all.
#[tokio::test]
async fn watchman_defends_multi_input_offboard_exit() {
	let stolen = offboard_exit_attack("server/watchman_defends_multi_input_offboard_exit", 2).await;
	assert_eq!(stolen, sat(0),
		"multi-input offboard double-spend was NOT prevented; attacker stole {}", stolen);
}

/// How far the unilateral exit is driven before the stale clone tries to
/// offboard the same vtxo.
#[derive(Copy, Clone, Debug)]
enum ExitDepth {
	/// The exit tx is confirmed but its output is still unspent, so a forfeit
	/// could still confiscate it.
	TxConfirmed,
	/// The exit output has been claimed by the user, so no forfeit can ever
	/// spend it again.
	Claimed,
}

/// Outcome of an "exit the vtxo first, then offboard it anyway" attempt.
struct OffboardAfterExit {
	/// The server's refusal, if it refused the offboard.
	refusal: Option<String>,
	/// What the offboard payout address received on chain.
	payout: bitcoin::Amount,
	/// The number of exit outputs still unspent after the watchman had every
	/// chance to confiscate them.
	unconfiscated: usize,
}

/// Boards one vtxo, unilaterally exits it as far as `depth` says, then has a
/// stale clone of the same wallet offboard that same vtxo. The clone runs with
/// `--no-sync` so it never notices the exit, which models a modified client:
/// the server never sees client vtxo state, so accepting or refusing the
/// offboard is entirely the server's call.
async fn offboard_after_exit(test_name: &str, depth: ExitDepth) -> OffboardAfterExit {
	let ctx = TestContext::new(test_name).await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let wm = srv.watchmand();

	// fund the watchman so it can pay CPFP fees for any confiscation broadcast
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark.sync().await;
	let vtxo_ids = bark.vtxo_ids().await;
	assert_eq!(vtxo_ids.len(), 1, "should hold exactly one board vtxo");
	// the output a unilateral exit of this vtxo puts on chain
	let exit_point = vtxo_ids[0].to_point();

	// snapshot before the exit, so the clone still believes the vtxo is spendable
	let stale = bark.full_clone("stale").await;

	// the wallet unilaterally exits the vtxo
	bark.start_exit_all().await;
	let client = ctx.bitcoind().sync_client();
	match depth {
		ExitDepth::TxConfirmed => {
			progress_exit_until_awaiting_delta(&ctx, &bark).await;
			assert!(
				client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_some(),
				"exit output {} should be on chain and still unspent", exit_point,
			);
		},
		ExitDepth::Claimed => {
			complete_exit(&ctx, &bark).await;
			let thief = ctx.bitcoind().get_new_address();
			bark.claim_all_exits(&thief).await;
			ctx.generate_blocks(1).await;
			assert!(ctx.bitcoind().get_received_by_address(&thief) > sat(0),
				"the exit should have been claimed on chain",
			);
			assert!(
				client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none(),
				"exit output {} should have been spent by the claim", exit_point,
			);
		},
	}

	// the stale clone now offboards the very same vtxo
	let payout = ctx.bitcoind().get_new_address();
	let refusal = match stale.try_offboard_all_no_sync(&payout).await {
		Ok(out) => {
			println!("{}: server ACCEPTED the offboard: {}", test_name, out);
			None
		},
		Err(e) => {
			let msg = format!("{:#}", e);
			println!("{}: server refused the offboard: {}", test_name, msg);
			Some(msg)
		},
	};
	ctx.generate_blocks(1).await;
	let payout_received = ctx.bitcoind().get_received_by_address(&payout);

	// If the server paid out, give the watchman every chance to cash in the
	// forfeit before we call the exit output unconfiscated.
	let exit_output_live = || {
		client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_some()
	};
	if payout_received > sat(0) && exit_output_live() {
		let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period.to_u32()).await;
		wm.wait_for_sync_height(tip).await;
		for _ in 0..25 {
			wm.trigger_sweep().await;
			tokio::time::sleep(Duration::from_secs(2)).await;
			let tip = ctx.generate_blocks(1).await;
			wm.wait_for_sync_height(tip).await;
			if !exit_output_live() {
				break;
			}
		}
	}
	let unconfiscated = if exit_output_live() { 1 } else { 0 };

	println!("{}: refused={} payout={} unconfiscated={}",
		test_name, refusal.is_some(), payout_received, unconfiscated,
	);
	OffboardAfterExit { refusal, payout: payout_received, unconfiscated }
}

/// The regression test: a vtxo whose exit was fully claimed must not be
/// offboardable. The claimed exit output is already spent, so a forfeit can
/// never confiscate it and paying out the offboard is a straight loss for the
/// server. This test is red without the exit gate in `prepare_offboard` and
/// green with it.
#[tokio::test]
async fn server_refuses_offboard_of_claimed_exited_vtxo() {
	let res = offboard_after_exit(
		"server/server_refuses_offboard_of_claimed_exited_vtxo", ExitDepth::Claimed,
	).await;

	let refusal = res.refusal.expect(
		"server accepted an offboard of a vtxo whose exit was already claimed",
	);
	let refusal_msg = refusal.to_lowercase();
	assert!(refusal_msg.contains("exit") || refusal_msg.contains("unusable"),
		"expected an 'already exited' refusal from the server, got: {}", refusal,
	);
	assert_eq!(res.payout, sat(0),
		"the offboard was refused, so the payout address must have received nothing, got {}",
		res.payout,
	);
}

/// Control for [server_refuses_offboard_of_claimed_exited_vtxo]: the same flow,
/// but the exit stops once the exit tx confirms, so its output is still unspent
/// and a forfeit could still confiscate it. This only asserts the invariant
/// that holds with and without the exit gate: the server never ends up out of
/// pocket, because it either refuses the offboard or pays out and the watchman
/// confiscates the exit output.
#[tokio::test]
async fn offboard_of_confirmed_exited_vtxo_never_costs_server() {
	let res = offboard_after_exit(
		"server/offboard_of_confirmed_exited_vtxo_never_costs_server", ExitDepth::TxConfirmed,
	).await;

	assert!(res.payout == sat(0) || res.unconfiscated == 0,
		"server paid out {} for an exited vtxo and {} exit output(s) were left unconfiscated",
		res.payout, res.unconfiscated,
	);
	if let Some(ref refusal) = res.refusal {
		let refusal_msg = refusal.to_lowercase();
		assert!(refusal_msg.contains("exit") || refusal_msg.contains("unusable"),
			"expected an 'already exited' refusal from the server, got: {}", refusal,
		);
	}
}
