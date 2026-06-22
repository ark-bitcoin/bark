
use std::sync::Arc;
use std::time::Duration;

use log::{error, warn};
use parking_lot::Mutex;
use bitcoincore_rpc::RpcApi;

use bark_json::primitives::VtxoStateInfo;
use bitcoin_ext::rpc::BitcoinRpcExt;
use bitcoin_ext::TxStatus;
use server::config::OptionalService;
use server::vtxopool::VtxoTarget;
use server_log::{
	ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure, ProgressBroadcast,
	ProgressCpfpFailure,
};

use ark_testing::{Bark, TestContext, btc, require_bark_version, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::SlogHandler;
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};
use ark_testing::util::{BarkVersion, FutureExt};

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
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	let _ = bark1.board(sat(100_000)).await;
	ctx.generate_blocks(2 * BOARD_CONFIRMATIONS).await;
	let _ = bark1.offchain_balance().await;

	ctx.refresh_all(&srv, &[&bark1]).await;

	// expire only the board, not the refresh
	let tip = ctx.generate_blocks(
		srv.config().vtxo_lifetime as u32 - 2 * BOARD_CONFIRMATIONS + 2,
	).await;
	wm.wait_for_sync_height(tip as u32).await;

	wm.trigger_sweep().await;
	let msg = log_claim.recv().wait_millis(15000).await.expect("no claim log");
	failures.assert_empty();
	println!("Board sweep: {:#?}", msg);
	assert_eq!(1, msg.vtxo_ids.len());
	// rounds didnt' expire yet
	assert_eq!(100_000, msg.total_input_value.to_sat());
	assert_eq!(99_093, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_round_vtxos() {
	let ctx = TestContext::new("server/watchman_sweeps_round_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_sender_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_receiver_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	// only change
	assert_eq!(1, msg.vtxo_ids.len());
	assert_eq!(250_000, msg.total_input_value.to_sat());
	assert_eq!(249_093, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_lightning_vtxos() {
	let ctx = TestContext::new("server/watchman_sweeps_lightning_vtxos").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 10, amount: sat(10_000) },
		];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_round_leftovers_after_exits").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
		cfg.watchman.claim_chunksize = 20.try_into().unwrap();
	}).create(&srv).await;
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
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_vtxopool_with_exit").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").funded(btc(10)).lightningd(&ln.internal).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![
			// total: 300_099_000
			VtxoTarget { count: 9, amount: sat(1_000) },
			VtxoTarget { count: 9, amount: sat(10_000) },
			VtxoTarget { count: 3, amount: btc(1) },
		];
		cfg.vtxopool.vtxo_lifetime = 144;
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
			// should exit the 250k change vtxo
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
	assert_eq!(300_094_905, msg.total_output_value.to_sat());
}

#[tokio::test]
async fn watchman_sweeps_exit_after_forfeit() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_exit_after_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period as u32).await;
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

/// After bark1 and bark2 both board and refresh into round vtxos, bark1 gets cloned.
/// One clone sends an OOR payment to bark2 and bark2 refreshes (forfeiting the OOR vtxo
/// in a round), which makes the server store the signed OOR transaction and set
/// server_may_own_descendant on bark1's round vtxo exit tx. The other clone (bark1_old)
/// then attempts a malicious exit with its stale round vtxo. The watchman detects this
/// and blocks the exit by broadcasting the OOR transaction as a progress step via CPFP.
#[tokio::test]
async fn watchman_sweeps_exit_after_oor_then_forfeit() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/watchman_sweeps_exit_after_oor_then_forfeit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period as u32).await;
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
		srv.config().vtxo_lifetime as u32 - 2 * ROUND_CONFIRMATIONS + 3,
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
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;

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
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period as u32).await;
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

/// A *lightning-receive* VTXO can be force-exited on-chain by the *watchman* (not by the owner)
/// when a third party exits the shared round tree and drags the VTXO's parent on-chain. The fix
/// (bark >= 0.2.6) checkpoints the claim, giving the watchman a stopping point: it broadcasts the
/// checkpoint but never the user's leaf, so the leaf stays a refreshable off-chain VTXO.
///
/// This test pins the fix at the 0.2.6 boundary by branching on the bark client version:
/// - bark >= 0.2.6 (incl. DIRTY working-tree builds): the leaf is NOT force-exited; it stays
///   `Spendable`, off-chain, and refreshable.
/// - bark < 0.2.6: the pre-fix behaviour — the leaf is force-exited and the server rejects refresh
///   via `check_vtxos_not_exited`.
///
/// The `safe` wallet (which spends its receive to itself, adding a checkpoint) is a control that is
/// never force-exited in either case.
#[tokio::test]
async fn watchman_force_exit_lightning_vtxo_blocks_refresh() {
	let ctx = TestContext::new("server/watchman_force_exit_lightning_vtxo_blocks_refresh").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").lightningd(&ln.internal).funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		// One pool vtxo per receiver. The round tree has radix 4 (`ark::tree` RADIX), so up
		// to 4 leaves sit directly under the root - with 3 they are siblings. Exiting one
		// receiver broadcasts the shared root, dragging the others' HTLC sources on-chain,
		// and the watchman then progresses down to each leaf. (The pool can't reuse change,
		// so it needs one vtxo per receiver; a single vtxo can't serve three receives)
		cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 3, amount: sat(100_000) }];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	// Fund the watchman so it can pay CPFP fees for its progress broadcasts.
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;

	let attacker = Arc::new(ctx.bark("attacker", &srv).funded(sat(1_000_000)).create().await);
	let victim = Arc::new(ctx.bark("victim", &srv).funded(sat(1_000_000)).create().await);
	let safe = Arc::new(ctx.bark("safe", &srv).funded(sat(1_000_000)).create().await);
	srv.wait_for_vtxopool(&ctx).await;

	// Receive sequentially for deterministic input assignment, `attacker` first. Each
	// HOLDS its claimed vtxo (no exit, no refresh).
	for receiver in [attacker.clone(), victim.clone(), safe.clone()] {
		let invoice = receiver.bolt11_invoice(sat(50_000)).await.invoice;
		let receiver_bark = receiver.clone();
		tokio::join!(
			ln.external.pay_bolt11(&invoice),
			async move { receiver_bark.lightning_receive_all().wait_millis(60_000).await; },
		);
	}
	let victim_vtxo = {
		victim.sync().await;
		let vtxos = victim.vtxos().await;
		let v = vtxos.iter().find(|v| matches!(v.state, VtxoStateInfo::Spendable))
			.expect("victim should hold a spendable received vtxo");
		v.id
	};
	let victim_txid = victim_vtxo.to_point().txid;
	let safe_vtxo = {
		safe.sync().await;
		let vtxos = safe.vtxos().await;
		let old = vtxos.iter().find(|v| matches!(v.state, VtxoStateInfo::Spendable))
			.expect("safe should hold a spendable ln-receive vtxo");
		// Send to self to make the VTXO safe.
		safe.send_oor(safe.address().await, sat(40_000)).await;
		let vtxos = safe.vtxos().await;
		let new = vtxos.iter().find(|v| matches!(v.state, VtxoStateInfo::Spendable))
			.expect("safe should hold a spendable arkoor vtxo");
		assert_ne!(old.id, new.id);
		new.id
	};
	let safe_txid = safe_vtxo.to_point().txid;

	// The attacker unilaterally exits its received vtxo, broadcasting the shared pool
	// tree and dragging the victim's HTLC source on-chain.
	attacker.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &attacker).await;

	// Drive the watchman. With the victim's source now on-chain, it progresses the
	// checkpoint-free chain down to the victim's leaf, force-exiting it.
	let mut log_progress = wm.subscribe_log::<ProgressBroadcast>();
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period as u32).await;
	wm.wait_for_sync_height(tip).await;

	let mut forced = false;
	let mut any_progress = false;
	for _ in 0..25 {
		wm.trigger_sweep().await;
		tokio::time::sleep(Duration::from_secs(2)).await;
		while let Ok(p) = log_progress.try_recv() {
			println!("ProgressBroadcast vtxo_id={} txid={}", p.vtxo_id, p.txid);
			any_progress = true;
			ctx.await_transactions_across_nodes([p.cpfp_txid], [wm.bitcoind().as_ref()]).await;
			if p.txid == victim_txid {
				forced = true;
			}
			assert_ne!(p.txid, safe_txid, "the safe VTXO should not be broadcast");
		}
		let tip = ctx.generate_blocks(1).await;
		wm.wait_for_sync_height(tip).await;
	}
	// The fix (bark >= 0.2.6, incl. DIRTY working-tree builds) checkpoints the claim, so the
	// watchman stops at the checkpoint and never broadcasts the victim's leaf; older bark builds
	// the checkpoint-free claim and the watchman force-exits the leaf.
	let version = BarkVersion::parse(&Bark::version().await);
	if version >= BarkVersion::parse("0.2.6") {
		// Fixed: the leaf was not force-exited and stays a refreshable off-chain VTXO.
		// Guard against a vacuous pass: the watchman must have actually progressed the
		// dragged-on-chain tree (up to the checkpoint), otherwise `!forced` proves nothing.
		assert!(any_progress,
			"watchman never broadcast any progress; the checkpoint-stop assertion is vacuous",
		);
		assert!(!forced,
			"watchman must not force-exit the checkpointed ln leaf {}", victim_txid,
		);
		let vtxos = victim.vtxos().await;
		let v = vtxos.iter().find(|v| v.id == victim_vtxo).expect("victim vtxo disappeared");
		assert!(matches!(v.state, VtxoStateInfo::Spendable),
			"victim ln leaf must stay Spendable, was {:?}", v.state,
		);
		let status = ctx.bitcoind().sync_client().tx_status(victim_txid)
			.expect("status should succeed");
		assert!(matches!(status, TxStatus::NotFound),
			"victim ln leaf must not be on-chain, status was {:?}", status,
		);
		let (res, _) = tokio::join!(
			victim.try_refresh_all_no_retry(),
			srv.trigger_round(),
		);
		assert!(res.is_ok(),
			"refresh of the non-force-exited ln leaf must succeed: {:?}", res,
		);
	} else {
		// Pre-fix: the leaf was force-exited and the server rejects refresh.
		assert!(forced,
			"watchman never broadcast the victim's lightning vtxo funding tx {}; force-exit did not occur",
			victim_txid,
		);
		let (res, _) = tokio::join!(
			victim.try_refresh_all_no_retry(),
			srv.trigger_round(),
		);
		let err = res.expect_err("refresh of a force-exited vtxo must be rejected by the server");
		let msg = format!("{:#}", err).to_lowercase();
		assert!(msg.contains("exit"),
			"expected an 'already exited' rejection from the server, got: {}", msg,
		);
	}
	failures.assert_empty();

	// The safe VTXO should not have been broadcast because it's protected by the spend.
	let vtxos = safe.vtxos().await; // syncs
	let state = vtxos.iter().find(|v| v.id == safe_vtxo).map(|v| format!("{:?}", v.state));
	println!("safe {} state on client after force-exit: {:?}", safe_vtxo, state);

	// The server accepts the input because it shouldn't be exited during round registration.
	let (res, _) = tokio::join!(
		safe.try_refresh_all_no_retry(),
		srv.trigger_round(),
	);
	assert!(res.is_ok(), "server should accept the safe vtxo during round registration");
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
	let ctx = TestContext::new("server/watchman_force_exit_checkpointed_arkoor_stays_spendable").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_secs(15 * 60);
	}).create(&srv).await;
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
	let tip = ctx.generate_blocks(wm.config().watchman.progress_grace_period as u32).await;
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
	require_bark_version!(> "0.2.0");
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
	require_bark_version!(> "0.2.0");
	let stolen = offboard_exit_attack("server/watchman_defends_multi_input_offboard_exit", 2).await;
	assert_eq!(stolen, sat(0),
		"multi-input offboard double-spend was NOT prevented; attacker stole {}", stolen);
}
