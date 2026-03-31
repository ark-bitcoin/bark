
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use log::{error, warn};
use parking_lot::Mutex;
use server::config::OptionalService;
use server::vtxopool::VtxoTarget;
use server_log::{
	ClaimBroadcast, ClaimBroadcastFailure, ClaimChunkBroadcastFailure, ProgressCpfpFailure,
};

use ark_testing::{TestContext, btc, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::SlogHandler;
use ark_testing::exit::complete_exit;
use ark_testing::util::{FutureExt, ReceiverExt};


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
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(200_000)).await;

	let _ = bark1.board(sat(100_000)).await;
	ctx.generate_blocks(100).await;
	let _ = bark1.offchain_balance().await;

	ctx.refresh_all(&srv, &[&bark1]).await;

	ctx.generate_blocks(50).await;

	let msgs = log_claim.collect_for(Duration::from_millis(10000)).await;
	failures.assert_empty();
	println!("Board sweep: {:#?}", msgs);
	assert_eq!(1, msgs.iter().map(|m| m.vtxo_ids.len()).sum::<usize>());
	// rounds didnt' expire yet
	assert_eq!(100_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
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
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(500_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(500_000)).await;

	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	// Create round vtxos by doing a payment
	ctx.refresh_all(&srv, &[&bark1, &bark2]).await;

	// Wait for round to be confirmed so watchman can track the vtxos
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;

	// Wait for vtxos to expire (144 blocks from their creation)
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired server-owned vtxos from the round
	// (checkpoint vtxos or other intermediate vtxos created during round processing)
	let msgs = log_claim.collect_for(Duration::from_millis(15000)).await;
	failures.assert_empty();
	println!("Round vtxo sweep: {:#?}", msgs);
	assert_eq!(3, msgs.iter().map(|m| m.vtxo_ids.len()).sum::<usize>());
	assert_eq!(800_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_sender_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_sender_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await);
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	bark1.send_oor(bark2.address().await, sat(50_000)).await;

	bark1.sync().await;
	bark2.sync().await;

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
	bark1.claim_all_exits(bark1.get_onchain_address().await).await;

	// Wait for the HTLC vtxos to expire
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired HTLC vtxos
	let msgs = log_claim.collect_for(Duration::from_millis(5000)).await;
	failures.assert_empty();
	println!("arkoor vtxo sweep: {:#?}", msgs);
	// 1 boards and 1 change
	assert_eq!(2, msgs[0].vtxo_ids.len());
	assert_eq!(350_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
}

#[tokio::test]
async fn watchman_sweeps_arkoor_vtxos_receiver_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_arkoor_vtxos_receiver_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await);
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await);

	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	bark1.send_oor(bark2.address().await, sat(50_000)).await;

	bark1.sync().await;
	bark2.sync().await;

	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;
	bark2.claim_all_exits(bark2.get_onchain_address().await).await;

	// Wait for the HTLC vtxos to expire
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired HTLC vtxos
	let msgs = log_claim.collect_for(Duration::from_millis(5000)).await;
	failures.assert_empty();
	println!("arkoor vtxo sweep: {:#?}", msgs);
	// only change
	assert_eq!(1, msgs[0].vtxo_ids.len());
	assert_eq!(250_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
}

#[tokio::test]
async fn watchman_sweeps_lightning_vtxos() {
	let ctx = TestContext::new("server/watchman_sweeps_lightning_vtxos").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").lightningd(&ln.sender).funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 10, amount: sat(10_000) },
		];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await);
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await);

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
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired HTLC vtxos
	let msgs = log_claim.collect_for(Duration::from_millis(5000)).await;
	failures.assert_empty();
	println!("Lightning vtxo sweep: {:#?}", msgs);
	assert_eq!(1, msgs.len());
	// 2 boards and 1 vtxopool root
	assert_eq!(3, msgs[0].vtxo_ids.len());
	assert_eq!(700_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
}

#[tokio::test]
async fn watchman_sweeps_round_leftovers_after_exits() {
	let ctx = TestContext::new("server/watchman_sweeps_round_leftovers_after_exits").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.watchman = OptionalService::Disabled;
		cfg.vtxo_lifetime = 144;
		cfg.vtxopool.vtxo_targets = vec![];
	}).create().await;
	let failures = WatchmanFailureCollector::default();
	let wm = ctx.watchmand("watchman").cfg(|cfg| {
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();

	// Create 10 barks
	let mut barks = Vec::new();
	for i in 0..10 {
		let bark = ctx.new_bark_with_funds(&format!("bark{}", i), &srv, sat(500_000)).await;
		bark.board(sat(200_000)).await;
		barks.push(bark);
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

	ctx.generate_blocks(1).await;

	// Wait for remaining vtxos to expire
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired server-owned vtxos from the round
	// After exits, there are still server-side vtxos (checkpoints, connectors, etc.) to sweep
	let msgs = log_claim.collect_for(Duration::from_millis(15000)).await;
	failures.assert_empty();
	println!("Round leftovers sweep: {:#?}", msgs);
	assert_eq!(Amount::from_sat(3_600_000), msgs.iter().map(|m| m.total_input_value).sum::<Amount>(),
		"Watchman should sweep expired vtxos after some users exit",
	);
}

#[tokio::test]
async fn watchman_sweeps_vtxopool_with_exit() {
	let ctx = TestContext::new("server/watchman_sweeps_vtxopool_with_exit").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.captaind("server").funded(btc(10)).lightningd(&ln.sender).cfg(|cfg| {
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
		cfg.watchman.process_interval = Duration::from_millis(500);
	}).create(&srv).await;
	wm.add_slog_handler(failures.clone());

	let mut log_claim = wm.subscribe_log::<ClaimBroadcast>();
	let bark1 = Arc::new(ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await);
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await);

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
	ctx.generate_blocks(150).await;

	// Watchman should sweep the expired HTLC vtxos
	let msgs = log_claim.collect_for(Duration::from_millis(10000)).await;
	failures.assert_empty();
	println!("Lightning vtxo sweep: {:#?}", msgs);
	assert_eq!(300_099_000, msgs.iter().map(|m| m.total_input_value).sum::<Amount>().to_sat());
}
