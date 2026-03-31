use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use futures::future::join_all;
use log::{debug, info, trace};
use tokio_stream::StreamExt;

use ark::{VtxoPolicy, VtxoRequest};
use ark::rounds::RoundEvent;
use ark::vtxo::policy::PubkeyVtxoPolicy;
use bark::persist::models::{StoredRoundState, Unlocked};
use bark::round::RoundParticipation;
use bark::subsystem::RoundMovement;
use bark::vtxo::VtxoState;
use server_log::{AttemptingRound, RestartMissingVtxoSigs, RoundFinished, RoundUserVtxoNotAllowed};
use server_rpc::protos;

use ark_testing::{btc, sat, signed_sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;

#[tokio::test]
async fn large_round() {
	let ctx = TestContext::new("bark/large_round").await;
	#[cfg(not(feature = "slow_test"))]
	const N: usize = 9;
	#[cfg(feature = "slow_test")]
	const N: usize = 74;

	info!("Running multiple_round_test with N set to {}", N);

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.round_sign_time = Duration::from_millis(1000 * N as u64);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let barks = join_all((0..N).map(|i| {
		let name = format!("bark{}", i);
		ctx.new_bark_with_funds(name, &srv, sat(90_000))
	})).await;
	ctx.generate_blocks(1).await;

	// Fund and board all clients.
	for chunk in barks.chunks(20) {
		join_all(chunk.iter().map(|b| async {
			b.board(sat(80_000)).await;
		})).await;
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark_refs = barks.iter().collect::<Vec<_>>();
	ctx.refresh_all(&srv, &bark_refs).await;
}

#[tokio::test]
async fn refresh_all() {
	let ctx = TestContext::new("bark/refresh_all").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board(sat(400_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	bark1.board_and_confirm_and_register(&ctx, sat(400_000)).await;

	// We want bark2 to have a refresh, board, round and oor vtxo
	let pk1 = bark1.address().await;
	let pk2 = bark2.address().await;
	bark2.send_oor(&pk1, sat(20_000)).await; // generates change
	bark1.send_oor(&pk2, sat(20_000)).await;
	bark2.board(sat(20_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(3, bark2.vtxos().await.len());
	ctx.refresh_all(&srv, &[&bark2]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	assert_eq!(1, bark2.vtxos().await.len());
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn refresh_counterparty() {
	let ctx = TestContext::new("bark/refresh_counterparty").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let (arkoor_vtxo, others): (Vec<_>, Vec<_>) = bark1.vtxos().await
		.into_iter()
		.partition(|v| v.amount == sat(330_000));

	tokio::join!(
		srv.trigger_round(),
		bark1.refresh_counterparty(),
	);
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let vtxos = bark1.vtxos().await;
	// there should still be 3 vtxos
	assert_eq!(3, vtxos.len(), "vtxos: {:?}", vtxos);
	// received oor vtxo should be refreshed
	assert!(!vtxos.iter().any(|v| v.id == arkoor_vtxo.first().unwrap().id));
	// others should remain untouched
	assert!(others.iter().all(|o| vtxos.iter().any(|v| v.id == o.id)));
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn second_round_attempt() {
	//! test that we can recover from an error in the round

	/// This proxy will drop the very first request to provide_vtxo_signatures.
	#[derive(Clone)]
	struct Proxy;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn provide_vtxo_signatures(
			&self, _upstream: &mut ArkClient, _req: protos::VtxoSignaturesRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Ok(protos::Empty {})
		}
	}

	let ctx = TestContext::new("bark/second_round_attempt").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;
	bark1.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	let bark2 = ctx.new_bark("bark2".to_string(), &srv).await;
	let bark2_addr = bark2.address().await;

	// Send arkoor package to mailbox
	bark1.send_oor(bark2_addr, sat(200_000)).await;
	let bark2_vtxo = bark2.vtxos().await.get(0).expect("should have 1 vtxo").id;

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;
	bark2.set_ark_url(&proxy.address).await;

	let mut log_not_allowed = srv.subscribe_log::<RoundUserVtxoNotAllowed>();

	ctx.generate_blocks(1).await;
	let (res1, _res2, ()) = tokio::join!(
		bark1.try_refresh_all_no_retry(),
		bark2.try_refresh_all_no_retry(),
		async {
			tokio::time::sleep(Duration::from_millis(500)).await;
			let _ = srv.wallet_status().await;
			let mut log_restart_missing_sigs = srv.subscribe_log::<RestartMissingVtxoSigs>();
			srv.trigger_round().await;
			log_restart_missing_sigs.recv().wait(Duration::from_secs(60)).await.unwrap();
		},
	);
	info!("Checking bark1 succeeded...");
	res1.expect("bark1 should have refreshed successfully");
	// check that bark2 was kicked with the correct log message
	assert_eq!(log_not_allowed.recv().ready().await.unwrap().vtxo, bark2_vtxo);
}

#[tokio::test]
async fn bark_can_sign_up_to_round_during_signup_phase() {
	//! Test that a bark client can sign up to a round that has already started.
	//!
	//! This simulates a real-world scenario where a phone wakes up (e.g., from a
	//! push notification) after a round has already begun. The client should be
	//! able to join the ongoing round during the signup phase, even though it
	//! wasn't listening when the round started.

	let ctx = TestContext::new("bark/bark_can_sign_up_to_round_during_signup_phase").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	// Subscribe to logs before triggering
	let mut log_round_finished = srv.subscribe_log::<RoundFinished>();
	let mut log_attempting_round = srv.subscribe_log::<AttemptingRound>();

	// Trigger the round BEFORE the bark starts refresh_all
	srv.trigger_round().await;

	// Wait for the round attempt to be broadcast. This ensures the round is actually started.
	log_attempting_round.recv().wait(Duration::from_secs(10)).await.unwrap();

	// Now bark tries to join the already-started round.
	// Use a timeout so the test fails instead of hanging if bark can't join.
	// Use no_retry to test the direct join-in-progress behavior.
	bark.refresh_all_no_retry().wait(Duration::from_secs(60)).await;

	// Verify the round finished successfully with our vtxo
	let finished = log_round_finished.recv().wait(Duration::from_secs(30)).await.unwrap();
	assert_eq!(finished.nb_input_vtxos, 1);
}

#[tokio::test]
async fn delegated_maintenance_refresh() {
	let ctx = TestContext::new("bark/delegated_maintenance_refresh").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// Board funds and confirm
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	// Let vtxo almost expire so it needs refresh
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32).await;

	// Call delegated maintenance - should return immediately
	bark.maintain_delegated().await;

	// Trigger a round so the server can complete the delegated refresh
	srv.trigger_round().await;

	// Check that a pending refresh movement was created
	let movements = bark.history().await;
	let refresh_movement = movements.iter().find(|m| {
		m.subsystem.name == "bark.round" &&
		m.subsystem.kind == "refresh" &&
		m.status == bark_json::cli::MovementStatus::Pending
	}).expect("should have pending refresh movement");
	let movement_id = refresh_movement.id;

	info!("Found pending refresh movement: {:?}", movement_id);

	// Wait loop: call sync() until the movement shows success
	let mut success = false;
	for i in 0..100 {
		// Sync the wallet
		bark.sync().await;

		// Check movement status
		let movements = bark.history().await;
		if let Some(movement) = movements.iter().find(|m| m.id == movement_id) {
			info!("Movement status: {:?}", movement.status);
			if movement.status == bark_json::cli::MovementStatus::Successful {
				success = true;
				break;
			}
		}

		// Wait a bit and generate blocks to progress the round
		if i % 5 == 0 {
			ctx.generate_blocks(1).await;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	assert!(success, "refresh movement should complete successfully");

	// Verify that the vtxo was refreshed
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "should still have one vtxo after refresh");
	assert_eq!(vtxos[0].amount, sat(800_000));
}

async fn print_pending_rounds(wallet: &bark::Wallet) -> Vec<StoredRoundState<Unlocked>> {
	let states = wallet.pending_round_states().await.unwrap();
	info!("Wallet has {} pending round states:", states.len());
	for state in &states {
		info!("  - {}", state.id());
	}
	states
}

#[tokio::test]
async fn stepwise_round() {
	//! this test tests that the bark rust api can be used to participate
	//! in rounds stepwise by manually feeding events into the wallet

	let ctx = TestContext::new("bark/stepwise_round").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	// let vtxo almost expire
	ctx.generate_blocks(srv.config().vtxo_lifetime as u32 - BOARD_CONFIRMATIONS).await;

	let bark = bark.client().await; // explicitly override name to avoid cli usage

	let inputs = bark.get_vtxos_to_refresh().await.unwrap();
	assert_eq!(inputs.len(), 1);
	info!("refreshing {}", inputs[0].vtxo.id());

	let participation = RoundParticipation {
		inputs: vec![inputs[0].vtxo.clone()],
		outputs: vec![VtxoRequest {
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy {
				user_pubkey: bark.derive_store_next_keypair().await.unwrap().0.public_key(),
			}),
			amount: inputs[0].vtxo.amount(),
		}],
	};

	let state_id = bark.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap().id();

	info!("Signed up for round, state_id={}", state_id);
	print_pending_rounds(&bark).await;
	assert_eq!(bark.balance().await.unwrap().pending_in_round, sat(800_000));

	let mut rpc = srv.get_public_rpc().await;
	let mut events = rpc.subscribe_rounds(protos::Empty{}).await.unwrap().into_inner();

	// Trigger a round manually so bark cannot be late for an automatic round
	srv.trigger_round().await;

	while let Some(item) = events.next().await {
		let event = RoundEvent::try_from(item.unwrap()).unwrap();
		info!("Received round event of type: {}", event.kind());

		bark.progress_pending_rounds(Some(&event)).await.unwrap();
		// test idempotency
		bark.progress_pending_rounds(Some(&event)).await.unwrap();

		let states = print_pending_rounds(&bark).await;
		if let Some(ours) = states.into_iter().find(|s| s.id() == state_id) {
			let mut ours = bark.lock_wait_round_state(ours.id()).await.unwrap().unwrap();
			if !ours.state().ongoing_participation() {
				info!("Round finished");
				break;
			} else {
				if let RoundEvent::Finished(_) = event {
					let status = ours.state_mut().sync(&bark).await.unwrap();
					panic!("Our round state says ongoing participation but we just got round \
						finished event. status: {:?}", status,
					);
				}
			}
		} else {
			panic!("our round is gone");
		}

		trace!("waiting for next event...");
	}
	drop(events);

	info!("Starting to wait for confirmations");

	loop {
		ctx.generate_blocks(1).await;
		trace!("Syncing pending rounds");
		bark.sync_pending_rounds().await.unwrap();

		let states = print_pending_rounds(&bark).await;
		if let Some(ours) = states.into_iter().find(|s| s.id() == state_id) {
			let mut ours = bark.lock_wait_round_state(ours.id()).await.unwrap().unwrap();
			debug!("Result: {:#?}", ours.state_mut().sync(&bark).await);
		} else {
			info!("Our state is gone!");
			break;
		}

		tokio::time::sleep(Duration::from_millis(500)).await;
	}

	//TODO(stevenroose) test new vtxo state and movement
}

#[tokio::test]
async fn multiple_round_participations_dont_race() {
	let ctx = TestContext::new("bark/multiple_round_participations_dont_race").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// Board some sats and wait for confirmation
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	let wallet = bark.client().await;

	// Record the initial vtxo before refresh
	let [old_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	let old_vtxo_id = old_vtxo.vtxo.id();

	// Build participation and join the round once, locking the vtxo.
	let participation = wallet.build_refresh_participation(vec![old_vtxo_id]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();

	// Now fire 100 concurrent participate_ongoing_rounds together with a
	// round trigger. All 100 load the same stored round state and race on
	// processing the same round events, bypassing the vtxo lock.
	let ongoing_futs = (0..100).map(|_| wallet.participate_ongoing_rounds());

	let (_, results) = tokio::join!(
		srv.trigger_round(),
		join_all(ongoing_futs).wait_millis(20_000),
	);

	// Verify all participations completed without error
	for (i, r) in results.iter().enumerate() {
		r.as_ref().unwrap_or_else(|e| panic!("participation {} failed: {:#}", i, e));
	}

	// Confirm the round and sync the wallet
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	// Verify old vtxo is spent
	let old_vtxo = wallet.get_vtxo_by_id(old_vtxo_id).await.unwrap();
	assert_eq!(old_vtxo.state, VtxoState::Spent, "old vtxo should be spent");

	// Verify a new vtxo was created and it is different from the old one
	let [new_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo after refresh");
	assert_ne!(old_vtxo_id, new_vtxo.vtxo.id(), "old and new vtxo should not be the same");

	// Offboard the new vtxo to prove it is spendable
	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.unwrap();
	ctx.generate_blocks(1).await;

	let received = ctx.bitcoind().get_received_by_address(&address);
	assert!(received > Amount::ZERO, "should have received sats from offboard");
	info!("Offboarded successfully, received {} on-chain", received);
}

#[tokio::test]
async fn refresh_vtxos_and_participate_ongoing_rounds_dont_race() {
	let ctx = TestContext::new("bark/refresh_vtxos_and_participate_ongoing_rounds_dont_race").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// Board some sats and wait for confirmation
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	let wallet = bark.client().await;

	// Record the initial vtxo before refresh
	let [old_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	let old_vtxo_id = old_vtxo.vtxo.id();

	let refresh_fut = wallet.refresh_vtxos(vec![old_vtxo_id]);

	// Now fire 100 concurrent participate_ongoing_rounds together with a
	// round trigger. All 100 load the same stored round state and race on
	// processing the same round events, bypassing the vtxo lock.
	let ongoing_futs = (0..100).map(|_| wallet.participate_ongoing_rounds());

	let (_, _, results) = tokio::join!(
		srv.trigger_round(),
		refresh_fut,
		join_all(ongoing_futs).wait_millis(20_000),
	);

	// Verify all participations completed without error
	for (i, r) in results.iter().enumerate() {
		r.as_ref().unwrap_or_else(|e| panic!("participation {} failed: {:#}", i, e));
	}

	// Confirm the round and sync the wallet
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	// Verify old vtxo is spent
	let old_vtxo = wallet.get_vtxo_by_id(old_vtxo_id).await.unwrap();
	assert_eq!(old_vtxo.state, VtxoState::Spent, "old vtxo should be spent");

	// Verify a new vtxo was created and it is different from the old one
	let [new_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo after refresh");
	assert_ne!(old_vtxo_id, new_vtxo.vtxo.id(), "old and new vtxo should not be the same");

	// Offboard the new vtxo to prove it is spendable
	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.unwrap();
	ctx.generate_blocks(1).await;

	let received = ctx.bitcoind().get_received_by_address(&address);
	assert!(received > Amount::ZERO, "should have received sats from offboard");
	info!("Offboarded successfully, received {} on-chain", received);
}

/// Test that a user-initiated participate_ongoing_rounds and
/// progress_pending_rounds(None) don't race on the same round state
/// (participate_ongoing_rounds locks the round state).
#[tokio::test]
async fn participate_round_and_progress_pending_dont_race() {
	let ctx = TestContext::new("bark/participate_round_and_progress_pending_dont_race").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// Board some sats and wait for confirmation
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	let wallet = Arc::new(bark.client().await);

	// Record the initial vtxo before refresh
	let [old_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	let old_vtxo_id = old_vtxo.vtxo.id();

	// Build participation and join the round once, locking the vtxo.
	let participation = wallet.build_refresh_participation(vec![old_vtxo_id]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();

	// Race: one participate_ongoing_rounds (user-initiated path) against
	// many progress_pending_rounds(None) poll loops (daemon-style path).
	//
	// Either side may win the round state lock: participate_ongoing_rounds
	// acquires and holds the lock for the full round, while each progress
	// call briefly acquires the lock for one poll iteration.
	//
	// Progress tasks loop until the round state is fully removed from the
	// DB, ensuring the round completes regardless of who drives it.
	let mut progress_handles = Vec::new();
	for _ in 0..100 {
		let w = wallet.clone();
		progress_handles.push(tokio::spawn(async move {
			while w.pending_round_states().await?.iter()
				.any(|s| s.state().ongoing_participation())
			{
				w.progress_pending_rounds(None).await?;
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
			Ok::<_, anyhow::Error>(())
		}));
	}

	let (ongoing_result, _, _) = tokio::join!(
		wallet.participate_ongoing_rounds(),
		srv.trigger_round(),
		join_all(progress_handles),
	);
	ongoing_result.expect("participate_ongoing_rounds should succeed");

	// Confirm the round and sync the wallet
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	// Verify old vtxo is spent
	let old_vtxo = wallet.get_vtxo_by_id(old_vtxo_id).await.unwrap();
	assert_eq!(old_vtxo.state, VtxoState::Spent, "old vtxo should be spent");

	// Verify a new vtxo was created and it is different from the old one
	let [new_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo after refresh");
	assert_ne!(old_vtxo_id, new_vtxo.vtxo.id(), "old and new vtxo should not be the same");

	// Offboard the new vtxo to prove it is spendable
	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.unwrap();
	ctx.generate_blocks(1).await;

	let received = ctx.bitcoind().get_received_by_address(&address);
	assert!(received > Amount::ZERO, "should have received sats from offboard");
	info!("Offboarded successfully, received {} on-chain", received);
}

/// Test that a user-initiated participate_ongoing_rounds and daemon-style
/// event stream consumers (subscribe + progress on each event) don't race
/// on the same round state (participate_ongoing_rounds locks the round state).
#[tokio::test]
async fn participate_round_and_event_stream_processing_dont_race() {
	let ctx = TestContext::new("bark/participate_round_and_event_stream_processing_dont_race").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// Board some sats and wait for confirmation
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;

	let wallet = Arc::new(bark.client().await);

	// Record the initial vtxo before refresh
	let [old_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo");
	let old_vtxo_id = old_vtxo.vtxo.id();

	// Build participation and join the round once, locking the vtxo.
	let participation = wallet.build_refresh_participation(vec![old_vtxo_id]).await
		.unwrap().expect("should build participation");
	wallet.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();

	// Spawn 100 daemon-style event stream consumers: each subscribes to the
	// round event stream and calls progress_pending_rounds on every received
	// event, exactly like inner_process_pending_rounds in daemon.rs.
	let mut daemon_handles = Vec::new();
	for _ in 0..100 {
		let w = wallet.clone();
		daemon_handles.push(tokio::spawn(async move {
			let mut events = w.subscribe_round_events().await?;
			while let Some(event) = events.next().await {
				let event = event?;
				w.progress_pending_rounds(Some(&event)).await?;
			}
			Ok::<_, anyhow::Error>(())
		}));
	}

	// Also run one user-initiated participate_ongoing_rounds racing with
	// all the daemon consumers.
	let (ongoing_result, _) = tokio::join!(
		wallet.participate_ongoing_rounds(),
		srv.trigger_round(),
	);

	ongoing_result.expect("participate_ongoing_rounds should succeed");

	// Confirm the round and sync the wallet
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wallet.sync().await;

	// Verify old vtxo is spent
	let old_vtxo = wallet.get_vtxo_by_id(old_vtxo_id).await.unwrap();
	assert_eq!(old_vtxo.state, VtxoState::Spent, "old vtxo should be spent");

	// Verify a new vtxo was created and it is different from the old one
	let [new_vtxo] = wallet.spendable_vtxos().await.unwrap()
		.try_into().expect("should have exactly one spendable vtxo after refresh");
	assert_ne!(old_vtxo_id, new_vtxo.vtxo.id(), "old and new vtxo should not be the same");

	// Offboard the new vtxo to prove it is spendable
	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address.clone()).await.unwrap();
	ctx.generate_blocks(1).await;

	let received = ctx.bitcoind().get_received_by_address(&address);
	assert!(received > Amount::ZERO, "should have received sats from offboard");
	info!("Offboarded successfully, received {} on-chain", received);

	for h in daemon_handles {
		h.abort();
	}
}

#[tokio::test]
async fn refresh_consolidates_vtxos() {
	let ctx = TestContext::new("bark/refresh_consolidates_vtxos").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;

	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let movements = bark1.history().await;
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.input_vtxos.len(), 3);
	assert_eq!(refresh_mvt.output_vtxos.len(), 1);
	assert_eq!(refresh_mvt.effective_balance, signed_sat(0));
	assert_eq!(refresh_mvt.offchain_fee, Amount::ZERO);
}
