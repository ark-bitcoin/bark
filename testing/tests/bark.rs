
use std::io::{self, BufRead};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;

use bitcoin::Amount;
use bitcoin_ext::P2TR_DUST_SAT;
use bitcoincore_rpc::RpcApi;
use futures::future::join_all;
use log::{debug, info, trace};
use tokio::fs;
use tokio_stream::StreamExt;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy, VtxoRequest};
use ark::rounds::RoundEvent;
use ark::vtxo::policy::PubkeyVtxoPolicy;
use bark::BarkNetwork;
use bark::persist::StoredRoundState;
use bark::round::RoundParticipation;
use bark::subsystem::RoundMovement;
use bark_json::cli::{MovementDestination, PaymentMethod};
use bark_json::primitives::VtxoStateInfo;
use server_log::{AttemptingRound, RestartMissingVtxoSigs, RoundFinished, RoundUserVtxoNotAllowed};
use server_rpc::protos;

use ark_testing::{btc, sat, signed_sat, Bark, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use ark_testing::util::{
	get_bark_chain_source_from_env, FutureExt, TestContextChainSource, ToAltString,
};

#[tokio::test]
async fn bark_version() {
	let ctx = TestContext::new("bark/bark_version").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"--version"]).await;
	assert!(result.starts_with("bark "));
}

#[tokio::test]
async fn bark_ark_info() {
	let ctx = TestContext::new("bark/bark_ark_info").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"ark-info"]).await;
	serde_json::from_str::<bark_json::cli::ArkInfo>(&result).expect("should deserialise");
}

#[tokio::test]
async fn bark_config_json() {
	let ctx = TestContext::new("bark/bark_config_json").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let result = bark1.run(&[&"config"]).await;
	serde_json::from_str::<bark::Config>(&result).expect("should deserialise");
}

#[tokio::test]
async fn bark_address_changes() {
	let ctx = TestContext::new("bark/bark_address_changes").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;

	let addr1 = bark1.address().await;
	let addr2 = bark1.address().await;

	assert_ne!(addr1, addr2);
	assert_eq!(addr1, bark1.address_at_idx(0).await);
	assert_eq!(addr2, bark1.address_at_idx(1).await);
}

#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/bark_create_is_atomic").await;
	let srv = ctx.new_captaind("server", None).await;

	// Create a bark defines the folder
	let _  = ctx.try_new_bark("bark_ok", &srv).await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_ok").is_dir());

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.try_new_bark("bark_twice", &srv).await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	let _ = ctx.try_new_bark("bark_twice", &srv).await.expect_err("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	// We stop the server
	// This ensures that clients cannot be created
	srv.stop().await.unwrap();
	let err = ctx.try_new_bark("bark_fails", &srv).await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"Failed to connect to provided server (if you are sure use the --force flag): transport error"
	), "{:?}", err);
	assert!(!ctx.datadir.join("bark_fails").is_dir());
}

#[tokio::test]
async fn bark_create_force_flag() {
	let ctx = TestContext::new("bark/bark_create_force_flag").await;
	let srv = ctx.new_captaind("server", None).await;

	// Stop the server to simulate unavailability
	srv.stop().await.unwrap();

	// Attempt to create with force_create should succeed
	let datadir = ctx.datadir.join("bark");
	let bitcoind = ctx.new_bitcoind("bark_bitcoind").await;
	let cfg = ctx.bark_default_cfg(&srv, Some(&bitcoind));
	Bark::try_new_with_create_opts(
		"bark", datadir, BarkNetwork::Regtest, cfg, Some(bitcoind), None, None, true,
	).await.unwrap();

	assert!(std::path::Path::is_dir(ctx.datadir.join("bark").as_path()));
}

#[tokio::test]
async fn board_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_bark").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(100_000)).await;

	let board = bark1.board(sat(BOARD_AMOUNT)).await;

	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT), bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_twice_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_twice_bark").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(200_000)).await;

	let board_a = bark1.board(sat(BOARD_AMOUNT)).await;
	let board_b = bark1.board(sat(BOARD_AMOUNT)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "should have 2 board vtxos");
	assert!(vtxos.iter().any(|v| v.id == board_a.vtxos[0]));
	assert!(vtxos.iter().any(|v| v.id == board_b.vtxos[0]));
	assert!(vtxos.iter().all(|v| matches!(v.state, VtxoStateInfo::Locked { .. })));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT) * 2, bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_all_bark() {
	let ctx = TestContext::new("bark/board_all_bark").await;

	let srv = ctx.new_captaind("server", None).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;

	// Get the bark-address and fund it
	ctx.fund_bark(&bark1, sat(100_000)).await;
	assert_eq!(bark1.onchain_balance().await, sat(100_000));

	let board = bark1.board_all().await;
	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Check that we emptied our on-chain balance
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	// Check if the boarding tx's output value is the same as our off-chain balance
	let board_tx = ctx.bitcoind().await_transaction(board.funding_tx.txid).await;
	assert_eq!(
		bark1.spendable_balance().await,
		board_tx.output.last().unwrap().value,
	);
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn bark_rejects_boarding_subdust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_subdust_amount").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	let board_amount = sat(P2TR_DUST_SAT - 1);
	let res = bark1.try_board(board_amount).await;

	// This is taken care by BDK
	assert!(res.unwrap_err().to_string().contains(&format!("Output below the dust limit: 0")));
}

#[tokio::test]
async fn bark_rejects_boarding_below_minimum_board_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_below_minimum_board_amount").await;
	// Set up server with `min_board_amount` of 30 000 sats
	const MIN_BOARD_AMOUNT_SATS: u64 = 30_000;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.min_board_amount = sat(MIN_BOARD_AMOUNT_SATS);
	}).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	let board_amount = sat(MIN_BOARD_AMOUNT_SATS - 1);
	let res = bark1.try_board(board_amount).await;

	assert!(res.unwrap_err().to_string().contains(&format!(
		"board amount of 0.00029999 BTC is less than minimum board amount required by server (0.00030000 BTC)",
	)));
}

#[tokio::test]
async fn list_utxos() {
	let ctx = TestContext::new("bark/list_utxos").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, std::slice::from_ref(&bark)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let addr = bark.get_onchain_address().await;
	let (_, _offb) = tokio::join!(
		srv.trigger_round(),
		bark.offboard_all(&addr),
	);
	ctx.generate_blocks(2).await;

	let utxos = bark.utxos().await;

	let offboard_fee = 938;

	assert_eq!(2, utxos.len());
	// board change utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 799_228));
	// offboard utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 200_000 - offboard_fee));
}

#[tokio::test]
async fn list_vtxos() {
	let ctx = TestContext::new("bark/list_vtxos").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(3, vtxos.len());
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 200_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 300_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 330_000));

	// Should have the same behavior when the server is offline
	srv.stop().await.unwrap();

	let vtxos = bark1.vtxos().await;
	assert_eq!(3, vtxos.len());
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 200_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 300_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 330_000));
}

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
		cfg.round_submit_time = Duration::from_millis(100 * N as u64);
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

	ctx.refresh_all(&srv, &barks).await;
}

#[tokio::test]
async fn send_simple_arkoor() {
	let ctx = TestContext::new("bark/send_simple_arkoor").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(5_000)).await;

	bark1.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	let addr2 = bark2.address().await;
	bark1.send_oor(addr2, sat(20_000)).await;

	assert_eq!(60_000, bark1.spendable_balance().await.to_sat());
	assert_eq!(20_000, bark2.spendable_balance().await.to_sat());
}

#[tokio::test]
async fn send_full_arkoor() {
	let ctx = TestContext::new("bark/send_full_arkoor").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(5_000)).await;
	bark1.board(sat(80_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr2 = bark2.address().await;
	bark1.send_oor(addr2, sat(80_000)).await;

	assert_eq!(0, bark1.spendable_balance().await.to_sat());
	assert_eq!(80_000, bark2.spendable_balance().await.to_sat());
}

#[tokio::test]
async fn send_arkoor_package() {
	let ctx = TestContext::new("bark/send_arkoor_package").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(5_000)).await;
	bark1.board(sat(20_000)).await;
	bark1.board(sat(20_000)).await;
	bark1.board(sat(20_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.sync().await;

	let addr2 = bark2.address().await;
	bark1.send_oor(addr2, sat(50_000)).await;

	let [vtxo] = bark1.vtxos().await.try_into().expect("should only remain change vtxo");
	assert_eq!(vtxo.amount, sat(10_000));

	let mut vtxos = bark2.vtxos().await;
	vtxos.sort_by_key(|v| v.amount);
	let [vtxo1, vtxo2, vtxo3] = vtxos.try_into().expect("should have 3 vtxos");
	assert_eq!(vtxo1.amount, sat(10_000));
	assert_eq!(vtxo2.amount, sat(20_000));
	assert_eq!(vtxo3.amount, sat(20_000));
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
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	bark1.board_and_confirm_and_register(&ctx, sat(400_000)).await;

	// We want bark2 to have a refresh, board, round and oor vtxo
	let pk1 = bark1.address().await;
	let pk2 = bark2.address().await;
	bark2.send_oor(&pk1, sat(20_000)).await; // generates change
	bark1.send_oor(&pk2, sat(20_000)).await;
	bark2.board(sat(20_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(3, bark2.vtxos().await.len());
	ctx.refresh_all(&srv, std::slice::from_ref(&bark2)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	assert_eq!(1, bark2.vtxos().await.len());
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn bark_allows_sending_dust_arkoor_but_errors_on_dust_refresh() {
	let ctx = TestContext::new("bark/bark_allows_sending_dust_arkoor_but_errors_on_dust_refresh").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board_and_confirm_and_register(&ctx, board_amount).await;

	let dust_amount = sat(P2TR_DUST_SAT - 1);
	bark1.try_send_oor(&bark2.address().await, dust_amount, true).await.unwrap();

	let err = bark2.try_refresh_all_no_retry().await.unwrap_err();
	let err_str = format!("{err:?}");
	assert!(err_str.contains("vtxo amount must be at least"),
		"expected: dust validation error, got: {err_str}");
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
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
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
async fn compute_balance() {
	let ctx = TestContext::new("bark/compute_balance").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// board vtxo
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let balance = bark1.spendable_balance().await;
	assert_eq!(balance, sat(830_000));

	// Should have the same behavior when the server is offline
	srv.stop().await.unwrap();

	let balance = bark1.spendable_balance().await;
	assert_eq!(balance, sat(830_000));
}

#[tokio::test]
async fn list_movements() {
	// Initialize the test
	let ctx = TestContext::new("bark/list_movements").await;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.sync().await;
	bark2.sync().await;
	let movements = bark1.history().await;
	assert_eq!(movements.len(), 1);
	assert_eq!(movements.last().unwrap().input_vtxos.len(), 0);
	assert_eq!(movements.last().unwrap().output_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().effective_balance, signed_sat(300_000));
	assert_eq!(movements.last().unwrap().offchain_fee, Amount::ZERO);
	assert!(movements.last().unwrap().sent_to.first().is_none());

	// oor change
	bark1.send_oor(&bark2.address().await, sat(150_000)).await;
	let movements = bark1.history().await;
	assert_eq!(movements.len(), 2);
	assert_eq!(movements.last().unwrap().effective_balance, signed_sat(-150_000));
	assert_eq!(movements.last().unwrap().input_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().output_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().sent_to[0].amount, sat(150_000));
	assert_eq!(movements.last().unwrap().offchain_fee, Amount::ZERO);

	// refresh vtxos - trigger round manually
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let movements = bark1.history().await;
	assert_eq!(movements.len(), 3);
	assert_eq!(movements.last().unwrap().effective_balance, signed_sat(0));
	assert_eq!(movements.last().unwrap().input_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().output_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().offchain_fee, Amount::ZERO);
	assert_eq!(movements.last().unwrap().sent_to.len(), 0);
	assert_eq!(movements.last().unwrap().received_on.len(), 0);

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;
	let movements = bark1.history().await;

	assert_eq!(movements.len(), 4);
	assert_eq!(movements.last().unwrap().input_vtxos.len(), 0);
	assert_eq!(movements.last().unwrap().output_vtxos.len(), 1);
	assert_eq!(movements.last().unwrap().effective_balance, signed_sat(330_000));
	assert_eq!(movements.last().unwrap().offchain_fee, Amount::ZERO);
	assert!(movements.last().unwrap().sent_to.first().is_none());
}

#[tokio::test]
async fn multiple_spends_in_payment() {
	// TODO: This test does not do what its name suggests.
	// Initialize the test
	let ctx = TestContext::new("bark/multiple_spends_in_payment").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;

	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let movements = bark1.history().await;
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.input_vtxos.len(), 3);
	assert_eq!(refresh_mvt.output_vtxos.len(), 1);
	assert_eq!(refresh_mvt.effective_balance, signed_sat(0));
	assert_eq!(refresh_mvt.offchain_fee, Amount::ZERO);
}

#[tokio::test]
async fn offboard_all() {
	let ctx = TestContext::new("bark/offboard_all").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board(sat(200_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let address = ctx.bitcoind().get_new_address();

	let init_balance = bark1.spendable_balance().await;
	assert_eq!(init_balance, sat(830_000));

	tokio::join!(
		srv.trigger_round(),
		bark1.offboard_all(&address),
	);

	// We check that all vtxos have been offboarded
	assert_eq!(Amount::ZERO, bark1.spendable_balance().await);

	let offboard_fee = sat(854);
	let movements = bark1.history().await;
	let offb_movement = movements.last().unwrap();
	assert_eq!(offb_movement.input_vtxos.len(), 3, "all offboard vtxos should be in movement");
	assert_eq!(
		offb_movement.sent_to.first(),
		Some(MovementDestination {
			destination: PaymentMethod::Bitcoin(address.to_string()),
			amount: init_balance - offboard_fee,
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, init_balance - offboard_fee);
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn offboard_vtxos() {
	let ctx = TestContext::new("bark/offboard_vtxos").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(3, vtxos.len(), "vtxos: {:?}", vtxos);

	let address = ctx.bitcoind().get_new_address();
	let vtxo_to_offboard = &vtxos[1];

	tokio::join!(
		srv.trigger_round(),
		bark1.offboard_vtxo(vtxo_to_offboard.id, &address),
	);

	// We check that only selected vtxo has been touched
	let updated_vtxos = bark1.vtxos().await
		.into_iter()
		.map(|vtxo| vtxo.id)
		.collect::<Vec<_>>();

	assert!(updated_vtxos.contains(&vtxos[0].id));
	assert!(updated_vtxos.contains(&vtxos[2].id));

	let offboard_fee = sat(854);
	let movements = bark1.history().await;
	let offb_movement = movements.last().unwrap();
	assert_eq!(offb_movement.input_vtxos.len(), 1, "only provided vtxo should be offboarded");
	assert_eq!(offb_movement.input_vtxos[0], vtxo_to_offboard.id, "only provided vtxo should be offboarded");
	assert_eq!(
		offb_movement.sent_to.first(),
		Some(MovementDestination {
			destination: PaymentMethod::Bitcoin(address.to_string()),
			amount: vtxo_to_offboard.amount - offboard_fee,
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, vtxo_to_offboard.amount - offboard_fee);
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn bark_send_onchain() {
	let ctx = TestContext::new("bark/bark_send_onchain").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;

	bark1.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let [input_vtxo] = bark1.vtxos().await.try_into().expect("should have one vtxo");

	// board vtxo
	let send_amount = sat(300_000);
	let addr = bark2.get_onchain_address().await;
	bark1.send_onchain(&addr, send_amount).await;
	ctx.generate_blocks(2).await;

	let offboard_fee = sat(938);
	let [change_vtxo] = bark1.vtxos().await.try_into().expect("should have one vtxo");
	assert_eq!(change_vtxo.amount, input_vtxo.amount - send_amount - offboard_fee);

	let movements = bark1.history().await;
	let send_movement = movements.last().unwrap();
	assert!(send_movement.input_vtxos.contains(&input_vtxo.id));
	assert_eq!(
		send_movement.sent_to.first(),
		Some(MovementDestination {
			destination: PaymentMethod::Bitcoin(addr.to_string()),
			amount: sat(300_000),
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	assert_eq!(bark2.onchain_balance().await, sat(300_000));
	assert_eq!(bark2.inround_balance().await, sat(0));
}

#[tokio::test]
async fn bark_send_onchain_too_much() {
	let ctx = TestContext::new("bark/bark_send_onchain_too_much").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr = bark2.get_onchain_address().await;

	// board vtxo
	let ret = bark1.try_send_onchain(&addr, sat(1_000_000)).await;
	ctx.generate_blocks(2).await;

	let err = ret.unwrap_err();
	let expected = format!("Insufficient money available. Needed {} but {} is available",
		sat(1_000_000), board_amount,
	);
	assert!(err.to_alt_string().contains(&expected),
		"err does not match '{}': {:#}", expected, err);

	assert_eq!(bark1.spendable_balance().await, board_amount,
		"offchain balance shouldn't have changed");
	assert_eq!(bark1.history().await.len(), 1,
		"Should only have board movement");
}

#[tokio::test]
async fn bark_rejects_offboarding_dust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_offboarding_dust_amount").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;

	let board_amount = sat(800_000);
	bark1.board_and_confirm_and_register(&ctx, board_amount).await;

	let addr = bark2.get_onchain_address().await;

	let err = bark1.try_send_onchain(&addr, sat(P2TR_DUST_SAT - 1)).await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"it doesn't make sense to send dust",
	), "err: {err}");
}

#[tokio::test]
async fn bark_balance_shows_pending_board_sats_until_deeply_confirmed() {
	let ctx = TestContext::new("bark/bark_balance_shows_pending_board_sats_until_deeply_confirmed").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;

	assert_eq!(bark1.pending_board_balance().await, board_amount);
	assert_eq!(bark1.spendable_balance().await, Amount::ZERO);
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO);
	assert_eq!(bark1.spendable_balance().await, board_amount);
}

#[tokio::test]
async fn drop_vtxos() {
	let ctx = TestContext::new("bark/drop_vtxos").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, std::slice::from_ref(&bark1)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	bark1.drop_vtxos().await;
	let balance = bark1.spendable_balance_no_sync().await;

	assert_eq!(balance, Amount::ZERO);
}

#[tokio::test]
async fn reject_arkoor_with_bad_signature() {
	let ctx = TestContext::new("bark/reject_arkoor_with_bad_signature").await;

	#[derive(Clone)]
	struct InvalidSigProxy;

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InvalidSigProxy {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, ArkoorMessage};

			let response = upstream.read_mailbox(req).await?.into_inner();
			let message = match response.messages[0].message.as_ref().unwrap() {
				mailbox_message::Message::Arkoor(ArkoorMessage { vtxos }) => {
					let mut vtxo = Vtxo::deserialize(&vtxos[0]).unwrap();
					vtxo.invalidate_final_sig();
					ArkoorMessage { vtxos: vec![vtxo.serialize()] }
				},
			};

			Ok(protos::mailbox_server::MailboxMessages {
				messages: vec![protos::mailbox_server::MailboxMessage {
					message: Some(mailbox_message::Message::Arkoor(message)),
					checkpoint: 0,
				}],
				have_more: false,
			})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// create a proxy to return an arkoor with invalid signatures
	let proxy = srv.start_proxy_with_mailbox((), InvalidSigProxy).await;

	// create a third wallet to receive the invalid arkoor
	let bark2 = ctx.new_bark("bark2".to_string(), &proxy.address).await;
	let bark2_addr = bark2.address().await;

	// Send arkoor package to mailbox
	bark1.send_oor(bark2_addr, sat(10_000)).await;

	// we should drop invalid arkoors
	assert_eq!(bark2.vtxos().await.len(), 0);

	// check that we saw a log
	tokio::time::sleep(Duration::from_millis(250)).await;


	assert!(io::BufReader::new(std::fs::File::open(bark2.command_log_file()).unwrap()).lines().any(|line| {
		let line = line.unwrap();
		line.contains("Received invalid arkoor VTXO") &&
		line.contains("error verifying one of the genesis transitions \
			(idx=2/3 type=arkoor): invalid signature")
	}));
}

#[tokio::test]
async fn accept_mailbox() {
	let ctx = TestContext::new("bark/accept_mailbox").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &srv, sat(1_000_000)).await;

	let _board = bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark2 = ctx.new_bark("bark2", &srv).await;
	bark.send_oor(bark2.address().await, sat(100_000)).await;

	bark2.maintain().await;
	let bark2_vtxos = bark2.vtxos().await;
	assert_eq!(bark2_vtxos.len(), 1);

	// Test import_vtxo
	let bark2_wallet = bark2.client().await;
	let vtxos = bark2_wallet.vtxos().await.unwrap();
	let vtxo_hex = vtxos[0].vtxo.serialize_hex();

	bark2.import_vtxos(&[&vtxo_hex]).await;
	assert_eq!(bark2.vtxos().await.len(), 1, "import should be idempotent");

	let err = bark.try_import_vtxos(&[&vtxo_hex]).await.unwrap_err();
	assert!(err.to_string().contains("signable clause") || err.to_string().contains("not owned"), "expected ownership error, got: {}", err);

	let bark3 = ctx.new_bark("bark3", &srv).await;
	bark.send_oor(bark3.address().await, sat(50_000)).await;
	bark.send_oor(bark3.address().await, sat(60_000)).await;

	bark3.maintain().await;
	let bark3_vtxos = bark3.vtxos().await;
	assert_eq!(bark3_vtxos.len(), 2, "bark3 should have 2 VTXOs");

	let bark3_wallet = bark3.client().await;
	let vtxos = bark3_wallet.vtxos().await.unwrap();
	let vtxo_hex1 = vtxos[0].vtxo.serialize_hex();
	let vtxo_hex2 = vtxos[1].vtxo.serialize_hex();

	// Drop all VTXOs from bark3 and re-import them in bulk
	bark3.drop_vtxos().await;
	assert_eq!(bark3.vtxos().await.len(), 0, "bark3 should have 0 VTXOs after drop");

	let imported = bark3.import_vtxos(&[&vtxo_hex1, &vtxo_hex2]).await;
	assert_eq!(imported.len(), 2, "should have imported 2 VTXOs");
	assert_eq!(bark3.vtxos().await.len(), 2, "bark3 should have 2 VTXOs after bulk import");

	let bark4 = ctx.new_bark("bark4", &srv).await;
	bark.send_oor(bark4.address().await, sat(40_000)).await;
	bark4.maintain().await;
	assert_eq!(bark4.vtxos().await.len(), 1, "bark4 should have 1 VTXO");

	let bark4_wallet = bark4.client().await;
	let bark4_vtxos = bark4_wallet.vtxos().await.unwrap();
	let expired_vtxo_hex = bark4_vtxos[0].vtxo.serialize_hex();

	bark4.drop_vtxos().await;
	assert_eq!(bark4.vtxos().await.len(), 0, "bark4 should have 0 VTXOs after drop");

	ctx.generate_blocks(srv.config().vtxo_lifetime as u32 + 10).await;

	let err = bark4.try_import_vtxos(&[&expired_vtxo_hex]).await.unwrap_err();
	assert!(err.to_string().contains("expired"), "expected expiry error, got: {}", err);
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
	let (res1, res2, ()) = tokio::join!(
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

#[ignore] // we removed this functionality, might be added again later
#[tokio::test]
async fn recover_mnemonic() {
	let ctx = TestContext::new("bark/recover_mnemonic").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(2_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// make sure we have a round and an board vtxo (arkoor doesn't work)
	bark.refresh_all().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let onchain = bark.onchain_balance().await;
	let _offchain = bark.spendable_balance().await;

	const MNEMONIC_FILE: &str = "mnemonic";
	let mnemonic = fs::read_to_string(bark.datadir().join(MNEMONIC_FILE)).await.unwrap();
	let _ = bip39::Mnemonic::parse(&mnemonic).expect("invalid mnemonic?");

	// first ensure we need to set a birthday for bitcoin core
	let bitcoind = if ctx.electrs.is_none() {
		Some(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await)
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_no_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_ref());
	let result = Bark::try_new_with_create_opts(
		"bark_recovered_no_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		None,
		true,
	).await;

	match get_bark_chain_source_from_env() {
		TestContextChainSource::BitcoinCore => {
			// it's not easy to get a grip of what the actual error was
			assert!(result.expect_err("--birthday-height should be required").to_string().contains(
				"You need to set the --birthday-height field when recovering from mnemonic.",
			));
		}
		_ => {
			let balance = result
				.expect("mnemonic should work without birthday")
				.onchain_balance()
				.await;
			assert_eq!(onchain, balance);
		}
	}

	// Now check that specifying a birthday height always succeeds
	let bitcoind = if ctx.electrs.is_none() {
		Some(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await)
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_with_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_ref());
	let recovered = Bark::try_new_with_create_opts(
		"bark_recovered_with_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		Some(0),
		true,
	).await.expect("mnemonic + birthday should work");
	assert_eq!(onchain, recovered.onchain_balance().await);
	//TODO(stevenroose) implement offchain recovery
	// assert_eq!(offchain, recovered.offchain_balance().await);
}

#[tokio::test]
async fn onchain_send() {
	let ctx = TestContext::new("bark/onchain_send").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &srv, sat(1_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &srv).await;

	sender.onchain_send(recipient.get_onchain_address().await, sat(200_000)).await;
	ctx.generate_blocks(1).await;

	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, sat(200_000));

	sender.onchain_send(recipient.get_onchain_address().await, sat(300_000)).await;
	ctx.generate_blocks(1).await;

	let sender_balance = sender.onchain_balance().await;
	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, sat(500_000));
	assert!(sender_balance < sat(500_0000));
}

#[tokio::test]
async fn onchain_send_many() {
	let ctx = TestContext::new("bark/onchain_send_many").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &srv, sat(10_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &srv).await;
	let addresses = [
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
		recipient.get_onchain_address().await,
	];
	let amounts = [
		sat(100_000),
		sat(200_000),
		sat(300_000),
		sat(400_000),
		sat(500_000),
	];

	// Send the transaction assuming each address gets mapped to amounts sequentially
	sender.onchain_send_many(addresses, amounts).await;
	ctx.generate_blocks(1).await;

	let utxos = recipient.utxos().await;
	let client = ctx.bitcoind().sync_client();

	// Every utxo should be in the same transaction and the vout should correspond to the amount array
	let tx = client.get_raw_transaction(&utxos[0].outpoint.txid, None).unwrap();
	for utxo in utxos {
		let vout = utxo.outpoint.vout as usize;
		assert_eq!(tx.output[vout].value, amounts[vout]);
	}

	// Finally verify our balances
	assert_eq!(recipient.onchain_balance().await, sat(1_500_000));
	assert!(sender.onchain_balance().await < sat(8_500_000));
}

#[tokio::test]
async fn onchain_drain() {
	let ctx = TestContext::new("bark/onchain_drain").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &srv, sat(1_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &srv).await;

	sender.onchain_drain(recipient.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	let sender_balance = sender.onchain_balance().await;
	assert_eq!(sender_balance, Amount::ZERO);

	let recipient_balance = recipient.onchain_balance().await;
	assert_eq!(recipient_balance, sat(999_443));
}

#[tokio::test]
async fn bark_recover_unregistered_board() {
	let ctx = TestContext::new("bark/recover_unregistered_board").await;

	// Set up the server.
	// The server misbehaves and drops the first request to register_board_vtxo
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;

	/// This proxy will drop the very first request to register_board
	#[derive(Clone)]
	struct Proxy(Arc<AtomicBool>);

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, upstream: &mut ArkClient, req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.0.swap(false, atomic::Ordering::Relaxed) {
				Err(tonic::Status::from_error(
					"Nope! I do not register on the first attempt!".into(),
				))
			} else {
				Ok(upstream.register_board_vtxo(req).await?.into_inner())
			}
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(Arc::new(AtomicBool::new(true)))).await;

	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_00)).await;
	// Only asks server to cosign, not register a board.
	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	// Triggers maintenance under the hood
	//
	// The board registration should have failed and the pending board balance should still be greater than 0.
	assert!(bark.pending_board_balance().await > Amount::ZERO);
	assert_eq!(bark.vtxos().await.len(), 1);

	ctx.generate_blocks(12).await;
	// The board registration will succeed during maintenance her and the pending board balance should be 0.
	assert_eq!(bark.pending_board_balance().await, Amount::ZERO);
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

#[tokio::test]
async fn test_ark_address_other_ark() {
	let ctx = TestContext::new("bark/test_ark_address_other_ark").await;

	let srv1 = ctx.new_captaind_with_funds("server1", None, btc(1)).await;
	let srv2 = ctx.new_captaind_with_funds("server2", None, btc(1)).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv1, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv2, sat(1_000_000)).await;

	bark1.board(sat(800_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark2.sync().await;

	let addr1 = bark1.address().await;
	let err = bark2.try_send_oor(addr1, sat(10_000), false).await.unwrap_err().to_alt_string();
	assert!(err.contains("Ark address is for different server"), "err: {err:#}");
}

#[tokio::test]
async fn bark_can_claim_all_claimable_lightning_receives() {
	let ctx = TestContext::new("bark/bark_can_claim_all_claimable_lightning_receives").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = ctx.new_bark_with_funds("bark1", &srv, btc(3)).await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info_1 = bark.bolt11_invoice(btc(1)).await;
	let invoice_info_2 = bark.bolt11_invoice(btc(1)).await;

	let res = tokio::spawn(async move {
		tokio::join!(
			lightning.sender.pay_bolt11(invoice_info_1.invoice),
			lightning.sender.pay_bolt11(invoice_info_2.invoice),
		)
	});

	srv.wait_for_vtxopool(&ctx).await;

	bark.lightning_receive_all().wait_millis(10_000).await;

	// HTLC settlement on lightning side
	res.ready().await.unwrap();

	assert_eq!(bark.spendable_balance().await, btc(4));
}

async fn print_pending_rounds(wallet: &bark::Wallet) -> Vec<StoredRoundState> {
	let states = wallet.pending_round_states().await.unwrap();
	info!("Wallet has {} pending round states:", states.len());
	for state in &states {
		info!("  - {}", state.id);
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
	let state = bark.join_next_round(participation, Some(RoundMovement::Refresh)).await.unwrap();
	let state_id = state.id;

	info!("Signed up for round, state_id={}", state.id);
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
		if let Some(mut ours) = states.into_iter().find(|s| s.id == state_id) {
			if !ours.state.ongoing_participation() {
				info!("Round finished");
				break;
			} else {
				if let RoundEvent::Finished(_) = event {
					let status = ours.state.sync(&bark).await.unwrap();
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
		if let Some(mut ours) = states.into_iter().find(|s| s.id == state_id) {
			debug!("Result: {:#?}", ours.state.sync(&bark).await);
		} else {
			info!("Our state is gone!");
			break;
		}

		tokio::time::sleep(Duration::from_millis(500)).await;
	}

	//TODO(stevenroose) test new vtxo state and movement
}
