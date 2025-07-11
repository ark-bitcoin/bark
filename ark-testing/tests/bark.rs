
use std::io::{self, BufRead};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;

use bitcoin::Amount;
use bitcoin_ext::{P2TR_DUST, P2TR_DUST_SAT};
use bitcoincore_rpc::RpcApi;
use futures::future::join_all;
use log::info;
use tokio::fs;

use ark::{ProtocolEncoding, Vtxo};
use aspd_log::{MissingForfeits, RestartMissingForfeits, RoundUserVtxoNotAllowed};
use aspd_rpc::{self as rpc, protos};
use bark::movement::MovementRecipient;

use ark_testing::{TestContext, btc, sat};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::aspd;
use ark_testing::util::FutureExt;

const OFFBOARD_FEES: Amount = sat(900);

#[tokio::test]
async fn bark_version() {
	let ctx = TestContext::new("bark/bark_version").await;
	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let result = bark1.run(&[&"--version"]).await;
	assert!(result.starts_with("bark "));
}

#[tokio::test]
async fn bark_ark_info() {
	let ctx = TestContext::new("bark/bark_ark_info").await;
	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let result = bark1.run(&[&"ark-info"]).await;
	serde_json::from_str::<bark_json::cli::ArkInfo>(&result).expect("should deserialise");
}

#[tokio::test]
async fn bark_vtxo_pubkey_changes() {
	let ctx = TestContext::new("bark/bark_vtxo_pubkey_changes").await;
	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;

	let pk1 = bark1.vtxo_pubkey().await;
	let pk2 = bark1.vtxo_pubkey().await;

	assert_ne!(pk1, pk2);
	assert_eq!(pk1, bark1.vtxo_pubkey_at_idx(0).await);
	assert_eq!(pk2, bark1.vtxo_pubkey_at_idx(1).await);
}


#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/bark_create_is_atomic").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Create a bark defines the folder
	let _  = ctx.try_new_bark("bark_ok", &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_ok").as_path()));

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.try_new_bark("bark_twice", &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	let _ = ctx.try_new_bark("bark_twice", &aspd).await.expect_err("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	// We stop the asp
	// This ensures that clients cannot be created
	aspd.stop().await.unwrap();
	let _ = ctx.try_new_bark("bark_fails", &aspd).await.expect_err("Cannot create bark if asp is not available");
	assert!(!std::path::Path::is_dir(ctx.datadir.join("bark_fails").as_path()));
}

#[tokio::test]
async fn board_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_bark").await;
	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(100_000)).await;

	bark1.board(sat(BOARD_AMOUNT)).await;

	assert_eq!(sat(BOARD_AMOUNT), bark1.offchain_balance().await);
}

#[tokio::test]
async fn board_all_bark() {
	let ctx = TestContext::new("bark/board_all_bark").await;

	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;

	// Get the bark-address and fund it
	ctx.fund_bark(&bark1, sat(100_000)).await;
	assert_eq!(bark1.onchain_balance().await, sat(100_000));

	let board_txid = bark1.board_all().await.funding_txid;

	// Check that we emptied our on-chain balance
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	// Check if the boarding tx's output value is the same as our off-chain balance
	let board_tx = ctx.bitcoind().await_transaction(&board_txid).await;
	assert_eq!(
		bark1.offchain_balance().await,
		board_tx.output.last().unwrap().value,
	);
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);
}

#[tokio::test]
async fn bark_rejects_boarding_subdust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_subdust_amount").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;

	let board_amount = sat(P2TR_DUST_SAT - 1);
	let res =bark1.try_board(board_amount).await;

	// This is taken care by BDK
	assert!(res.unwrap_err().to_string().contains(&format!("Output below the dust limit: 0")));
}

#[tokio::test]
async fn list_utxos() {
	let ctx = TestContext::new("bark/list_utxos").await;

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;
	ctx.generate_blocks(1).await;

	let addr = bark.get_onchain_address().await;
	let _offb = bark.offboard_all(&addr).await;
	ctx.generate_blocks(1).await;

	let utxos = bark.utxos().await;

	assert_eq!(2, utxos.len());
	// board change utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 799_228));
	// offboard utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 198_900));
}

#[tokio::test]
async fn list_vtxos() {
	let ctx = TestContext::new("bark/list_vtxos").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(3, vtxos.len());
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 200_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 300_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 330_000));

	// Should have the same behaviour when ASP is offline
	aspd.stop().await.unwrap();

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

	let aspd = ctx.new_aspd_with_cfg("aspd", None, |cfg| {
		cfg.round_interval = Duration::from_millis(2_000);
		cfg.round_submit_time = Duration::from_millis(100 * N as u64);
		cfg.round_sign_time = Duration::from_millis(1000 * N as u64);
		cfg.nb_round_nonces = 200;
	}).await;
	ctx.fund_asp(&aspd, btc(10)).await;

	let barks = join_all((0..N).map(|i| {
		let name = format!("bark{}", i);
		ctx.new_bark_with_funds(name, &aspd, sat(90_000))
	})).await;
	ctx.generate_blocks(1).await;

	// Fund and board all clients.
	for chunk in barks.chunks(20) {
		join_all(chunk.iter().map(|b| async {
			b.board(sat(80_000)).await;
		})).await;
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Refresh all vtxos
	//TODO(stevenroose) need to find a way to ensure that all these happen in the same round
	join_all(barks.iter().map(|b| {
		b.refresh_all()
	})).await;
}

#[tokio::test]
async fn send_simple_arkoor() {
	let ctx = TestContext::new("bark/send_simple_arkoor").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(5_000)).await;
	bark1.board(sat(80_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let pk2 = bark2.vtxo_pubkey().await;
	bark1.send_oor(pk2, sat(20_000)).await;

	assert_eq!(60_000, bark1.offchain_balance().await.to_sat());
	assert_eq!(20_000, bark2.offchain_balance().await.to_sat());
}

#[tokio::test]
async fn send_arkoor_package() {
	let ctx = TestContext::new("bark/send_arkoor_package").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(5_000)).await;
	bark1.board(sat(20_000)).await;
	bark1.board(sat(20_000)).await;
	bark1.board(sat(20_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let pk2 = bark2.vtxo_pubkey().await;
	bark1.send_oor(pk2, sat(50_000)).await;

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
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark1.board(sat(800_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// We want bark2 to have a refresh, board, round and oor vtxo
	let pk1 = bark1.vtxo_pubkey().await;
	let pk2 = bark2.vtxo_pubkey().await;
	bark2.send_oor(&pk1, sat(20_000)).await; // generates change
	bark1.refresh_all().await;
	bark1.send_oor(&pk2, sat(20_000)).await;
	bark2.board(sat(20_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(3, bark2.vtxos().await.len());
	bark2.refresh_all().await;
	assert_eq!(1, bark2.vtxos().await.len());
}

#[tokio::test]
async fn bark_rejects_sending_subdust_oor() {
	let ctx = TestContext::new("bark/bark_rejects_sending_subdust_oor").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let subdust_amount = sat(P2TR_DUST_SAT - 1);
	let res = bark1.try_send_oor(&bark2.vtxo_pubkey().await, subdust_amount, true).await;

	assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	assert_eq!(bark1.offchain_balance().await, board_amount);
}

#[tokio::test]
async fn bark_rejects_creating_arkoor_subdust_change() {
	let ctx = TestContext::new("bark/bark_rejects_creating_arkoor_subdust_change").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let sent_amount = board_amount - sat(P2TR_DUST_SAT - 1);
	let err = bark1.try_send_oor(&bark2.vtxo_pubkey().await, sent_amount, true).await.unwrap_err();

	assert!(err.to_string().contains(&format!(
		"An error occurred: Insufficient money available. Needed {} but {} is available",
		// sent amount (799_671) + change (330)
		sat(800_001),
		board_amount,
	)), "err: {err}");
	assert_eq!(bark1.offchain_balance().await, board_amount);
}

#[tokio::test]
async fn refresh_counterparty() {
	let ctx = TestContext::new("bark/refresh_counterparty").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;

	let (arkoor_vtxo, others): (Vec<_>, Vec<_>) = bark1.vtxos().await
		.into_iter()
		.partition(|v| v.amount == sat(330_000));

	bark1.refresh_counterparty().await;

	let vtxos = bark1.vtxos().await;
	// there should still be 3 vtxos
	assert_eq!(3, vtxos.len());
	// received oor vtxo should be refreshed
	assert!(!vtxos.iter().any(|v| v.id == arkoor_vtxo.first().unwrap().id));
	// others should remain untouched
	assert!(others.iter().all(|o| vtxos.iter().any(|v| v.id == o.id)));
}

#[tokio::test]
async fn compute_balance() {
	let ctx = TestContext::new("bark/compute_balance").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;

	let balance = bark1.offchain_balance().await;
	assert_eq!(balance, sat(830_000));

	// Should have the same behaviour when ASP is offline
	aspd.stop().await.unwrap();

	let balance = bark1.offchain_balance().await;
	assert_eq!(balance, sat(830_000));
}

#[tokio::test]
async fn list_movements() {
	// Initialize the test
	let ctx = TestContext::new("bark/list_movements").await;

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 1);
	assert_eq!(movements[0].spends.len(), 0);
	assert_eq!(movements[0].receives[0].amount, sat(300_000));
	assert_eq!(movements[0].fees, Amount::ZERO);
	assert!(movements[0].recipients.first().is_none());

	// oor change
	bark1.send_oor(&bark2.vtxo_pubkey().await, sat(150_000)).await;
	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 2);
	assert_eq!(movements[0].spends[0].amount, sat(300_000));
	assert_eq!(movements[0].receives[0].amount, sat(150_000));
	assert_eq!(movements[0].fees, Amount::ZERO);
	assert!(movements[0].recipients.first().is_some());

	// refresh vtxos
	bark1.refresh_all().await;
	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 3);
	assert_eq!(movements[0].spends[0].amount, sat(150_000));
	assert_eq!(movements[0].receives[0].amount, sat(150_000));
	assert_eq!(movements[0].fees, Amount::ZERO);
	assert!(movements[0].recipients.first().is_none());

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;
	let movements = bark1.list_movements().await;

	assert_eq!(movements.len(), 4);
	assert_eq!(movements[0].spends.len(), 0);
	assert_eq!(movements[0].receives[0].amount, sat(330_000));
	assert_eq!(movements[0].fees, Amount::ZERO);
	assert!(movements[0].recipients.first().is_none());
}

#[tokio::test]
async fn multiple_spends_in_payment() {
	// Initialize the test
	let ctx = TestContext::new("bark/multiple_spends_in_payment").await;

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &aspd, sat(1_000_000)).await;

	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(1).await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// refresh vtxos
	bark1.refresh_all().await;
	let movements = bark1.list_movements().await;
	assert_eq!(movements[0].spends.len(), 3);
	assert_eq!(movements[0].spends[0].amount, sat(100_000));
	assert_eq!(movements[0].spends[1].amount, sat(200_000));
	assert_eq!(movements[0].spends[2].amount, sat(300_000));
	assert_eq!(movements[0].receives[0].amount, sat(600_000));
	assert_eq!(movements[0].fees, Amount::ZERO);
}

#[tokio::test]
async fn offboard_all() {
	let ctx = TestContext::new("bark/offboard_all").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark1.board(sat(200_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// refresh and board more
	bark1.refresh_all().await;
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;

	let address = ctx.bitcoind().get_new_address();

	let init_balance = bark1.offchain_balance().await;
	assert_eq!(init_balance, sat(830_000));

	bark1.offboard_all(address.clone()).await;

	// We check that all vtxos have been offboarded
	assert_eq!(Amount::ZERO, bark1.offchain_balance().await);

	let movements = bark1.list_movements().await;
	let offb_movement = movements.first().unwrap();
	assert_eq!(offb_movement.spends.len(), 3, "all offboard vtxos should be in movement");
	assert_eq!(
		offb_movement.recipients.first(),
		Some(MovementRecipient {
			recipient: address.to_string(),
			amount: sat(829100),
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, init_balance - OFFBOARD_FEES);
}

#[tokio::test]
async fn offboard_vtxos() {
	let ctx = TestContext::new("bark/offboard_vtxos").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(3, vtxos.len());

	let address = ctx.bitcoind().get_new_address();
	let vtxo_to_offboard = &vtxos[1];

	bark1.offboard_vtxo(vtxo_to_offboard.id, address.clone()).await;

	// We check that only selected vtxo has been touched
	let updated_vtxos = bark1.vtxos().await
		.into_iter()
		.map(|vtxo| vtxo.id)
		.collect::<Vec<_>>();

	assert!(updated_vtxos.contains(&vtxos[0].id));
	assert!(updated_vtxos.contains(&vtxos[2].id));

	let movements = bark1.list_movements().await;
	let offb_movement = movements.first().unwrap();
	assert_eq!(offb_movement.spends.len(), 1, "only provided vtxo should be offboarded");
	assert_eq!(offb_movement.spends[0].id, vtxo_to_offboard.id, "only provided vtxo should be offboarded");
	assert_eq!(
		offb_movement.recipients.first(),
		Some(MovementRecipient {
			recipient: address.to_string(),
			amount: vtxo_to_offboard.amount - sat(900),
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, vtxo_to_offboard.amount - OFFBOARD_FEES);
}

#[tokio::test]
async fn bark_send_onchain() {
	let ctx = TestContext::new("bark/bark_send_onchain").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;

	bark1.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let [sent_vtxos] = bark1.vtxos().await.try_into().expect("should have one vtxo");
	let addr = bark2.get_onchain_address().await;

	// board vtxo
	bark1.send_onchain(&addr, sat(300_000)).await;
	ctx.generate_blocks(1).await;

	let [change_vtxo] = bark1.vtxos().await.try_into().expect("should have one vtxo");
	assert_eq!(change_vtxo.amount, sat(498_900));

	let movements = bark1.list_movements().await;
	let send_movement = movements.first().unwrap();
	assert_eq!(send_movement.spends[0].id, sent_vtxos.id);
	assert_eq!(
		send_movement.recipients.first(),
		Some(MovementRecipient {
			recipient: addr.to_string(),
			amount: sat(300_000),
		}).as_ref(), "destination should be correct"
	);

	// We check that provided address received the coins
	ctx.generate_blocks(1).await;
	assert_eq!(bark2.onchain_balance().await, sat(300_000));
}

#[tokio::test]
async fn bark_send_onchain_too_much() {
	let ctx = TestContext::new("bark/bark_send_onchain_too_much").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr = bark2.get_onchain_address().await;

	// board vtxo
	let ret = bark1.try_send_onchain(&addr, sat(1_000_000)).await;

	assert!(ret.unwrap_err().to_string().contains(
		&format!("Your balance is too low. Needed: {}, available: {}",
		sat(1_000_110), board_amount)
	));
	assert_eq!(bark1.offchain_balance().await, board_amount, "offchain balance shouldn't have changed");
	assert_eq!(bark1.list_movements().await.len(), 1, "Should only have board movement");
}

#[tokio::test]
async fn bark_rejects_offboarding_subdust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_offboarding_subdust_amount").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;

	let board_amount = sat(800_000);
	bark1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr = bark2.get_onchain_address().await;

	let res = bark1.try_send_onchain(&addr, sat(P2TR_DUST_SAT - 1)).await;

	assert!(res.unwrap_err().to_string().contains(&format!("Offboard amount must be at least {}", P2TR_DUST)));
}

#[tokio::test]
async fn drop_vtxos() {
	let ctx = TestContext::new("bark/drop_vtxos").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;
	ctx.generate_blocks(1).await;

	bark1.drop_vtxos().await;
	let balance = bark1.offchain_balance_no_sync().await;

	assert_eq!(balance, Amount::ZERO);
}

#[tokio::test]
async fn reject_arkoor_with_bad_signature() {
	let ctx = TestContext::new("bark/reject_arkoor_with_bad_signature").await;

	#[derive(Clone)]
	struct InvalidSigProxy(rpc::ArkServiceClient<tonic::transport::Channel>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for InvalidSigProxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn empty_arkoor_mailbox(&mut self, req: protos::ArkoorVtxosRequest) -> Result<protos::ArkoorVtxosResponse, tonic::Status>  {
			let response = self.upstream().empty_arkoor_mailbox(req).await?.into_inner();
			let mut vtxo = Vtxo::deserialize(&response.packages[0].vtxos[0]).unwrap();
			vtxo.invalidate_final_sig();
			Ok(protos::ArkoorVtxosResponse {
				packages: vec![protos::ArkoorMailboxPackage {
					arkoor_package_id: [0; 32].to_vec(),
					vtxos: vec![vtxo.serialize()],
				}],
			})
		}
	}

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// create a proxy to return an arkoor with invalid signatures
	let proxy = aspd::proxy::AspdRpcProxyServer::start(InvalidSigProxy(aspd.get_public_client().await)).await;

	// create a third wallet to receive the invalid arkoor
	let bark2 = ctx.new_bark("bark2".to_string(), &proxy.address).await;

	bark1.send_oor(bark2.vtxo_pubkey().await, sat(10_000)).await;

	// we should drop invalid arkoors
	assert_eq!(bark2.vtxos().await.len(), 0);

	// check that we saw a log
	tokio::time::sleep(Duration::from_millis(250)).await;
	assert!(io::BufReader::new(std::fs::File::open(bark2.command_log_file()).unwrap()).lines().any(|line| {
		line.unwrap().contains("Received invalid arkoor VTXO from server: \
			error verifying one of the genesis transitions (idx=1): invalid signature")
	}));
}

#[tokio::test]
async fn second_round_attempt() {
	//! test that we can recover from an error in the round

	/// This proxy will drop the very first request to provide_forfeit_signatures.
	#[derive(Clone)]
	struct Proxy(rpc::ArkServiceClient<tonic::transport::Channel>, Arc<AtomicBool>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn provide_forfeit_signatures(
			&mut self,
			req: protos::ForfeitSignaturesRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.1.swap(false, atomic::Ordering::Relaxed) {
				Ok(protos::Empty {})
			} else {
				Ok(self.0.provide_forfeit_signatures(req).await?.into_inner())
			}
		}
	}

	let ctx = TestContext::new("bark/second_round_attempt").await;
	let aspd = ctx.new_aspd_with_cfg("aspd", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	ctx.fund_asp(&aspd, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &aspd, sat(1_000_000)).await;
	bark1.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let proxy = Proxy(aspd.get_public_client().await, Arc::new(AtomicBool::new(true)));
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	let bark2 = ctx.new_bark("bark2".to_string(), &proxy.address).await;
	bark1.send_oor(bark2.vtxo_pubkey().await, sat(200_000)).await;
	let bark2_vtxo = bark2.vtxos().await.get(0).expect("should have 1 vtxo").id;

	let mut log_missing_forfeits = aspd.subscribe_log::<MissingForfeits>().await;
	let mut log_not_allowed = aspd.subscribe_log::<RoundUserVtxoNotAllowed>().await;

	ctx.generate_blocks(1).await;
	let res1 = tokio::spawn(async move { bark1.refresh_all().await });
	let res2 = tokio::spawn(async move { bark2.refresh_all().await });
	tokio::time::sleep(Duration::from_millis(500)).await;
	let _ = aspd.get_admin_client().await.wallet_sync(protos::Empty {}).await.unwrap();
	aspd.trigger_round().await;
	aspd.wait_for_log::<RestartMissingForfeits>().await;
	res1.await.unwrap();
	// check that bark2 was kicked
	assert_eq!(log_missing_forfeits.recv().fast().await.unwrap().input, bark2_vtxo);
	assert_eq!(log_not_allowed.recv().fast().await.unwrap().vtxo, bark2_vtxo);

	// bark2 is kicked out of the first round, so we need to start another one
	ctx.generate_blocks(1).await;
	let _ = aspd.get_admin_client().await.wallet_sync(protos::Empty {}).await.unwrap();
	aspd.trigger_round().await;
	res2.await.unwrap();
}

#[tokio::test]
async fn recover_mnemonic() {
	let ctx = TestContext::new("bark/recover_mnemonic").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(2_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// make sure we have a round and an board vtxo (arkoor doesn't work)
	bark.refresh_all().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(1).await;
	let onchain = bark.onchain_balance().await;
	let _offchain = bark.offchain_balance().await;

	const MNEMONIC_FILE: &str = "mnemonic";
	let mnemonic = fs::read_to_string(bark.config().datadir.join(MNEMONIC_FILE)).await.unwrap();
	let _ = bip39::Mnemonic::parse(&mnemonic).expect("invalid mnemonic?");

	// first check we need birthday
	let args = &["--mnemonic", &mnemonic];
	// it's not easy to get a grip of what the actual error was
	let err = ctx.try_new_bark_with_create_args("bark_recovered", &aspd, args).await.unwrap_err();
	assert!(err.to_string().contains(
		"You need to set the --birthday-height field when recovering from mnemonic.",
	));

	let args = &["--mnemonic", &mnemonic, "--birthday-height", "0"];
	let recovered = ctx.try_new_bark_with_create_args("bark_recovered", &aspd, args).await.unwrap();
	assert_eq!(onchain, recovered.onchain_balance().await);
	//TODO(stevenroose) implement offchain recovery
	// assert_eq!(offchain, recovered.offchain_balance().await);
}

#[tokio::test]
async fn onchain_send() {
	let ctx = TestContext::new("bark/onchain_send").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &aspd, sat(1_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &aspd).await;

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
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &aspd, sat(10_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &aspd).await;
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
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(1)).await;
	let sender = ctx.new_bark_with_funds("bark_sender", &aspd, sat(1_000_000)).await;
	let recipient = ctx.new_bark("bark_recipient", &aspd).await;

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

	// Set up an aspd.
	// The aspd misbehaves and drops the first request to register_board_vtxo
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(1)).await;

	/// This proxy will drop the very first request to register_board
	#[derive(Clone)]
	struct Proxy(rpc::ArkServiceClient<tonic::transport::Channel>, Arc<AtomicBool>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn register_board_vtxo(
			&mut self,
			req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.1.swap(false, atomic::Ordering::Relaxed) {
				Err(tonic::Status::from_error("Nope! I do not register on the first attempt!".into()))
			} else {
				Ok(self.0.register_board_vtxo(req).await?.into_inner())
			}
		}
	}

	let proxy = Proxy(aspd.get_public_client().await, Arc::new(AtomicBool::new(true)));
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_00)).await;
	bark.try_board_all().await.expect_err("The Ark server should have refused the registration");

	assert_eq!(bark.vtxos().await.len(), 1);

	ctx.generate_blocks(12).await;
	bark.refresh_all().await;
}

#[tokio::test]
async fn bark_does_not_spend_too_deep_arkoors() {
	let ctx = TestContext::new("bark/does_not_spend_too_deep_arkoors").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(1)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark1.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let pk = bark2.vtxo_pubkey().await;
	bark1.send_oor(&pk, sat(100_000)).await;
	bark1.send_oor(&pk, sat(100_000)).await;
	bark1.send_oor(&pk, sat(100_000)).await;
	bark1.send_oor(&pk, sat(100_000)).await;
	bark1.send_oor(&pk, sat(100_000)).await;

	let err = bark1.try_send_oor(&pk, sat(100_000), false).await.unwrap_err();
	assert!(err.to_string().contains(
		"Insufficient money available. Needed 0.00100330 BTC but 0 BTC is available",
	), "err: {err}");
}
