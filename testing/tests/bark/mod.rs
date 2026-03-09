mod board;
mod chain_source;
mod create;
mod dust;
mod exit;
mod fees;
mod lightning;
mod mailbox;
mod movement;
mod onchain;
mod recover;
mod round;

use std::time::Duration;

use bitcoin::Amount;
use bitcoin_ext::P2TR_DUST_SAT;

use bark_json::cli::{MovementDestination, PaymentMethod};

use ark_testing::{btc, sat, signed_sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::util::{FutureExt, ToAltString};

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
