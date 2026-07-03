
use bitcoin::Amount;
use bitcoin_ext::P2TR_DUST_SAT;

use bark_json::movements::{MovementDestination, PaymentMethod};

use ark_testing::{btc, sat, TestContext, require_bark_version};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::util::ToAltString;

#[tokio::test]
async fn offboard_all() {
	require_bark_version!(> "0.2.3");

	let ctx = TestContext::new("bark/offboard_all").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

	bark1.board(sat(200_000)).await;
	bark2.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, &[&bark1]).await;
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
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

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
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;

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
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

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
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;

	let board_amount = sat(800_000);
	bark1.board_and_confirm_and_register(&ctx, board_amount).await;

	let addr = bark2.get_onchain_address().await;

	let err = bark1.try_send_onchain(&addr, sat(P2TR_DUST_SAT - 1)).await.unwrap_err();
	let err = err.to_alt_string();
	assert!(
		// current wallet
		err.contains("the minimum you can send")
		// bark <= 0.2.x under the backward-compat jobs
		|| err.contains("it doesn't make sense to send dust"),
		"err: {err}",
	);
}

#[tokio::test]
async fn old_bark_recovers_from_rejected_forfeit_sigs() {
	require_bark_version!(== "0.2.3");

	let ctx = TestContext::new("bark/old_bark_recovers_from_rejected_forfeit_sigs").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let bark = ctx.bark("bark", &srv)
		.boarded(sat(1_000_000))
		.boarded(sat(1_000_000))
		.create().await;

	let old_balance = bark.offchain_balance().await;
	let vtxos = bark.vtxos().await;
	println!("vtxos before: {:#?}", vtxos);

	let addr = bark.get_onchain_address().await;
	assert!(bark.try_send_onchain(&addr, sat(1_850_000)).await.is_err());

	let vtxos = bark.vtxos().await;
	println!("vtxos after: {:#?}", vtxos);
	assert_ne!(old_balance, bark.offchain_balance().await);

	// Here we use a hack: the SDK is always at the latest version,
	// so creating this client will apply the latest migration and it should unstuck
	// the movement
	let client = bark.client().await;
	client.sync().await;
	let vtxos = client.vtxos().await.unwrap();
	println!("vtxos sdk: {:#?}", vtxos);
	let balance = client.balance().await.unwrap();
	assert_eq!(bark_json::cli::Balance::from(balance), old_balance);

	// The recovered VTXOs must actually be spendable: offboard everything
	// with the new SDK and check the funds arrive onchain.
	let address = ctx.bitcoind().get_new_address();
	client.offboard_all(address.clone()).await.unwrap();

	assert_eq!(client.balance().await.unwrap().spendable, Amount::ZERO);

	ctx.generate_blocks(1).await;
	let offboard_fee = sat(854);
	assert_eq!(
		ctx.bitcoind().get_received_by_address(&address),
		old_balance.spendable - offboard_fee,
	);
}
