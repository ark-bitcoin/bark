use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::{FutureExt, ToAltString};
use bark::movement::{MovementDestination, PaymentMethod};
use futures::StreamExt;

#[tokio::test]
async fn send_simple_arkoor() {
	let ctx = TestContext::new("bark/send_simple_arkoor").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(90_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(5_000)).await;

	bark1.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	// Open a wallet client for bark2 and subscribe to notifications before the send
	let bark2_wallet = bark2.client().await;
	// NB: only use `bark2_wallet` from now since we can't have 2 wallets on same persistence yet

	let notifications = bark2_wallet.subscribe_notifications();

	let addr2 = bark2_wallet.new_address().await.unwrap();
	bark1.send_oor(&addr2, sat(20_000)).await;

	// Sync bark2 via the wallet client and receive the notification that the arkoor payment was received
	bark2_wallet.sync().await;
	let movement = notifications.movements().next().ready().await.unwrap();
	assert_eq!(movement.received_on[0], MovementDestination {
		destination: PaymentMethod::Ark(addr2),
		amount: sat(20_000),
	});

	assert_eq!(60_000, bark1.spendable_balance().await.to_sat());
	assert_eq!(20_000, bark2_wallet.balance().await.unwrap().spendable.to_sat());
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
