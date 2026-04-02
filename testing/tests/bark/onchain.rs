use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};

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
async fn list_utxos() {
	let ctx = TestContext::new("bark/list_utxos").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, &[&bark]).await;
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
