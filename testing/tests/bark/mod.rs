mod arkoor;
mod base;
mod board;
mod chain_source;
mod create;
mod dust;
mod exit;
mod fees;
mod lightning;
mod mailbox;
mod movement;
mod offboard;
mod onchain;
mod recover;
mod round;
mod vtxos;

use bitcoin::Amount;

use ark_testing::{btc, sat, signed_sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::util::FutureExt;

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
