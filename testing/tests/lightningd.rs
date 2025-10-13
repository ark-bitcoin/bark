
use std::str::FromStr;
use std::sync::Arc;

use bark::lightning_invoice::Bolt11Invoice;
use ark_testing::constants::ROUND_CONFIRMATIONS;
use bitcoin::Amount;
use cln_rpc as rpc;

use log::{info, trace};

use ark_testing::{btc, constants::BOARD_CONFIRMATIONS, daemon::captaind, sat, TestContext};
use ark_testing::util::{FutureExt};
use bitcoin_ext::{P2TR_DUST, P2TR_DUST_SAT};


#[tokio::test]
async fn start_lightningd() {
	let ctx = TestContext::new("lightningd/start_lightningd").await;
	// See https://github.com/ElementsProject/lightning/pull/7379
	// Why we need to generate 100 blocks before starting cln
	ctx.generate_blocks(100).await;

	// Start an instance of lightningd
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let mut client = lightningd_1.grpc_client().await;
	let result = client.getinfo(rpc::GetinfoRequest{}).await.unwrap();
	let info = result.into_inner();

	assert_eq!(info.alias.unwrap(), "lightningd-1");
}

/// A test that makes a simple lightning payment
/// If this tests fails there is something wrong with your lightning set-up
/// We don't integrate with `server` yet
#[tokio::test]
async fn cln_can_pay_lightning() {
	let ctx = TestContext::new("lightningd/cln_can_pay_lightning").await;
	// See https://github.com/ElementsProject/lightning/pull/7379
	// Why we need to generate 100 blocks before starting cln
	ctx.generate_blocks(100).await;

	// Start an instance of lightningd
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Connect both peers and verify the connection succeeded
	info!("Connect `{}` to `{}`", lightningd_1.name, lightningd_2.name);
	lightningd_1.wait_for_block_sync().await;
	lightningd_1.connect(&lightningd_2).await;
	let mut grpc_client = lightningd_1.grpc_client().await;
	let peers = grpc_client.list_peers(rpc::ListpeersRequest{
		id: Some(lightningd_2.id().await),
		level: None
	}).await.unwrap().into_inner().peers;

	assert_eq!(peers.len(), 1);

	// Fund lightningd_1
	info!("Funding lightningd_1");
	ctx.fund_lightning(&lightningd_1, btc(5)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;


	info!("Lightningd_1 opens channel to lightningd_2");
	// Open a channel from lightningd_1 to lightningd_2
	lightningd_1.fund_channel(&lightningd_2, btc(1)).await;
	lightningd_1.bitcoind().generate(6).await;
	lightningd_1.wait_for_block_sync().await;
	lightningd_2.wait_for_block_sync().await;

	// Pay an invoice from lightningd_1 to lightningd_2
	trace!("Lightningd_2 creates an invoice");
	let invoice = lightningd_2.invoice(Some(sat(1000)), "test_label", "Test Description").await;
	trace!("lightningd_1 pays the invoice");
	lightningd_1.pay_bolt11(invoice).await;
	lightningd_2.wait_invoice_paid("test_label").await;
}

#[tokio::test]
async fn bark_pay_ln_succeeds() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_succeeds").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	{
		// Create a payable invoice
		let invoice_amount = btc(2);
		let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

		assert_eq!(bark_1.offchain_balance().await, board_amount);
		bark_1.send_lightning(invoice, None).await;
		assert_eq!(bark_1.offchain_balance().await, btc(3));
	}

	{
		// Test invoice without amount, reusing previous change output
		let invoice_amount = btc(1);
		let invoice = lightningd_2.invoice(None, "test_payment2", "A test payment").await;
		bark_1.send_lightning(invoice, Some(invoice_amount)).await;
		assert_eq!(bark_1.offchain_balance().await, btc(2));
	}

	{
		// Test invoice with msat amount
		let invoice = lightningd_2.invoice_msat(330300, "test_payment3", "msat").await;
		bark_1.send_lightning(invoice, None).await;
		assert_eq!(bark_1.offchain_balance().await, btc(2) - sat(331));
	}
}

#[tokio::test]
async fn bark_pay_ln_with_multiple_inputs() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_with_multiple_inputs").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_1), btc(10)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, btc(10)).await;
	let bark_2 = ctx.new_bark_with_funds("bark-2", &srv, btc(10)).await;

	bark_1.board(btc(1)).await;
	bark_2.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.refresh_all().await;
	bark_1.board(btc(1)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_2.maintain().await;
	bark_2.send_oor(bark_1.address().await, btc(1)).await;

	let expected_balance = btc(3);
	assert_eq!(bark_1.offchain_balance().await, expected_balance, "bark should have 3BTC spendable offchain");

	let invoice = lightningd_2.invoice(Some(expected_balance - sat(10_000)), "test_payment", "A test payment").await.clone();
	bark_1.send_lightning(invoice.clone(), None).await;
}


#[tokio::test]
async fn bark_pay_invoice_twice() {
	let ctx = TestContext::new("lightningd/bark_pay_invoice_twice").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, btc(7)).await;

	bark_1.board_and_confirm_and_register(&ctx, btc(5)).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	bark_1.send_lightning(invoice.clone(), None).await;

	let res = bark_1.try_send_lightning(invoice, None).await;
	assert!(res.unwrap_err().to_string().contains("Invoice has already been paid"))
}


#[tokio::test]
async fn bark_pay_ln_fails() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_fails").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// No channels are created
	// The payment must fail

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark = ctx.new_bark_with_funds("bark", &srv, onchain_amount).await;

	// Board funds into the Ark
	bark.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let board_vtxo = bark.vtxos().await.into_iter().next().unwrap().id;

	// Create a payable invoice
	let invoice_amount = btc(0.5);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark.offchain_balance().await, board_amount);
	bark.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	let vtxos = bark.vtxos().await;
	assert!(!vtxos.iter().any(|v| v.id == board_vtxo), "board vtxo not spent");
	assert_eq!(vtxos.len(), 2,
		"user should get 2 VTXOs, change and revocation one, got: {:?}", vtxos,
	);
	assert!(
		vtxos.iter().any(|v| v.amount == (board_amount - invoice_amount)),
		"user should get a change VTXO of 1btc, got: {:?}", vtxos,
	);

	assert!(
		vtxos.iter().any(|v| v.amount == invoice_amount),
		"user should get a revocation arkoor of payment_amount + forwarding fee, got: {:?}", vtxos,
	);
}

#[tokio::test]
async fn bark_refresh_ln_change_vtxo() {
	let ctx = TestContext::new("lightningd/bark_refresh_ln_change_vtxo").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_1), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.send_lightning(invoice, None).await;
	assert_eq!(bark_1.offchain_balance().await, btc(3));

	bark_1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh {:?}", vtxos);
	assert_eq!(vtxos[0].amount, btc(3));
}

#[tokio::test]
async fn bark_refresh_payment_revocation() {
	let ctx = TestContext::new("lightningd/bark_refresh_payment_revocation").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// No channels are created
	// The payment must fail

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_1), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	bark_1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh {:?}", vtxos);
	assert_eq!(vtxos[0].amount, btc(2));
}

#[tokio::test]
async fn bark_rejects_sending_subdust_bolt11_payment() {
	let ctx = TestContext::new("lightningd/bark_rejects_sending_subdust_bolt11_payment").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	{
		// Invoice with amount
		let invoice = lightningd_2.invoice(Some(sat(P2TR_DUST_SAT - 1)), "test_payment", "A test payment").await;
		let res = bark_1.try_send_lightning(invoice, None).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}

	{
		// Invoice with no amount
		let invoice = lightningd_2.invoice(None, "test_payment2", "A test payment").await;
		let res = bark_1.try_send_lightning(invoice, Some(sat(P2TR_DUST_SAT - 1))).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}
}

#[tokio::test]
async fn bark_can_send_full_balance_on_lightning() {
	let ctx = TestContext::new("lightningd/bark_can_send_full_balance_on_lightning").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(2);
	let board_amount = btc(1);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	let invoice = lightningd_2.invoice(Some(board_amount), "test_payment2", "A test payment").await;
	bark_1.send_lightning(invoice, None).await;

	assert_eq!(0, bark_1.offchain_balance().await.to_sat());
}

#[tokio::test]
async fn bark_can_receive_lightning() {
	let ctx = TestContext::new("lightningd/bark_can_receive_lightning").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightningd_1.pay_bolt11(cloned_invoice_info.invoice).await
	});

	srv.wait_for_vtxopool().await;

	bark.lightning_receive(invoice_info.invoice.clone()).wait(10_000).await;

	// trigger a maintenance to claim the lightning receive
	bark.maintain().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	let vtxos = bark.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == pay_amount), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == board_amount));

	let [board_mvt, ln_round_mvt, ln_claim_mvt] = bark.list_movements().await
		.try_into().expect("should have 4 movements");
	assert!(
		board_mvt.spends.is_empty() &&
		board_mvt.fees == Amount::ZERO &&
		board_mvt.receives[0].amount == board_amount &&
		board_mvt.recipients.is_empty()
	);

	assert!(
		ln_round_mvt.spends.is_empty() &&
		ln_round_mvt.fees == Amount::ZERO &&
		ln_round_mvt.receives[0].amount == pay_amount &&
		ln_round_mvt.recipients.is_empty()
	);

	assert!(
		ln_claim_mvt.spends[0].amount == pay_amount &&
		ln_claim_mvt.fees == Amount::ZERO &&
		ln_claim_mvt.receives[0].amount == pay_amount &&
		ln_claim_mvt.recipients.is_empty()
	);

	assert_eq!(bark.offchain_balance().await, board_amount + pay_amount);

	let receives = bark.list_lightning_receives().await;
	assert_eq!(receives.len(), 1);
	assert_eq!(receives[0].invoice.to_string(), invoice_info.invoice);
	assert!(receives[0].preimage_revealed_at.is_some());
}

#[tokio::test]
async fn bark_check_lightning_receive_no_wait() {
	let ctx = TestContext::new("lightningd/bark_check_lightning_receive_no_wait").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;
	srv.wait_for_vtxopool().await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let error = bark.try_lightning_receive_no_wait(invoice_info.invoice.clone()).ready().await.unwrap_err();
	assert!(error.to_string().contains("payment not yet initiated by sender"), "should have received error.  received: {}", error);

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightningd_1.pay_bolt11(cloned_invoice_info.invoice).await
	});

	let mut success = false;
	for _ in 0..10 {
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
		if bark.try_lightning_receive_no_wait(invoice_info.invoice.clone()).await.is_ok() {
			success = true;
			break;
		}
	}

	if !success {
		panic!("Lightning receive could not be claimed")
	}

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();
}

#[tokio::test]
async fn bark_can_pay_an_invoice_generated_by_same_server_user() {
	let ctx = TestContext::new("lightningd/bark_can_pay_an_invoice_generated_by_same_server_user").await;
	let ctx = Arc::new(ctx);

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	let bark_2 = Arc::new(ctx.new_bark_with_funds("bark-2", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark_1.board(board_amount).await;
	bark_2.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.maintain().await;
	bark_2.maintain().await;

	let pay_amount = btc(1);
	let invoice_info = bark_1.bolt11_invoice(pay_amount).await;

	srv.wait_for_vtxopool().await;

	let cloned = bark_1.clone();
	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		cloned.lightning_receive(cloned_invoice_info.invoice).wait(10_000).await;
	});

	let max_delay = srv.config().invoice_check_interval.as_millis() + 1_000;
	tokio::spawn(async move {
		// Payment settlement should not take more than receiver invoice check interval
		bark_2.send_lightning(invoice_info.invoice, None).wait(max_delay as u64).await;
	});

	res1.await.unwrap();

	let vtxos = bark_1.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == pay_amount), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == board_amount), "should have fees change");

	assert_eq!(bark_1.offchain_balance().await, board_amount + pay_amount);
}

#[tokio::test]
async fn bark_revoke_expired_pending_ln_payment() {
	let ctx = TestContext::new("lightningd/bark_revoke_expired_pending_ln_payment").await;

	// Start three lightning nodes and connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;
	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);

	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> server_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self,
			_req: server_rpc::protos::SignedLightningPaymentDetails,
		) -> Result<server_rpc::protos::LightningPaymentResult, tonic::Status> {
			// Never return - wait indefinitely
			loop {
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
			}
		}

		async fn check_lightning_payment(
			&mut self,
			_req: server_rpc::protos::CheckLightningPaymentRequest,
		) -> Result<server_rpc::protos::LightningPaymentResult, tonic::Status> {
			Ok(server_rpc::protos::LightningPaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: server_rpc::protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = captaind::proxy::ArkRpcProxyServer::start(proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).try_wait(1000).await.expect_err("the payment is held");

	// htlc expiry is 6 ahead of current block
	ctx.generate_blocks(8).await;
	bark_1.maintain().await;

	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "user should get 2 VTXOs, change and revocation one");
	assert!(
		vtxos.iter().any(|v| v.amount == (board_amount - invoice_amount)),
		"user should get a change VTXO of 1btc");

	assert!(
		vtxos.iter().any(|v| v.amount == invoice_amount),
		"user should get a revocation arkoor of payment_amount + forwarding fee");
}


#[tokio::test]
async fn bark_pay_ln_offer() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_offer").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an Ark Server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	// Pay invoice with no amount specified
	{
		let offer = lightningd_2.offer(None, Some("A test payment")).await;
		bark_1.send_lightning(offer, Some(btc(1))).await;
		assert_eq!(bark_1.offchain_balance().await, btc(4));
	}

	// Pay invoice with amount specified
	{
		let offer = lightningd_2.offer(Some(btc(1)), Some("A test payment")).await;
		bark_1.send_lightning(offer, None).await;
		assert_eq!(bark_1.offchain_balance().await, btc(3));
	}
}

#[tokio::test]
async fn bark_pay_twice_ln_offer() {
	let ctx = TestContext::new("lightningd/bark_pay_twice_ln_offer").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an Ark Server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	let offer = lightningd_2.offer(None, Some("A test payment")).await;

	bark_1.send_lightning(offer.clone(), Some(btc(1))).await;
	assert_eq!(bark_1.offchain_balance().await, btc(4));

	bark_1.send_lightning(offer, Some(btc(2))).await;
	assert_eq!(bark_1.offchain_balance().await, btc(2));
}
