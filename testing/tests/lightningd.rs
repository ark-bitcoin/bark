
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ark::vtxo::VtxoPolicyKind;
use bark::lightning_invoice::Bolt11Invoice;
use ark_testing::constants::ROUND_CONFIRMATIONS;
use bark_json::primitives::VtxoStateInfo;
use bitcoin::Amount;
use cln_rpc as rpc;

use log::{info, trace};

use ark_testing::{btc, constants::BOARD_CONFIRMATIONS, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;
use bitcoin_ext::{P2TR_DUST, P2TR_DUST_SAT};
use server_rpc::protos::{self, prepare_lightning_receive_claim_request::LightningReceiveAntiDos};


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
	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Connect both peers and verify the connection succeeded
	info!("Connect `{}` to `{}`", lightning.sender.name, lightning.receiver.name);
	let mut grpc_client = lightning.sender.grpc_client().await;
	let peers = grpc_client.list_peers(rpc::ListpeersRequest{
		id: Some(lightning.receiver.id().await),
		level: None
	}).await.unwrap().into_inner().peers;

	assert_eq!(peers.len(), 1);

	// Fund lightningd_1
	info!("Funding lightningd_1");
	ctx.fund_lightning(&lightning.sender, btc(5)).await;
	ctx.generate_blocks(6).await;
	lightning.sender.wait_for_block_sync().await;


	info!("Lightningd_1 opens channel to lightningd_2");
	// Open a channel from lightningd_1 to lightningd_2
	lightning.sender.fund_channel(&lightning.receiver, btc(1)).await;
	lightning.sender.bitcoind().generate(6).await;
	lightning.sender.wait_for_block_sync().await;
	lightning.receiver.wait_for_block_sync().await;

	// Pay an invoice from lightningd_1 to lightningd_2
	trace!("receiver node creates an invoice");
	let invoice = lightning.receiver.invoice(Some(sat(1000)), "test_label", "Test Description").await;
	trace!("sender node pays the invoice");
	lightning.sender.pay_bolt11(invoice).await;
	lightning.receiver.wait_invoice_paid("test_label").await;
}

#[tokio::test]
async fn bark_pay_ln_succeeds() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_succeeds").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	{
		// Create a payable invoice
		let invoice_amount = btc(2);
		let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

		assert_eq!(bark_1.spendable_balance().await, board_amount);
		bark_1.pay_lightning(invoice, None).await;
		assert_eq!(bark_1.spendable_balance().await, btc(3));
	}

	{
		// Test invoice without amount, reusing previous change output
		let invoice_amount = btc(1);
		let invoice = lightning.receiver.invoice(None, "test_payment2", "A test payment").await;
		bark_1.pay_lightning(invoice, Some(invoice_amount)).await;
		assert_eq!(bark_1.spendable_balance().await, btc(2));
	}

	{
		// Test invoice with msat amount
		let invoice = lightning.receiver.invoice_msat(330300, "test_payment3", "msat").await;
		bark_1.pay_lightning(invoice, None).await;
		assert_eq!(bark_1.spendable_balance().await, btc(2) - sat(331));
	}

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_pay_ln_with_multiple_inputs() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_with_multiple_inputs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

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
	assert_eq!(bark_1.spendable_balance().await, expected_balance, "bark should have 3BTC spendable offchain");

	lightning.sync().await;

	let invoice = lightning.receiver.invoice(Some(expected_balance - sat(10_000)), "test_payment", "A test payment").await.clone();
	bark_1.pay_lightning(invoice.clone(), None).await;

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}


#[tokio::test]
async fn bark_pay_invoice_twice() {
	let ctx = TestContext::new("lightningd/bark_pay_invoice_twice").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, btc(7)).await;

	bark_1.board_and_confirm_and_register(&ctx, btc(5)).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	bark_1.pay_lightning(invoice.clone(), None).await;

	let res = bark_1.try_pay_lightning(invoice, None).await;
	assert!(res.unwrap_err().to_string().contains("Invoice has already been paid"));

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}


#[tokio::test]
async fn bark_pay_ln_fails() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_fails").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

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
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark.spendable_balance().await, board_amount);
	bark.try_pay_lightning(invoice, None).await.expect_err("The payment fails");

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

	assert_eq!(bark.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_refresh_ln_change_vtxo() {
	let ctx = TestContext::new("lightningd/bark_refresh_ln_change_vtxo").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.pay_lightning(invoice, None).await;
	assert_eq!(bark_1.spendable_balance().await, btc(3));

	bark_1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh {:?}", vtxos);
	assert_eq!(vtxos[0].amount, btc(3));

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_refresh_payment_revocation() {
	let ctx = TestContext::new("lightningd/bark_refresh_payment_revocation").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.try_pay_lightning(invoice, None).await.expect_err("The payment fails");

	bark_1.refresh_all().await;
	ctx.generate_blocks(srv.config().htlc_send_expiry_delta as u32 + 6).await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh {:?}", vtxos);
	assert_eq!(vtxos[0].amount, btc(2));

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_rejects_sending_subdust_bolt11_payment() {
	let ctx = TestContext::new("lightningd/bark_rejects_sending_subdust_bolt11_payment").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	{
		// Invoice with amount
		let invoice = lightning.receiver.invoice(Some(sat(P2TR_DUST_SAT - 1)), "test_payment", "A test payment").await;
		let res = bark_1.try_pay_lightning(invoice, None).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}

	{
		// Invoice with no amount
		let invoice = lightning.receiver.invoice(None, "test_payment2", "A test payment").await;
		let res = bark_1.try_pay_lightning(invoice, Some(sat(P2TR_DUST_SAT - 1))).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_can_send_full_balance_on_lightning() {
	let ctx = TestContext::new("lightningd/bark_can_send_full_balance_on_lightning").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(2);
	let board_amount = btc(1);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	let invoice = lightning.receiver.invoice(Some(board_amount), "test_payment2", "A test payment").await;
	bark_1.pay_lightning(invoice, None).await;

	let balance = bark_1.offchain_balance().await;
	assert_eq!(balance.spendable, btc(0));
	assert_eq!(balance.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_can_receive_lightning() {
	let ctx = TestContext::new("lightningd/bark_can_receive_lightning").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let receives = bark.list_lightning_receives().await;
	assert_eq!(receives.len(), 1);
	assert_eq!(receives[0].invoice.to_string(), invoice_info.invoice);
	assert!(receives[0].preimage_revealed_at.is_none());

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	srv.wait_for_vtxopool(&ctx).await;

	bark.lightning_receive(invoice_info.invoice.clone()).wait(10_000).await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	let vtxos = bark.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == pay_amount), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == board_amount));

	let [board_mvt, ln_receive_mvt] = bark.list_movements().await
		.try_into().expect("should have 2 movements");
	assert!(
		board_mvt.input_vtxos.is_empty() &&
		board_mvt.output_vtxos.len() == 1 &&
		board_mvt.offchain_fee == Amount::ZERO &&
		board_mvt.effective_balance == board_amount.to_signed().unwrap() &&
		board_mvt.sent_to.is_empty()
	);

	assert!(
		ln_receive_mvt.effective_balance == pay_amount.to_signed().unwrap() &&
		ln_receive_mvt.offchain_fee == Amount::ZERO &&
		ln_receive_mvt.sent_to.is_empty() &&
		ln_receive_mvt.received_on[0].destination == invoice.to_string() &&
		ln_receive_mvt.received_on[0].amount == pay_amount &&
		ln_receive_mvt.received_on.len() == 1
	);

	assert_eq!(bark.spendable_balance().await, board_amount + pay_amount);

	let receives = bark.list_lightning_receives().await;
	assert!(receives.is_empty());

	assert_eq!(bark.offchain_balance().await.pending_lightning_receive.total, btc(0),
		"pending lightning receive should be reset after payment");
	assert_eq!(bark.offchain_balance().await.pending_lightning_receive.claimable, btc(0),
		"pending lightning receive should be reset after payment");
	let vtxos = bark.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_check_lightning_receive_no_wait() {
	let ctx = TestContext::new("lightningd/bark_check_lightning_receive_no_wait").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

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
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
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

	assert_eq!(bark.offchain_balance().await.pending_lightning_receive.total, btc(0),
		"pending lightning receive should be reset after payment");
	assert_eq!(bark.offchain_balance().await.pending_lightning_receive.claimable, btc(0),
		"pending lightning receive should be reset after payment");
	let vtxos = bark.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_can_pay_intra_ark_invoice() {
	let ctx = TestContext::new("lightningd/bark_can_pay_intra_ark_invoice").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

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

	srv.wait_for_vtxopool(&ctx).await;

	let cloned = bark_1.clone();
	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		cloned.lightning_receive(cloned_invoice_info.invoice).wait(10_000).await;
	});

	let max_delay = srv.config().invoice_check_interval.as_millis() + 1_000;
	tokio::spawn(async move {
		// Payment settlement should not take more than receiver invoice check interval
		bark_2.pay_lightning(invoice_info.invoice, None).wait(max_delay as u64).await;

		assert_eq!(bark_2.offchain_balance().await.pending_lightning_send, btc(0),
			"pending lightning send should be reset after payment");
		let vtxos = bark_2.vtxos().await;
		assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
	});

	res1.await.unwrap();

	let vtxos = bark_1.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == pay_amount), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == board_amount), "should have fees change");

	assert_eq!(bark_1.spendable_balance().await, board_amount + pay_amount);

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_receive.total, btc(0),
		"pending lightning receive should be reset after payment");
	assert_eq!(bark_1.offchain_balance().await.pending_lightning_receive.claimable, btc(0),
		"pending lightning receive should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_can_revoke_on_intra_ark_timeout_invoice_pay_failure() {
	let ctx = TestContext::new("lightningd/bark_can_revoke_on_intra_ark_timeout_invoice_pay_failure").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.htlc_subscription_timeout = Duration::from_secs(0);
		cfg.invoice_check_interval = Duration::from_secs(1);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	let bark_2 = ctx.new_bark_with_funds("bark-2", &srv, btc(3)).await;

	let board_amount = btc(2);
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;
	bark_2.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = btc(0.5);
	let invoice_info = bark_1.bolt11_invoice(pay_amount).await;

	trace!("Sleeping to let invoice subscription timeout");
	tokio::time::sleep(Duration::from_secs(2)).await;

	let cloned = bark_1.clone();
	let cloned_invoice_info = invoice_info.clone();
	tokio::spawn(async move {
		cloned.lightning_receive(cloned_invoice_info.invoice).wait(10_000).await;
	});

	let err = bark_2.try_pay_lightning(invoice_info.invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("payment failed"), "should have received error. received: {}", err);

	let vtxos = bark_2.vtxos().await;
	assert_eq!(vtxos.len(), 2, "user should get 2 VTXOs, change and revocation one");
	assert!(vtxos.iter().any(|v| {
		v.policy_type == VtxoPolicyKind::Pubkey && v.amount == (board_amount - pay_amount)
	}), "user should get a change VTXO of 1btc");
	assert!(vtxos.iter().any(|v| {
		v.policy_type == VtxoPolicyKind::Pubkey && v.amount == pay_amount
	}), "user should get a revocation arkoor of payment_amount + forwarding fee");

	assert_eq!(bark_2.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_can_revoke_on_intra_ark_send_when_receiver_leaves() {
	let ctx = TestContext::new("lightningd/bark_can_revoke_on_intra_ark_send_when_receiver_leaves").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// speed htlc subscription timeout
		cfg.htlc_subscription_timeout = Duration::from_secs(2);
		// speed htlc subscription check
		cfg.invoice_check_interval = Duration::from_secs(1);
		// quick payment update check
		cfg.invoice_poll_interval = Duration::from_secs(1);
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await;
	let bark_2 = Arc::new(ctx.new_bark_with_funds("bark-2", &srv, btc(3)).await);

	let board_amount = btc(2);
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;
	bark_2.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = btc(0.5);
	let invoice_info = bark_1.bolt11_invoice(pay_amount).await;

	let cloned = bark_2.clone();
	let handle = tokio::spawn(async move {
		cloned.try_pay_lightning(invoice_info.invoice, None).await.unwrap_err()
	});

	// receiver never show up so invoice will eventually fail

	let err = handle.wait(10_000).await.unwrap();
	assert!(err.to_string().contains("payment failed"), "should have received error. received: {}", err);

	let vtxos = bark_2.vtxos().await;
	assert_eq!(vtxos.len(), 2, "user should get 2 VTXOs, change and revocation one");
	assert!(vtxos.iter().any(|v| {
		v.policy_type == VtxoPolicyKind::Pubkey && v.amount == (board_amount - pay_amount)
	}), "user should get a change VTXO of 1btc");
	assert!(vtxos.iter().any(|v| {
		v.policy_type == VtxoPolicyKind::Pubkey && v.amount == pay_amount
	}), "user should get a revocation arkoor of payment_amount + forwarding fee");

	assert_eq!(bark_2.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_revoke_expired_pending_ln_payment() {
	let ctx = TestContext::new("lightningd/bark_revoke_expired_pending_ln_payment").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	// No channels are created so that payment will fail

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;
	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy;

	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn finish_lightning_payment(
			&self,
			_upstream: &mut ArkClient,
			_req: server_rpc::protos::SignedLightningPaymentDetails,
		) -> Result<server_rpc::protos::LightningPaymentResult, tonic::Status> {
			// Never return - wait indefinitely
			loop {
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
			}
		}

		async fn check_lightning_payment(
			&self,
			_upstream: &mut ArkClient,
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

	let proxy = srv.get_proxy_rpc(Proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	// Try send coins through lightning
	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.try_pay_lightning(invoice, None).try_wait(1000).await.expect_err("the payment is held");

	// htlc expiry is 6 ahead of current block
	ctx.generate_blocks(srv.config().htlc_send_expiry_delta as u32 + 6).await;
	bark_1.maintain().await;

	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "user should get 2 VTXOs, change and revocation one");
	assert!(
		vtxos.iter().any(|v| v.amount == (board_amount - invoice_amount)),
		"user should get a change VTXO of 1btc");

	assert!(
		vtxos.iter().any(|v| v.amount == invoice_amount),
		"user should get a revocation arkoor of payment_amount + forwarding fee");

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}


#[tokio::test]
async fn bark_pay_ln_offer() {
	let ctx = TestContext::new("lightningd/bark_pay_ln_offer").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start an Ark Server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.receiver)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	// Pay invoice with no amount specified
	{
		let offer = lightning.receiver.offer(None, Some("A test payment")).await;
		bark_1.pay_lightning(offer, Some(btc(1))).await;

		let balance = bark_1.offchain_balance().await;
		assert_eq!(balance.spendable, btc(4));
		assert_eq!(balance.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
		let vtxos = bark_1.vtxos().await;
		assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
	}

	// Pay invoice with amount specified
	{
		let offer = lightning.receiver.offer(Some(btc(1)), Some("A test payment")).await;
		bark_1.pay_lightning(offer, None).await;

		let balance = bark_1.offchain_balance().await;
		assert_eq!(balance.spendable, btc(3));
		assert_eq!(balance.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
		let vtxos = bark_1.vtxos_no_sync().await;
		assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
	}
}

#[tokio::test]
async fn bark_pay_twice_ln_offer() {
	let ctx = TestContext::new("lightningd/bark_pay_twice_ln_offer").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start an Ark Server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	let offer = lightning.receiver.offer(None, Some("A test payment")).await;

	lightning.sync().await;

	bark_1.pay_lightning(offer.clone(), Some(btc(1))).await;
	assert_eq!(bark_1.spendable_balance().await, btc(4));

	bark_1.pay_lightning(offer, Some(btc(2))).await;

	let balance = bark_1.offchain_balance().await;
	assert_eq!(balance.spendable, btc(2));
	assert_eq!(balance.pending_lightning_send, btc(0), "pending lightning send should be reset after payment");
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");
}

#[tokio::test]
async fn bark_sends_on_lightning_after_receiving_from_lightning() {
	let ctx = TestContext::new("lightningd/bark_sends_on_lightning_after_receiving_from_lightning").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = Arc::new(ctx.new_lightningd("lightningd-1").await);
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);

	let pay_amount = btc(1);
	let invoice_recv_info = bark.bolt11_invoice(pay_amount).await;
	let invoice_recv = Bolt11Invoice::from_str(&invoice_recv_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice_recv).await.unwrap();

	let cloned_invoice_info = invoice_recv_info.clone();
	let cloned_lightningd_1 = lightningd_1.clone();
	let res1 = tokio::spawn(async move {
		cloned_lightningd_1.pay_bolt11(cloned_invoice_info.invoice).await
	});

	srv.wait_for_vtxopool(&ctx).await;

	bark.lightning_receive(invoice_recv_info.invoice.clone()).wait(10_000).await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(bark.spendable_balance().await, pay_amount);

	let invoice_send = lightningd_1.invoice(Some(sat(500_000)), "test_payment", "A test payment").await;
	bark.pay_lightning(invoice_send, None).await;

	assert_eq!(bark.spendable_balance().await, pay_amount - sat(500_000));
}

#[tokio::test]
async fn server_allows_claim_receive_with_vtxo_proof() {
	let ctx = TestContext::new("lightningd/server_allows_claim_receive_with_vtxo_proof").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server with anti-dos enabled and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.ln_receive_anti_dos_required = true;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let res = tokio::spawn(async move {
		lightning.sender.pay_bolt11(invoice_info.invoice).await;
	});

	srv.wait_for_vtxopool(&ctx).await;

	bark.lightning_receive_all().wait(20_000).await;

	// HTLC settlement on lightning side
	res.ready().await.unwrap();

	assert_eq!(bark.spendable_balance().await, btc(3));
}

#[tokio::test]
async fn server_rejects_claim_receive_for_bad_vtxo_proof() {
	let ctx = TestContext::new("lightningd/server_rejects_claim_receive_for_bad_vtxo_proof").await;

	#[derive(Clone)]
	struct InvalidVtxoProofProxy;

	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for InvalidVtxoProofProxy {
		async fn prepare_lightning_receive_claim(
			&self, upstream: &mut ArkClient, mut req: protos::PrepareLightningReceiveClaimRequest,
		) -> Result<protos::PrepareLightningReceiveClaimResponse, tonic::Status> {
			let bad_anti_dos = match req.lightning_receive_anti_dos.unwrap() {
				LightningReceiveAntiDos::Token(_) => panic!("unexpected token"),
				LightningReceiveAntiDos::InputVtxo(mut input) => {
					input.ownership_proof = vec![0; 64];
					LightningReceiveAntiDos::InputVtxo(input)
				},
			};
			req.lightning_receive_anti_dos = Some(bad_anti_dos);
			let res = upstream.prepare_lightning_receive_claim(req).await;
			match res {
				Ok(_) => panic!("should fail"),
				Err(_) => ()
			}
			Ok(protos::PrepareLightningReceiveClaimResponse {
				receive: None,
				htlc_vtxos: vec![],
			})
		}
	}

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server with anti-dos enabled and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.ln_receive_anti_dos_required = true;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	// create a proxy to invalidate the proof
	let proxy = srv.get_proxy_rpc(InvalidVtxoProofProxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark1", &proxy.address, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let invoice = invoice_info.invoice.clone();

	let _ = tokio::spawn(async move {
		lightning.sender.pay_bolt11(invoice).await;
	});

	srv.wait_for_vtxopool(&ctx).await;

	let res = bark.try_lightning_receive_no_wait(invoice_info.invoice).await;

	assert!(res.is_err());
	assert_eq!(bark.spendable_balance().await, btc(2));
}

#[tokio::test]
async fn server_allows_claim_receive_for_valid_token_but_not_for_invalid_or_used() {
	let ctx = TestContext::new("lightningd/server_allows_claim_receive_for_valid_token_but_not_for_invalid_or_used").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server with anti-dos enabled and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.ln_receive_anti_dos_required = true;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Add integration `single-use-board` token configuration for "captaind" with 1 open token count and a 60 seconds activity.
	let stdout = srv.integration_cmd(&["configure-token-type", "captaind", "single-use-board", "1", "100"]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);
	// Generate integration token of type single-use-board for "captaind" with a 60 seconds activity.
	let stdout = srv.integration_cmd(&["generate-token", "captaind", "single-use-board"]).await;
	let mut parts = stdout.split(' ');
	assert_eq!(parts.next().unwrap(), "Token:");
	let token = parts.next().unwrap().trim().to_string();

	// Start a bark and don't board anything
	let bark = Arc::new(ctx.new_bark_with_funds("bark1", &srv, btc(3)).await);

	let invoice_info_1 = bark.bolt11_invoice(btc(1)).await;
	let invoice_info_2 = bark.bolt11_invoice(btc(1)).await;
	let invoice_1 = invoice_info_1.invoice.clone();
	let invoice_2 = invoice_info_2.invoice.clone();

	let _res = tokio::spawn(async move {
		tokio::join!(
			lightning.sender.pay_bolt11(invoice_1),
			lightning.sender.pay_bolt11(invoice_2),
		)
	});

	srv.wait_for_vtxopool(&ctx).await;

	// First try claim with invalid token
	let res = bark.try_lightning_receive_with_token(invoice_info_1.invoice.clone(), "badtoken".to_string()).await;
	assert!(res.is_err());
	assert_eq!(bark.spendable_balance_no_sync().await, btc(0));
	// Then claim with valid token
	let res = bark.try_lightning_receive_with_token(invoice_info_1.invoice, token.clone()).await;
	assert!(res.is_ok());
	assert_eq!(bark.spendable_balance_no_sync().await, btc(1));
	// Claiming with token that has already been used should fail
	let res = bark.try_lightning_receive_with_token(invoice_info_2.invoice, token).await;
	assert!(res.is_err());
	assert_eq!(bark.spendable_balance_no_sync().await, btc(1));
}
