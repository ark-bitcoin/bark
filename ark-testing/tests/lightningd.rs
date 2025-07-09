
use std::sync::Arc;

use bitcoin::Amount;
use cln_rpc as rpc;

use log::{info, trace};

use ark_testing::{btc, constants::BOARD_CONFIRMATIONS, daemon::aspd, sat, TestContext};
use ark_testing::util::FutureExt;
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
/// We don't integrate with `aspd` yet
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

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	{
		// Create a payable invoice
		let invoice_amount = btc(2);
		let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

		assert_eq!(bark_1.offchain_balance().await, board_amount);
		bark_1.send_bolt11(invoice, None).await;
		assert_eq!(bark_1.offchain_balance().await, btc(3));
	}

	{
		// Test invoice without amount, reusing previous change output
		let invoice_amount = btc(1);
		let invoice = lightningd_2.invoice(None, "test_payment2", "A test payment").await;
		bark_1.send_bolt11(invoice, Some(invoice_amount)).await;
		assert_eq!(bark_1.offchain_balance().await, btc(2));
	}

	{
		// Test invoice with msat amount
		let invoice = lightningd_2.invoice_msat(330300, "test_payment3", "msat").await;
		bark_1.send_bolt11(invoice, None).await;
		assert_eq!(bark_1.offchain_balance().await, btc(2) - sat(331));
	}
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

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, btc(7)).await;

	bark_1.board(btc(5)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	bark_1.send_bolt11(invoice.clone(), None).await;

	let res = bark_1.try_send_bolt11(invoice, None).await;
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

	// Start an aspd and link it to our cln installation
	let aspd = ctx.new_aspd("aspd", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark = ctx.new_bark_with_funds("bark", &aspd, onchain_amount).await;

	// Board funds into the Ark
	bark.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let board_vtxo = bark.vtxos().await.into_iter().next().unwrap().id;

	// Create a payable invoice
	let invoice_amount = btc(0.5);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark.offchain_balance().await, board_amount);
	bark.try_send_bolt11(invoice, None).await.expect_err("The payment fails");

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

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd_with_funds("aspd-1", Some(&lightningd_1), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.send_bolt11(invoice, None).await;
	assert_eq!(bark_1.offchain_balance().await, btc(3));

	bark_1.refresh_all().await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh");
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

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd_with_funds("aspd-1", Some(&lightningd_1), btc(10)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_bolt11(invoice, None).await.expect_err("The payment fails");

	bark_1.refresh_all().await;
	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 1, "there should be only one vtxo after refresh");
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

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	{
		// Invoice with amount
		let invoice = lightningd_2.invoice(Some(sat(P2TR_DUST_SAT - 1)), "test_payment", "A test payment").await;
		let res = bark_1.try_send_bolt11(invoice, None).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}

	{
		// Invoice with no amount
		let invoice = lightningd_2.invoice(None, "test_payment2", "A test payment").await;
		let res = bark_1.try_send_bolt11(invoice, Some(sat(P2TR_DUST_SAT - 1))).await;
		assert!(res.unwrap_err().to_string().contains(&format!("Sent amount must be at least {}", P2TR_DUST)));
	}
}

#[tokio::test]
async fn bark_can_board_from_lightning() {
	let ctx = TestContext::new("lightningd/bark_can_board_from_lightning").await;

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
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd = ctx.new_aspd_with_funds("aspd", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &aspd, btc(3)).await);
	bark.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = bark.clone();
	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		cloned.bolt11_board(cloned_invoice_info.invoice).await
	});
	lightningd_1.pay_bolt11(invoice_info.invoice).wait(30_000).await;
	res1.await.unwrap();

	let vtxos = bark.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == btc(1)), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == sat(199999650)), "should have fees change");

	let [ln_board_mvt, fee_split_mvt, board_mvt] = bark.list_movements().await
		.try_into().expect("should have 3 movements");
	assert!(
		board_mvt.spends.is_empty() &&
		board_mvt.fees == Amount::ZERO &&
		board_mvt.receives[0].amount == btc(2) &&
		board_mvt.recipients.is_empty()
	);

	assert!(
		fee_split_mvt.spends[0].amount == btc(2) &&
		fee_split_mvt.fees == Amount::ZERO &&
		fee_split_mvt.receives[0].amount == sat(350) &&
		fee_split_mvt.receives[1].amount == sat(199999650) &&
		board_mvt.recipients.is_empty()
	);

	assert!(
		ln_board_mvt.spends[0].amount == sat(350) &&
		ln_board_mvt.fees == sat(350) &&
		ln_board_mvt.receives[0].amount == btc(1) &&
		board_mvt.recipients.is_empty()
	);

	assert_eq!(bark.offchain_balance().await, sat(299999650));
}

#[tokio::test]
async fn bark_can_pay_an_invoice_generated_by_same_asp_user() {
	let ctx = TestContext::new("lightningd/bark_can_pay_an_invoice_generated_by_same_asp_user").await;

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
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd_with_funds("aspd-1", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = Arc::new(ctx.new_bark_with_funds("bark-1", &aspd_1, btc(3)).await);
	let bark_2 = Arc::new(ctx.new_bark_with_funds("bark-2", &aspd_1, btc(3)).await);
	bark_1.board(btc(2)).await;
	bark_2.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_info = bark_1.bolt11_invoice(btc(1)).await;

	let cloned = bark_1.clone();
	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		cloned.bolt11_board(cloned_invoice_info.invoice).await
	});

	bark_2.send_bolt11(invoice_info.invoice, None).await;
	res1.await.unwrap();

	let vtxos = bark_1.vtxos().await;
	assert!(vtxos.iter().any(|v| v.amount == btc(1)), "should have received lightning amount");
	assert!(vtxos.iter().any(|v| v.amount == sat(199999650)), "should have fees change");

	assert_eq!(bark_1.offchain_balance().await, sat(299999650));
}

#[tokio::test]
async fn bark_revoke_expired_pending_ln_payment() {
	let ctx = TestContext::new("lightningd/bark_revoke_expired_pending_ln_payment").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;
	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_bolt11_payment(
			&mut self,
			_req: aspd_rpc::protos::SignedBolt11PaymentDetails,
		) -> Result<aspd_rpc::protos::Bolt11PaymentResult, tonic::Status> {
			// Never return - wait indefinitely
			loop {
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
			}
		}

		async fn check_bolt11_payment(
			&mut self,
			_req: aspd_rpc::protos::CheckBolt11PaymentRequest,
		) -> Result<aspd_rpc::protos::Bolt11PaymentResult, tonic::Status> {
			Ok(aspd_rpc::protos::Bolt11PaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: aspd_rpc::protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}
	}

	let proxy = Proxy(aspd_1.get_public_client().await);
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_bolt11(invoice, None).try_fast().await.expect_err("the payment is held");

	// htlc expiry is 6 ahead of current block
	ctx.generate_blocks(8).await;

	// Triggers maintenance under the hood
	bark_1.offchain_balance().await;

	let vtxos = bark_1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "user should get 2 VTXOs, change and revocation one");
	assert!(
		vtxos.iter().any(|v| v.amount == (board_amount - invoice_amount)),
		"user should get a change VTXO of 1btc");

	assert!(
		vtxos.iter().any(|v| v.amount == invoice_amount),
		"user should get a revocation arkoor of payment_amount + forwarding fee");
}
