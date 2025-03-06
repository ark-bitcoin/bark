#[macro_use]
extern crate log;

use bark_cln::grpc;

use ark_testing::{TestContext, btc, sat};

#[tokio::test]
async fn start_lightningd() {
	let ctx = TestContext::new("lightningd/start_lightningd").await;
	// See https://github.com/ElementsProject/lightning/pull/7379
	// Why we need to generate 100 blocks before starting cln
	ctx.bitcoind.generate(100).await;

	// Start an instance of lightningd
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let mut client = lightningd_1.grpc_client().await;
	let result = client.getinfo(grpc::GetinfoRequest{}).await.unwrap();
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
	ctx.bitcoind.generate(100).await;

	// Start an instance of lightningd
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Connect both peers and verify the connection succeeded
	info!("Connect `{}` to `{}`", lightningd_1.name, lightningd_2.name);
	lightningd_1.wait_for_block_sync().await;
	lightningd_1.connect(&lightningd_2).await;
	let mut grpc_client = lightningd_1.grpc_client().await;
	let peers = grpc_client.list_peers(grpc::ListpeersRequest{
		id: Some(lightningd_2.id().await),
		level: None
	}).await.unwrap().into_inner().peers;

	assert_eq!(peers.len(), 1);

	// Fund lightningd_1
	info!("Funding lightningd_1");
	ctx.fund_lightning(&lightningd_1, btc(5)).await;
	ctx.bitcoind.generate(6).await;
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
	let ctx = TestContext::new("lightningd/bark_pay_ln").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.bitcoind.generate(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.bitcoind.generate(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let onboard_amount = btc(5);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	bark_1.onboard(onboard_amount).await;
	ctx.bitcoind.generate(6).await;

	{
		// Create a payable invoice
		let invoice_amount = btc(2);
		let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

		assert_eq!(bark_1.offchain_balance().await, onboard_amount);
		bark_1.send_bolt11(invoice, None).await;
		assert_eq!(bark_1.offchain_balance().await, sat(299999320));
	}

	{
		// Test invoice without amount, reusing previous change output
		let invoice_amount = btc(1);
		let invoice = lightningd_2.invoice(None, "test_payment2", "A test payment").await;
		bark_1.send_bolt11(invoice, Some(invoice_amount)).await;
		assert_eq!(bark_1.offchain_balance().await, sat(199998640));
	}
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
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let onboard_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	bark_1.onboard(onboard_amount).await;
	ctx.bitcoind.generate(6).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Onboard funds into the Ark
	assert_eq!(bark_1.offchain_balance().await, onboard_amount);
	bark_1.try_send_bolt11(invoice, None).await.expect_err("The payment fails");

	// The payment fails, the user still has all their funds
	assert_eq!(bark_1.offchain_balance().await, onboard_amount);
}

// TODO: add a test to refreshing Bolt11Change vtxo
