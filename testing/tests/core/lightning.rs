use cln_rpc as rpc;
use log::{info, trace};

use ark_testing::{btc, sat, TestContext};

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
