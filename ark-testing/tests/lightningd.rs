#[macro_use]
extern crate log;

use bitcoin::Amount;

use ark_testing::TestContext;
use bark_cln::grpc;

#[tokio::test]
async fn start_lightningd() {
	let context = TestContext::new("lightningd/start-lightningd");
	let bitcoind = context.bitcoind("bitcoind-1").await;
	// See https://github.com/ElementsProject/lightning/pull/7379
	// Why we need to generate 100 blocks before starting cln
	bitcoind.generate(100).await;

	// Start an instance of lightningd
	let lightningd_1 = context.lightningd("lightningd-1", &bitcoind).await;
	let mut client = lightningd_1.grpc_client().await;
	let result = client.getinfo(grpc::GetinfoRequest{}).await.unwrap();
	let info = result.into_inner();

	assert_eq!(info.alias.unwrap(), "lightningd-1");
}

/// A test that makes a simple lightning payment
/// If this tests fails there is something wrong with your lightning set-up
/// We don't integrate with `aspd` yet
#[tokio::test]
async fn pay_lightningd() {
	let context = TestContext::new("lightningd/pay-lightningd");
	let bitcoind = context.bitcoind("bitcoind-1").await;
	// See https://github.com/ElementsProject/lightning/pull/7379
	// Why we need to generate 100 blocks before starting cln
	bitcoind.generate(100).await;

	// Start an instance of lightningd
	let (lightningd_1, lightningd_2) = tokio::join!(
		context.lightningd("lightningd-1", &bitcoind),
		context.lightningd("lightningd-2", &bitcoind)
	);

	// Connect both peers and verify the connection succeeded
	info!("Connect `{}` to `{}`", lightningd_1.name(), lightningd_2.name());
	lightningd_1.connect(&lightningd_2).await;
	let mut grpc_client = lightningd_1.grpc_client().await;
	let peers = grpc_client.list_peers(grpc::ListpeersRequest{
		id: Some(lightningd_2.id().await),
		level: None
	}).await.unwrap().into_inner().peers;

	assert_eq!(peers.len(), 1);

	// Fund lightningd_1
	info!("Funding lightningd_1");
	bitcoind.generate(101).await;
	bitcoind.fund_lightningd(&lightningd_1, Amount::from_int_btc(5)).await;
	bitcoind.generate(6).await;
	lightningd_1.wait_for_block_sync(&bitcoind).await;


	info!("Lightningd_1 opens channel to lightningd_2");
	// Open a channel from lightningd_1 to lightningd_2
	lightningd_1.fund_channel(&lightningd_2, Amount::from_int_btc(1)).await;
	bitcoind.generate(6).await;
	lightningd_1.wait_for_block_sync(&bitcoind).await;
	lightningd_2.wait_for_block_sync(&bitcoind).await;

	// Pay an invoice from lightningd_1 to lightningd_2
	trace!("Lightningd_2 creates an invoice");
	let invoice = lightningd_2.invoice(Amount::from_sat(1000), "test_label", "Test Description").await;
	trace!("lightningd_1 pays the invoice");
	lightningd_1.pay_bolt11(invoice).await;
	lightningd_2.wait_invoice_paid("test_label").await;
}
