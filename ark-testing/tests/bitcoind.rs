extern crate bitcoincore_rpc;

use bitcoincore_rpc::RpcApi;
use ark_testing::context::TestContext;

#[tokio::test]
async fn start_bitcoind()  {
	let context = TestContext::new("bitcoind/start_bitcoind");
	let bitcoind = context.bitcoind("bitcoind-1").await;

	let client = bitcoind.sync_client();
	let info = client.get_blockchain_info().unwrap();
	assert_eq!(info.chain.to_string(), "regtest");
}

#[tokio::test]
async fn fund_bitcoind() {
	let context = TestContext::new("bitcoind/fund_bitcoind");
	let bitcoind = context.bitcoind("bitcoind-1").await;

	// We can initialize the wallet twice
	bitcoind.init_wallet().await;
	bitcoind.init_wallet().await;

	// We can fund the wallet
	bitcoind.generate(101).await;

	// Check the balance
	let client = bitcoind.sync_client();
	let amount = client.get_balance(Some(6), None).unwrap();
	assert!(amount.to_sat() > 100_000_000);
}

