extern crate bitcoincore_rpc;

use bitcoincore_rpc::RpcApi;
use ark_testing::context::TestContext;

#[tokio::test]
async fn start_bitcoind()  {
	let context = TestContext::new("bitcoind/start_bitcoind");
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind can be initialized");

	let client = bitcoind.sync_client().expect("Client can be created");
	let info = client.get_blockchain_info().expect("Get info about the blockchain");
	assert_eq!(info.chain.to_string(), "regtest");
}

#[tokio::test]
async fn fund_bitcoind() {
	let context = TestContext::new("bitcoind/fund_bitcoind");
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind can be initialized");

	// We can initialize the wallet twice
	bitcoind.init_wallet().await.unwrap();
	bitcoind.init_wallet().await.unwrap();

	// We can fund the wallet
	bitcoind.generate(101).await.unwrap();

	// Check the balance
	let client = bitcoind.sync_client().unwrap();
	let amount = client.get_balance(Some(6), None).unwrap();
	assert!(amount.to_sat() > 100_000_000);
}

