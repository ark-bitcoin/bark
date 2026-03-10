
use bitcoincore_rpc::RpcApi;

use ark_testing::TestContext;

#[tokio::test]
async fn start_bitcoind()  {
	let ctx = TestContext::new("bitcoind/start_bitcoind").await;
	let bitcoind = ctx.new_bitcoind("bitcoind-1").await;

	let client = bitcoind.sync_client();
	let info = client.get_blockchain_info().unwrap();
	assert_eq!(info.chain.to_string(), "regtest");
}

#[tokio::test]
async fn fund_bitcoind() {
	let ctx = TestContext::new("bitcoind/fund_bitcoind").await;

	// Check the balance
	let client = ctx.bitcoind().sync_client();
	let amount = client.get_balance(Some(6), None).unwrap();
	assert!(amount.to_sat() > 100_000_000);
}

