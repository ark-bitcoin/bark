
use bitcoincore_rpc::RpcApi;
use bitcoind_async_client::error::ClientError;
use bitcoind_async_client::traits::Reader;

use ark_testing::{Bitcoind, TestContext};

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


/// `submitblock` reports an accepted block as a null result. The async client
/// turns null into an error, so pushing blocks to a stalled secondary
/// bitcoind has to read the result with the sync client.
#[tokio::test]
async fn submitblock_null_result_needs_sync_client() {
	let ctx = TestContext::new("bitcoind/submitblock_null_result_needs_sync_client").await;

	// Not peered with the ctx bitcoind, so it only learns the blocks we
	// submit, and each one we submit is accepted.
	let node = Bitcoind::new("bitcoind-1".into(), ctx.bitcoind_default_cfg("bitcoind-1"), None);
	node.start().await.unwrap();
	let have = node.get_block_count().await;
	ctx.generate_blocks(2).await;

	let ctx_rpc = ctx.bitcoind().async_client();
	let mut block_hex = Vec::new();
	for height in [have + 1, have + 2] {
		let hash = ctx_rpc.get_block_hash(height).await.unwrap();
		let hex: String = ctx_rpc.call_raw("getblock", &[hash.to_string().into(), 0.into()])
			.await.unwrap();
		block_hex.push(hex);
	}

	// The async client fails on the null result, though the node took the block.
	let res = node.async_client()
		.call_raw::<serde_json::Value>("submitblock", &[block_hex[0].clone().into()]).await;
	assert!(matches!(res, Err(ClientError::Other(ref s)) if s == "Empty data received"),
		"expected the async client to fail on a null result, got {:?}", res,
	);
	assert_eq!(node.get_block_count().await, have + 1);

	// The sync client reads the same null result as `Value::Null`.
	let res: serde_json::Value = node.sync_client()
		.call("submitblock", &[block_hex[1].clone().into()]).unwrap();
	assert_eq!(res, serde_json::Value::Null);
	assert_eq!(node.get_block_count().await, have + 2);
}
