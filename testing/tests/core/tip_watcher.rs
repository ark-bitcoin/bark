use std::sync::Arc;
use std::time::Duration;

use bitcoincore_rpc::RpcApi;

use bark::tip_watcher::{TipSource, TipWatcher};
use bitcoin_ext::BlockRef;

use ark_testing::TestContext;
use ark_testing::util::FutureExt;

struct RpcTipSource {
	rpc: bitcoin_ext::rpc::BitcoinRpcClient,
}

impl TipSource for RpcTipSource {
	async fn tip_ref(&self) -> anyhow::Result<BlockRef> {
		let height = self.rpc.get_block_count()? as u32;
		let hash = self.rpc.get_block_hash(height as u64)?;
		Ok(BlockRef { height, hash })
	}
}

#[tokio::test]
async fn polling_watcher_detects_new_blocks() {
	let mut ctx = TestContext::new_minimal("tip_watcher/polling").await;
	ctx.init_central_bitcoind().await;

	let bitcoind = ctx.bitcoind.as_ref().expect("bitcoind initialized").clone();

	let source = Arc::new(RpcTipSource {
		rpc: bitcoind.sync_client(),
	});

	let watcher = TipWatcher::start_poll(source, Duration::from_millis(100))
		.await
		.expect("start polling watcher");

	let target_height = watcher.tip().height + 5;

	bitcoind.generate(5).await;

	let tip = watcher.wait_for_height(target_height)
		.try_wait_millis(5_000).await
		.expect("watcher should detect blocks within 5s")
		.expect("watcher should stay running");
	assert_eq!(tip.height, target_height);
}

#[tokio::test]
async fn zmq_watcher_detects_new_blocks() {
	let mut ctx = TestContext::new_minimal("tip_watcher/zmq").await;
	ctx.init_central_bitcoind().await;

	let bitcoind = ctx.bitcoind.as_ref().expect("bitcoind initialized").clone();

	let source = Arc::new(RpcTipSource {
		rpc: bitcoind.sync_client(),
	});
	let target_height = source.tip_ref().await.expect("fetch initial tip").height + 5;

	// A reconcile interval longer than any test run makes sure the ZMQ
	// notifications drive the updates, not the reconcile timer.
	let watcher = TipWatcher::start_zmq(source, &bitcoind.zmq_url(), Duration::from_secs(3600))
		.await
		.expect("start zmq watcher");

	bitcoind.generate(5).await;

	let tip = watcher.wait_for_height(target_height)
		.try_wait_millis(5_000).await
		.expect("watcher should detect blocks within 5s")
		.expect("watcher should stay running");
	assert_eq!(tip.height, target_height);
}
