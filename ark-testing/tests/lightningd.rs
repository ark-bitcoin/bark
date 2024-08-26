extern crate bark_cln;

use ark_testing::TestContext;
use bark_cln::grpc;

#[tokio::test]
async fn start_lightningd() {
	let context = TestContext::new("lightningd/start-lightningd");
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind started");

	// Start an instance of lightningd
	let lightningd_1 = context.lightningd("lightningd-1", &bitcoind).await.expect("Can start lightningd");
	let mut client = lightningd_1.grpc_client().await;
	let result = client.getinfo(grpc::GetinfoRequest{}).await.expect("Can make grpc-request");
	let info = result.into_inner();

	assert_eq!(info.alias.unwrap(), "lightningd-1");
}
