#[macro_use]
extern crate log;
extern crate bark_cln;

use ark_testing::TestContext;
use bark_cln::grpc;

#[tokio::test]
async fn start_lightningd() {
	let context = TestContext::new("lightningd/start-lightningd");
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind started");

	// Start an instance of lightningd
	let lightningd_1 = context.lightningd("lightningd-1", &bitcoind).await.expect("Can start lightningd");
	let mut client = lightningd_1.grpc_client().await.expect("Can connect to grpc-client");
	let result = client.getinfo(grpc::GetinfoRequest{}).await.expect("Can make grpc-request");
	let info = result.into_inner();

	assert_eq!(info.alias.unwrap(), "lightningd-1");
}

#[tokio::test]
async fn pay_lightningd() {
	let context = TestContext::new("lightningd/pay-lightningd");
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind started");

	// Start an instance of lightningd
	let (mut lightningd_1, mut lightningd_2) = tokio::try_join!(
		context.lightningd("lightningd-1", &bitcoind),
		context.lightningd("lightningd-2", &bitcoind)
	).expect("Can start lightningd");


	// Connect both peers and verify the connection succeeded
	info!("Connect `{}` to `{}`", lightningd_1.name(), lightningd_2.name());
	lightningd_1.connect(&lightningd_2).await.expect("Lightning nodes can connect");
	let mut client = lightningd_1.grpc_client().await.unwrap();
	let peers = client.list_peers(grpc::ListpeersRequest{
		id: Some(lightningd_2.id().await.unwrap()),
		level: None
	}).await.unwrap().into_inner().peers;

	assert_eq!(peers.len(), 1);


}
