
use std::time::Duration;

use ark_testing::TestContext;
use ark_testing::daemon::aspd::Aspd;
use aspd_rpc_client::Empty;

use bitcoin::amount::Amount;
use bitcoin::secp256k1::PublicKey;

#[test]
fn check_aspd_version() {
	let output = Aspd::base_cmd()
		.arg("--version")
		.output()
		.expect("Failed to spawn process and capture output");

	let stdout = String::from_utf8(output.stdout).expect("Output is valid utf-8");
	assert!(stdout.starts_with("bark-aspd"))
}

#[tokio::test]
async fn fund_asp() {
	let ctx = TestContext::new("aspd/fund_aspd").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.generate(106).await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let mut admin_client = aspd.get_admin_client().await;

	// Query the wallet balance of the asp
	let response  = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert_eq!(response.balance, 0);

	// Fund the aspd
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;
	tokio::time::sleep(Duration::from_secs(1)).await;

	// Confirm that the balance is updated
	let response  = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert!(response.balance > 0);
}

#[tokio::test]
async fn restart_key_stability() {
	//! Test to ensure that the asp key stays stable accross loads
	//! but gives new on-chain addresses.

	let ctx = TestContext::new("aspd/key_stability").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.generate(106).await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;

	let asp_key1 = {
		let mut client = aspd.get_public_client().await;
		let res = client.get_ark_info(Empty {}).await.unwrap().into_inner();
		PublicKey::from_slice(&res.pubkey).unwrap()
	};
	let addr1 = {
		let mut admin_client = aspd.get_admin_client().await;
		let res = admin_client.wallet_status(Empty {}).await.unwrap().into_inner();
		res.address
	};

	// Fund the aspd's addr
	bitcoind.fund_addr(&addr1, Amount::from_int_btc(1)).await;
	bitcoind.generate(1).await;

	// Restart aspd.
	let _ = aspd.get_admin_client().await.stop(Empty {}).await;
	aspd.stop().await.unwrap();
	tokio::time::sleep(Duration::from_secs(1)).await;

	let aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let asp_key2 = {
		let mut client = aspd.get_public_client().await;
		let res = client.get_ark_info(Empty {}).await.unwrap().into_inner();
		PublicKey::from_slice(&res.pubkey).unwrap()
	};
	let addr2 = {
		let mut admin_client = aspd.get_admin_client().await;
		let res = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
		res.address
	};

	assert_eq!(asp_key1, asp_key2);
	assert_ne!(addr1, addr2);
}
