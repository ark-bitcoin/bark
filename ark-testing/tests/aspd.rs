extern crate tokio;

use std::time::Duration;

use tokio::process::Command;

use ark_testing::TestContext;
use aspd_rpc_client::Empty;

use bitcoin::amount::Amount;

#[tokio::test]
async fn check_aspd_version() {
	let output = Command::new("cargo")
		.arg("run")
		.arg("--package")
		.arg("bark-aspd")
		.arg("--")
		.arg("--version")
		.kill_on_drop(true)
		.output()
		.await
		.expect("Failed to spawn process and capture output");

	let stdout = String::from_utf8(output.stdout).expect("Output is valid utf-8");
	assert!(stdout.starts_with("bark-aspd"))
}

#[tokio::test]
async fn fund_asp() {
	let context = TestContext::generate();
	let bitcoind = context.bitcoind("bitcoind-1").await.expect("bitcoind-1 started");
	bitcoind.generate(106).await.unwrap();
	let aspd = context.aspd("aspd-1", &bitcoind).await.expect("arkd-1 started");
	let mut admin_client = aspd.get_admin_client().await.expect("Can conect to the admin-client");


	// Query the wallet balance of the asp
	let response  = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert_eq!(response.balance, 0);

	// Fund the aspd
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await.unwrap();
	tokio::time::sleep(Duration::from_secs(5)).await;

	// Confirm that the balance is updated
	let response  = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert!(response.balance > 0);
}
