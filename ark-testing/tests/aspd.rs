#[macro_use]
extern crate log;

use std::time::Duration;

use ark_testing::util::FutureExt;
use ark_testing::{AspdConfig, TestContext};
use ark_testing::daemon::aspd::Aspd;
use aspd_log::{NotSweeping, SweepComplete};
use aspd_rpc_client::Empty;

use bitcoin::amount::Amount;
use bitcoin::secp256k1::PublicKey;

#[tokio::test]
async fn check_aspd_version() {
	let output = Aspd::base_cmd()
		.arg("--version")
		.output()
		.await
		.expect("Failed to spawn process and capture output");

	let stdout = String::from_utf8(output.stdout).expect("Output is valid utf-8");
	assert!(stdout.starts_with("bark-aspd"))
}

#[tokio::test]
async fn round_started_log_can_be_captured() {
	let ctx = TestContext::new("aspd/capture_log").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;

	let mut log_stream = aspd.subscribe_log::<aspd_log::RoundStarted>().await;
	while let Some(l) = log_stream.recv().await {
		info!("Captured log: Round started at {}", l.round_id);
		break;
	}

	let l = aspd.wait_for_log::<aspd_log::RoundStarted>().await;
	info!("Captured log: Round started with round_num {}", l.round_id);

	// make sure we only capture the log once.
	assert!(aspd.wait_for_log::<aspd_log::RoundStarted>().try_fast().await.is_err());
}

#[tokio::test]
async fn fund_asp() {
	let ctx = TestContext::new("aspd/fund_aspd").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.prepare_funds().await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let mut admin_client = aspd.get_admin_client().await;

	// Query the wallet balance of the asp
	let response = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert_eq!(response.balance, 0);

	// Fund the aspd
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;
	tokio::time::sleep(Duration::from_secs(1)).await;

	// Confirm that the balance is updated
	let response = admin_client.wallet_status(Empty {}).await.expect("Get response").into_inner();
	assert!(response.balance > 0);
}

#[tokio::test]
async fn restart_key_stability() {
	//! Test to ensure that the asp key stays stable accross loads
	//! but gives new on-chain addresses.

	let ctx = TestContext::new("aspd/restart_key_stability").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.prepare_funds().await;
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

#[tokio::test]
async fn spend_expired() {
	//! Testing aspd spending expired rounds.

	let ctx = TestContext::new("aspd/spend_expired").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.prepare_funds().await;
	let mut aspd = ctx.aspd_with_cfg("aspd", AspdConfig {
		vtxo_expiry_delta: 64,
		sweep_threshold: Amount::from_sat(100_000),
		..ctx.aspd_default_cfg("aspd", &bitcoind, None).await
	}).await;
	let mut admin = aspd.get_admin_client().await;
	let bark = ctx.bark("bark".to_string(), &bitcoind, &aspd).await;

	bitcoind.fund_aspd(&aspd, Amount::from_sat(1_000_000)).await;
	bitcoind.fund_bark(&bark, Amount::from_sat(100_000)).await;
	bark.onboard(Amount::from_sat(75_000)).await;

	assert_eq!(1000000, admin.wallet_status(Empty {}).await.unwrap().into_inner().balance);

	// create a vtxo tree and do a round
	bark.refresh_all().await;
	bitcoind.generate(65).await;

	let mut not_sweeping = aspd.subscribe_log::<NotSweeping>().await;
	let mut sweeping = aspd.subscribe_log::<SweepComplete>().await;

	// Not sweeping yet, because available money under the threshold.
	admin.trigger_sweep(Empty{}).await.unwrap();
	assert_eq!(Amount::from_sat(75145), not_sweeping.recv().fast().await.unwrap().available_surplus);

	bark.refresh_all().await;
	bitcoind.generate(65).await;

	assert_eq!(844734, admin.wallet_status(Empty {}).await.unwrap().into_inner().balance);
	admin.trigger_sweep(Empty{}).await.unwrap();
	assert_eq!(Amount::from_sat(150290), sweeping.recv().fast().await.unwrap().surplus);

	bitcoind.generate(2).await;
	assert_eq!(992837, admin.wallet_status(Empty {}).await.unwrap().into_inner().balance);
}
