#[macro_use]
extern crate log;

use std::sync::Arc;
use std::time::Duration;

use bitcoin::amount::Amount;
use bitcoin::secp256k1::PublicKey;
use tokio::sync::Mutex;

use ark_testing::util::FutureExt;
use ark_testing::{AspdConfig, TestContext};
use ark_testing::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use ark_testing::daemon::aspd::{self, Aspd};
use ark_testing::setup::{setup_asp_funded, setup_full, setup_simple};
use aspd_log::{NotSweeping, RoundFullySwept, RoundUserVtxoAlreadyRegistered, RoundUserVtxoUnknown, SweepBroadcast, TxIndexUpdateFinished};
use aspd_rpc as rpc;

lazy_static::lazy_static! {
	static ref RANDOM_PK: PublicKey = "02c7ef7d49b365974cd219f7036753e1544a3cdd2120eb7247dd8a94ef91cf1e49".parse().unwrap();
}

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
async fn bitcoind_auth_connection() {
	let ctx = TestContext::new("aspd/bitcoind_auth_connection").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.prepare_funds().await;

	let mut config = ctx.aspd_default_cfg("aspd", &bitcoind, None).await;
	config.bitcoind_auth = bitcoincore_rpc::Auth::UserPass(BITCOINRPC_TEST_USER.into(), BITCOINRPC_TEST_PASSWORD.into());

	let aspd = ctx.aspd_with_cfg("aspd", config).await;
	let mut admin = aspd.get_admin_client().await;
	bitcoind.fund_aspd(&aspd, Amount::from_sat(1_000_000)).await;

	let response = admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner();
	assert_eq!(response.balance, 1_000_000);
}

#[tokio::test]
async fn bitcoind_cookie_connection() {
	let ctx = TestContext::new("aspd/bitcoind_cookie_connection").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	bitcoind.prepare_funds().await;

	let mut config = ctx.aspd_default_cfg("aspd", &bitcoind, None).await;
	config.bitcoind_auth = bitcoincore_rpc::Auth::CookieFile(bitcoind.rpc_cookie());

	let aspd = ctx.aspd_with_cfg("aspd", config).await;
	let mut admin = aspd.get_admin_client().await;
	bitcoind.fund_aspd(&aspd, Amount::from_sat(1_000_000)).await;

	let response = admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner();
	assert_eq!(response.balance, 1_000_000);
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
	let response = admin_client.wallet_status(rpc::Empty {}).await.expect("Get response").into_inner();
	assert_eq!(response.balance, 0);

	// Fund the aspd
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;
	tokio::time::sleep(Duration::from_secs(1)).await;

	// Confirm that the balance is updated
	let response = admin_client.wallet_status(rpc::Empty {}).await.expect("Get response").into_inner();
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
		let res = client.get_ark_info(rpc::Empty {}).await.unwrap().into_inner();
		PublicKey::from_slice(&res.pubkey).unwrap()
	};
	let addr1 = {
		let mut admin_client = aspd.get_admin_client().await;
		let res = admin_client.wallet_status(rpc::Empty {}).await.unwrap().into_inner();
		res.address
	};

	// Fund the aspd's addr
	bitcoind.fund_addr(&addr1, Amount::from_int_btc(1)).await;
	bitcoind.generate(1).await;

	// Restart aspd.
	let _ = aspd.get_admin_client().await.stop(rpc::Empty {}).await;
	aspd.stop().await.unwrap();
	tokio::time::sleep(Duration::from_secs(1)).await;

	let aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let asp_key2 = {
		let mut client = aspd.get_public_client().await;
		let res = client.get_ark_info(rpc::Empty {}).await.unwrap().into_inner();
		PublicKey::from_slice(&res.pubkey).unwrap()
	};
	let addr2 = {
		let mut admin_client = aspd.get_admin_client().await;
		let res = admin_client.wallet_status(rpc::Empty {}).await.expect("Get response").into_inner();
		res.address
	};

	assert_eq!(asp_key1, asp_key2);
	assert_ne!(addr1, addr2);
}

#[tokio::test]
async fn sweep_vtxos() {
	//! Testing aspd spending expired rounds.

	let ctx = TestContext::new("aspd/sweep_vtxos").await;
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

	assert_eq!(1000000, admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner().balance);

	// create a vtxo tree and do a round
	bark.refresh_all().await;
	bitcoind.generate(65).await;

	// subscribe to a few log messages
	let mut log_not_sweeping = aspd.subscribe_log::<NotSweeping>().await;
	let mut log_sweeping = aspd.subscribe_log::<SweepBroadcast>().await;
	let mut log_round_done = aspd.subscribe_log::<RoundFullySwept>().await;

	// Not sweeping yet, because available money under the threshold.
	aspd.wait_for_log::<TxIndexUpdateFinished>().wait(6000).await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(Amount::from_sat(74980), log_not_sweeping.recv().wait(1500).await.unwrap().available_surplus);

	bark.refresh_all().await;
	bitcoind.generate(65).await;

	assert_eq!(844734, admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner().balance);
	aspd.wait_for_log::<TxIndexUpdateFinished>().wait(6000).await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(Amount::from_sat(149960), log_sweeping.recv().wait(1500).await.unwrap().surplus);

	// then after a while, we should sweep the connectors
	bitcoind.generate(65).await;
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(993333, admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner().balance);

	// and eventually the round should be finished
	loop {
		if log_round_done.try_recv().is_ok() {
			break;
		}
		bitcoind.generate(65).await;
		tokio::time::sleep(Duration::from_millis(200)).await;
	}

	assert_eq!(993333, admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner().balance);
}

#[tokio::test]
async fn restart_fresh_aspd() {
	let (_ctx, _bitcoind, mut aspd, _bark1, _bark2) = setup_simple("aspd/restart_fresh_aspd").await;
	aspd.stop().await.unwrap();
	aspd.start().await.unwrap();
}

#[tokio::test]
async fn restart_funded_aspd() {
	let (_ctx, _bitcoind, mut aspd, _bark1, _bark2) = setup_asp_funded("aspd/restart_funded_aspd").await;
	aspd.stop().await.unwrap();
	aspd.start().await.unwrap();
}

#[tokio::test]
async fn restart_aspd_with_payments() {
	let (_ctx, _bitcoind, mut aspd, _bark1, _bark2) = setup_full("aspd/restart_aspd_with_payments").await;
	aspd.stop().await.unwrap();
	aspd.start().await.unwrap();
}

#[tokio::test]
async fn double_spend_oor() {
	let ctx = TestContext::new("aspd/double_spend_oor").await;

	/// This proxy will always duplicate OOR requests and store the latest request in the mutex.
	#[derive(Clone)]
	struct Proxy(aspd::ArkClient, Arc<Mutex<Option<rpc::OorCosignRequest>>>);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }

		async fn request_oor_cosign(&mut self, req: rpc::OorCosignRequest) -> Result<rpc::OorCosignResponse, tonic::Status> {
			let (mut c1, mut c2) = (self.0.clone(), self.0.clone());
			let (res1, res2) = tokio::join!(
				c1.request_oor_cosign(req.clone()),
				c2.request_oor_cosign(req.clone()),
			);
			self.1.lock().await.replace(req);
			match (res1, res2) {
				(Ok(_), Ok(_)) => panic!("one of them should fail"),
				(Err(_), Err(_)) => panic!("one of them should work"),
				(Ok(r), Err(e)) | (Err(e), Ok(r)) => {
					assert!(e.to_string().contains("attempted to sign OOR for vtxo already in flux"));
					Ok(r.into_inner())
				},
			}
		}
	}

	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let last_req = Arc::new(Mutex::new(None));
	let proxy = Proxy(aspd.get_public_client().await, last_req.clone());
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	bitcoind.prepare_funds().await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	let bark = ctx.bark("bark".to_string(), &bitcoind, &proxy.address).await;
	bitcoind.fund_bark(&bark, Amount::from_sat(1_000_000)).await;
	bark.onboard(Amount::from_sat(800_000)).await;

	bark.send_oor(&*RANDOM_PK, Amount::from_sat(100_000)).await;

	// then after it's done, fire the request again, which should fail.
	let req = last_req.lock().await.take().unwrap();
	let err = aspd.get_public_client().await.request_oor_cosign(req).await.unwrap_err();
	assert!(err.to_string().contains("attempted to sign OOR for already spent vtxo"));
}

#[tokio::test]
async fn double_spend_round() {
	let ctx = TestContext::new("aspd/double_spend_round").await;

	/// This proxy will duplicate all round payment submission requests.
	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }

		async fn submit_payment(&mut self, req: rpc::SubmitPaymentRequest) -> Result<rpc::Empty, tonic::Status> {
			let (mut c1, mut c2) = (self.0.clone(), self.0.clone());
			let (res1, res2) = tokio::join!(
				c1.submit_payment(req.clone()),
				c2.submit_payment(req),
			);
			assert!(res1.is_ok());
			assert!(res2.is_ok());
			Ok(rpc::Empty{})
		}
	}

	let bitcoind = ctx.bitcoind("bitcoind").await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let proxy = aspd::proxy::AspdRpcProxyServer::start(Proxy(aspd.get_public_client().await)).await;

	bitcoind.prepare_funds().await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	let bark = ctx.bark("bark".to_string(), &bitcoind, &proxy.address).await;
	bitcoind.fund_bark(&bark, Amount::from_sat(1_000_000)).await;
	bark.onboard(Amount::from_sat(800_000)).await;

	let mut l = aspd.subscribe_log::<RoundUserVtxoAlreadyRegistered>().await;
	bark.refresh_all().await;
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn spend_unregistered_onboard() {
	let ctx = TestContext::new("aspd/spend_unregistered_onboard").await;

	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }

		async fn register_onboard_vtxos(&mut self, _req: rpc::OnboardVtxosRequest) -> Result<rpc::Empty, tonic::Status> {
			// drop the request
			Ok(rpc::Empty{})
		}
	}

	let bitcoind = ctx.bitcoind("bitcoind").await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;
	let proxy = aspd::proxy::AspdRpcProxyServer::start(Proxy(aspd.get_public_client().await)).await;

	bitcoind.prepare_funds().await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	let bark = ctx.bark("bark".to_string(), &bitcoind, &proxy.address).await;
	bitcoind.fund_bark(&bark, Amount::from_sat(1_000_000)).await;
	bark.onboard(Amount::from_sat(800_000)).await;

	let mut l = aspd.subscribe_log::<RoundUserVtxoUnknown>().await;
	tokio::spawn(async move {
		let _ = bark.refresh_all().await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}



