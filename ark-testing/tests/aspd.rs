#[macro_use]
extern crate log;

use std::sync::Arc;
use std::time::Duration;

use ark::VtxoId;
use bitcoin::amount::Amount;
use bitcoin::secp256k1::PublicKey;
use tokio::sync::Mutex;

use aspd_log::{
	NotSweeping, OnboardFullySwept, RoundFullySwept, RoundUserVtxoAlreadyRegistered,
	RoundUserVtxoUnknown, SweepBroadcast, SweeperStats, SweepingOutput, TxIndexUpdateFinished
};
use aspd_rpc::{self as rpc, ForfeitSignaturesRequest, VtxoSignaturesRequest};

use ark_testing::{Aspd, TestContext, btc, sat};
use ark_testing::constants::ONBOARD_CONFIRMATIONS;
use ark_testing::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use ark_testing::daemon::aspd;
use ark_testing::util::{FutureExt, ReceiverExt};

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

	let aspd = ctx.new_aspd_with_cfg("aspd", aspd::Config {
		bitcoind: aspd::config::Bitcoind {
			url: "".into(), //t set later by test framework
			cookie: None,
			rpc_user: Some(BITCOINRPC_TEST_USER.to_string()),
			rpc_pass: Some(BITCOINRPC_TEST_PASSWORD.to_string()),
		},
		..ctx.aspd_default_cfg("aspd", None).await
	}).await;
	ctx.fund_asp(&aspd, sat(1_000_000)).await;

	let mut admin = aspd.get_admin_client().await;
	let response = admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner();
	assert_eq!(response.balance, 1_000_000);
}

#[tokio::test]
async fn bitcoind_cookie_connection() {
	let ctx = TestContext::new("aspd/bitcoind_cookie_connection").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(0.01)).await;

	let mut admin = aspd.get_admin_client().await;
	let response = admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner();
	assert_eq!(response.balance, 1_000_000);
}

#[tokio::test]
async fn round_started_log_can_be_captured() {
	let ctx = TestContext::new("aspd/capture_log").await;
	let aspd = ctx.new_aspd("aspd", None).await;

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
	let aspd = ctx.new_aspd("aspd", None).await;
	let mut admin_client = aspd.get_admin_client().await;

	// Query the wallet balance of the asp
	let response = admin_client.wallet_status(rpc::Empty {}).await.expect("Get response").into_inner();
	assert_eq!(response.balance, 0);

	// Fund the aspd
	ctx.fund_asp(&aspd, btc(10)).await;
	ctx.bitcoind.generate(1).await;

	// Confirm that the balance is updated
	let response = admin_client.wallet_status(rpc::Empty {}).await.expect("Get response").into_inner();
	assert!(response.balance > 0);
}

#[tokio::test]
async fn restart_key_stability() {
	//! Test to ensure that the asp key stays stable accross loads
	//! but gives new on-chain addresses.

	let ctx = TestContext::new("aspd/restart_key_stability").await;
	let aspd = ctx.new_aspd("aspd", None).await;

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
	ctx.bitcoind.fund_addr(&addr1, btc(1)).await;
	ctx.bitcoind.generate(1).await;

	// Restart aspd.
	let _ = aspd.get_admin_client().await.stop(rpc::Empty {}).await;
	// bitcoind must be shut down gracefully otherwise it will not restart properly
	aspd.shutdown_bitcoind().await;
	aspd.stop().await.unwrap();

	let mut cfg = aspd.config().clone();
	cfg.bitcoind.url = String::new();
	let aspd = ctx.new_aspd_with_cfg("aspd", cfg).await;
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
async fn max_vtxo_amount() {
	let ctx = TestContext::new("aspd/max_vtxo_amount").await;
	let aspd = ctx.new_aspd_with_cfg("aspd", aspd::Config {
		max_vtxo_amount: Some(Amount::from_sat(500_000)),
		..ctx.aspd_default_cfg("aspd", None).await
	}).await;
	ctx.fund_asp(&aspd, Amount::from_int_btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, Amount::from_sat(1_500_000)).await;
	ctx.bitcoind.generate(1).await;

	// exceeds limit, should fail
	// TODO(stevenroose) once we have better error reporting, assert error content
	assert!(bark1.try_onboard(Amount::from_sat(600_000)).await.is_err());
	bark1.onboard(Amount::from_sat(500_000)).await;
	bark1.onboard(Amount::from_sat(500_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	// try send OOR exceeding limit
	assert!(bark1.try_send_oor(*RANDOM_PK, Amount::from_sat(600_000)).await.is_err());
	bark1.send_oor(*RANDOM_PK, Amount::from_sat(400_000)).await;

	// then try send in a round
	assert!(bark1
		.try_refresh_all().await
		.unwrap_err().to_string().contains("bad user input: output exceeds maximum vtxo amount of 0.00500000 BTC"));

	// but we can offboard the entire amount!
	let address = ctx.bitcoind.get_new_address();
	bark1.offboard_all(address.clone()).await;
	ctx.bitcoind.generate(1).await;
	let balance = ctx.bitcoind.get_received_by_address(&address);
	assert_eq!(balance, Amount::from_sat(597_135));
}

#[tokio::test]
async fn sweep_vtxos() {
	//! Testing aspd spending expired rounds.
	let ctx = TestContext::new("aspd/sweep_vtxos").await;

	// TODO: in this test, blocks are generated by aspd's bitcoin node.
	// Ideally they would be generated by ctx.bitcoind but it will
	// require some synchronization.

	let aspd = ctx.new_aspd_with_cfg("aspd", aspd::Config {
		round_interval: Duration::from_millis(500000000),
		vtxo_expiry_delta: 64,
		sweep_threshold: sat(100_000),
		..ctx.aspd_default_cfg("aspd", None).await
	}).await;
	ctx.fund_asp(&aspd, sat(1_000_000)).await;
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &aspd, sat(500_000)).await);
	let mut admin = aspd.get_admin_client().await;

	// subscribe to a few log messages
	let mut log_not_sweeping = aspd.subscribe_log::<NotSweeping>().await;
	let mut log_sweeping = aspd.subscribe_log::<SweepBroadcast>().await;
	let mut log_onboard_done = aspd.subscribe_log::<OnboardFullySwept>().await;
	let mut log_round_done = aspd.subscribe_log::<RoundFullySwept>().await;
	let mut log_sweeps = aspd.subscribe_log::<SweepingOutput>().await;

	// we onboard one vtxo and then a few blocks later another
	bark.onboard(sat(75_000)).await;
	ctx.bitcoind.generate(5).await;
	bark.onboard(sat(75_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	// before either expires not sweeping yet because nothing available
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(sat(0), log_not_sweeping.recv().fast().await.unwrap().available_surplus);

	// we can't make vtxos expire, so we have to refresh them
	ctx.bitcoind.generate(18).await;
	let b = bark.clone();
	tokio::spawn(async move {
		b.refresh_all().await;
	});
	aspd.trigger_round().await;
	ctx.bitcoind.generate(30).await;

	// now we expire the first one, still not sweeping because not enough surplus
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(sat(73790), log_not_sweeping.recv().wait(1500).await.unwrap().available_surplus);

	// now we expire the second, but the amount is not enough to sweep
	ctx.bitcoind.generate(5).await;
	aspd.wait_for_log::<TxIndexUpdateFinished>().wait(6000).await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(sat(147580), log_sweeping.recv().wait(1500).await.unwrap().surplus);
	let sweeps = log_sweeps.collect();
	assert_eq!(2, sweeps.len());
	assert_eq!(sweeps[0].sweep_type, "onboard");
	assert_eq!(sweeps[1].sweep_type, "onboard");

	// now we swept both onboard vtxos, let's sweep the round we created above
	ctx.bitcoind.generate(30).await;
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(sat(149980), log_sweeping.recv().wait(2500).await.unwrap().surplus);
	let sweeps = log_sweeps.collect();
	assert_eq!(1, sweeps.len());
	assert_eq!(sweeps[0].sweep_type, "vtxo");

	// then after a while, we should sweep the connectors,
	// but they don't make the surplus threshold, so we add another onboard
	bark.onboard(sat(101_000)).await;
	ctx.bitcoind.generate(70).await;
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();
	assert_eq!(sat(100285), log_sweeping.recv().wait(1500).await.unwrap().surplus);
	let sweeps = log_sweeps.collect();
	assert_eq!(2, sweeps.len());
	assert_eq!(sweeps[0].sweep_type, "connector");
	assert_eq!(sweeps[1].sweep_type, "onboard");

	ctx.bitcoind.generate(65).await;
	aspd.wait_for_log::<TxIndexUpdateFinished>().await;
	let mut log_stats = aspd.subscribe_log::<SweeperStats>().await;
	admin.trigger_sweep(rpc::Empty{}).await.unwrap();

	// and eventually the round should be finished
	log_onboard_done.recv().wait(1000).await.unwrap();
	info!("Onboard done signal received");
	log_round_done.recv().wait(1000).await.unwrap();
	info!("Round done signal received");
	let stats = log_stats.recv().fast().await.unwrap();
	assert_eq!(0, stats.nb_pending_utxos);
	assert_eq!(1241212, admin.wallet_status(rpc::Empty {}).await.unwrap().into_inner().balance);
}

#[tokio::test]
async fn restart_fresh_aspd() {
	let ctx = TestContext::new("aspd/restart_fresh_aspd").await;
	let mut aspd = ctx.new_aspd("aspd", None).await;
	aspd.stop().await.unwrap();
	aspd.start().await.unwrap();
}

#[tokio::test]
async fn restart_funded_aspd() {
	let ctx = TestContext::new("aspd/restart_funded_aspd").await;
	let mut aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	aspd.stop().await.unwrap();
	aspd.start().await.unwrap();
}

#[tokio::test]
async fn restart_aspd_with_payments() {
	let ctx = TestContext::new("aspd/restart_aspd_with_payments").await;
	let mut aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;
	ctx.fund_bark(&bark1, sat(1_000_000)).await;
	ctx.fund_bark(&bark2, sat(1_000_000)).await;

	bark2.onboard(sat(800_000)).await;
	bark1.onboard(sat(200_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;
	bark1.send_oor(&bark2.vtxo_pubkey().await, sat(350_000)).await;
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

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let last_req = Arc::new(Mutex::new(None));
	let proxy = Proxy(aspd.get_public_client().await, last_req.clone());
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.onboard(sat(800_000)).await;

	bark.send_oor(&*RANDOM_PK, sat(100_000)).await;

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
			let vtxoid = VtxoId::from_slice(&req.input_vtxos[0]).unwrap();

			let (mut c1, mut c2) = (self.0.clone(), self.0.clone());
			let res1 = c1.submit_payment(req.clone()).await;
			let res2 = c2.submit_payment(req).await;

			assert!(res1.is_ok());
			assert!(res2.unwrap_err().message().contains(&format!("vtxo {} already registered", vtxoid)));
			Ok(rpc::Empty{})
		}
	}

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let proxy = aspd::proxy::AspdRpcProxyServer::start(Proxy(aspd.get_public_client().await)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.onboard(sat(800_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	let mut l = aspd.subscribe_log::<RoundUserVtxoAlreadyRegistered>().await;
	bark.refresh_all().await;
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn test_participate_round_wrong_step() {
	let ctx = TestContext::new("aspd/test_participate_round_wrong_step").await;

	/// This proxy will send a `provide_vtxo_signatures` req instead of `submit_payment` one
	#[derive(Clone)]
	struct ProxyA(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for ProxyA {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }
		async fn submit_payment(&mut self, _req: rpc::SubmitPaymentRequest) -> Result<rpc::Empty, tonic::Status> {
			self.0.provide_vtxo_signatures(VtxoSignaturesRequest {
				pubkey: RANDOM_PK.serialize().to_vec(), signatures: vec![]
			}).await?;
			Ok(rpc::Empty{})
		}
	}

	let aspd = ctx.new_aspd_with_funds("aspd", None, Amount::from_int_btc(10)).await;

	let proxy = aspd::proxy::AspdRpcProxyServer::start(ProxyA(aspd.get_public_client().await)).await;
	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, Amount::from_sat(1_000_000)).await;
	bark.onboard(Amount::from_sat(800_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	let res = bark.try_refresh_all().await;
	assert!(res.unwrap_err().to_string().contains("unexpected message. current step is payment registration"));

	/// This proxy will send a `provide_forfeit_signatures` req instead of `provide_vtxo_signatures` one
	#[derive(Clone)]
	struct ProxyB(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for ProxyB {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }
		async fn provide_vtxo_signatures(&mut self, _req: rpc::VtxoSignaturesRequest) -> Result<rpc::Empty, tonic::Status> {
			self.0.provide_forfeit_signatures(ForfeitSignaturesRequest { signatures: vec![] }).await?;
			Ok(rpc::Empty{})
		}
	}

	let proxy = aspd::proxy::AspdRpcProxyServer::start(ProxyB(aspd.get_public_client().await)).await;
	let bark2 = ctx.new_bark_with_funds("bark2".to_string(), &proxy.address, Amount::from_sat(1_000_000)).await;
	bark2.onboard(Amount::from_sat(800_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	let res = bark2.try_refresh_all().await;
	assert!(res.unwrap_err().to_string().contains("unexpected message. current step is vtxo signatures submission"));

	/// This proxy will send a `submit_payment` req instead of `provide_forfeit_signatures` one
	#[derive(Clone)]
	struct ProxyC(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for ProxyC {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }
		async fn provide_forfeit_signatures(&mut self, _req: rpc::ForfeitSignaturesRequest) -> Result<rpc::Empty, tonic::Status> {
			self.0.submit_payment(rpc::SubmitPaymentRequest {
				input_vtxos: vec![], vtxo_requests: vec![], offboard_requests: vec![]
			}).await?;
			Ok(rpc::Empty{})
		}
	}

	let proxy = aspd::proxy::AspdRpcProxyServer::start(ProxyC(aspd.get_public_client().await)).await;
	let bark3 = ctx.new_bark_with_funds("bark3".to_string(), &proxy.address, Amount::from_sat(1_000_000)).await;
	bark3.onboard(Amount::from_sat(800_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	let res = bark3.try_refresh_all().await;
	assert!(res.unwrap_err().to_string().contains("unexpected message. current step is forfeit signatures submission"));
}

#[tokio::test]
async fn spend_unregistered_onboard() {
	let ctx = TestContext::new("aspd/spend_unregistered_onboard").await;

	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);
	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd::ArkClient { self.0.clone() }

		async fn register_onboard_vtxo(&mut self, _req: rpc::OnboardVtxoRequest) -> Result<rpc::Empty, tonic::Status> {
			// drop the request
			Ok(rpc::Empty{})
		}
	}

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let proxy = aspd::proxy::AspdRpcProxyServer::start(Proxy(aspd.get_public_client().await)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.onboard(sat(800_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	let mut l = aspd.subscribe_log::<RoundUserVtxoUnknown>().await;
	tokio::spawn(async move {
		let _ = bark.refresh_all().await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}



