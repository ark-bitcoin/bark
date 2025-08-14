
use std::iter;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use bark::Wallet;
use bitcoin::hex::FromHex;
use bitcoin::{Amount, Network};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{ScriptBuf, WPubkeyHash};
use bitcoin_ext::{DEEPLY_CONFIRMED, P2TR_DUST, P2TR_DUST_SAT};
use bitcoin_ext::rpc::bitcoin_core::BitcoinRpcExt;
use futures::future::join_all;
use futures::{Stream, StreamExt, TryStreamExt};
use log::{error, info, trace};
use tokio::sync::{mpsc, Mutex};

use ark::{musig, OffboardRequest, ProtocolEncoding, SECP, SignedVtxoRequest, VtxoId, VtxoPolicy, VtxoRequest};
use ark::rounds::VtxoOwnershipChallenge;
use server_log::{
	NotSweeping, BoardFullySwept, RoundFinished, RoundFullySwept, RoundUserVtxoAlreadyRegistered,
	RoundUserVtxoUnknown, SweepBroadcast, SweeperStats, SweepingOutput, TxIndexUpdateFinished,
	UnconfirmedBoardSpendAttempt, ForfeitedExitInMempool, ForfeitedExitConfirmed,
	ForfeitBroadcasted, RoundError
};

use server::secret::Secret;
use server_rpc::protos;
use bark_json::exit::ExitState;

use ark_testing::{Captaind, TestContext, btc, sat, Bark};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use ark_testing::daemon::captaind;
use ark_testing::daemon::captaind::proxy::ArkRpcProxyServer;
use ark_testing::util::{FutureExt, ReceiverExt};

lazy_static::lazy_static! {
	static ref RANDOM_PK: PublicKey = "02c7ef7d49b365974cd219f7036753e1544a3cdd2120eb7247dd8a94ef91cf1e49".parse().unwrap();
}

async fn progress_exit_to_broadcast(bark: &Bark) {
	let progress_result = bark.progress_exit().await;
	assert_eq!(false, progress_result.done);
	assert_eq!(None, progress_result.spendable_height);
	for exit in progress_result.exits {
		assert_eq!(exit.error, None);
		if matches!(exit.state, ExitState::Processing(..)) {
			return;
		}
	}
	panic!("no confirming exit found");
}

#[tokio::test]
async fn check_captaind_version() {
	let output = Captaind::base_cmd().arg("--version").output().await
		.expect("Failed to spawn process and capture output");

	let stdout = String::from_utf8(output.stdout).expect("Output is valid utf-8");
	let mut parts = stdout.split(' ');
	assert_eq!(parts.next().unwrap(), "captaind");
	let version_str = parts.next().unwrap().trim();
	semver::Version::parse(&version_str).unwrap();
}

#[tokio::test]
async fn bitcoind_auth_connection() {
	let ctx = TestContext::new("server/bitcoind_auth_connection").await;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.bitcoind.url = "".into(); //t set later by test framework
		cfg.bitcoind.cookie = None;
		cfg.bitcoind.rpc_user = Some(BITCOINRPC_TEST_USER.to_string());
		cfg.bitcoind.rpc_pass = Some(Secret::new(BITCOINRPC_TEST_PASSWORD.to_string()));
	}).await;
	ctx.fund_captaind(&srv, sat(1_000_000)).await;

	assert_eq!(srv.wallet_status().await.total().to_sat(), 1_000_000);
}

#[tokio::test]
async fn bitcoind_cookie_connection() {
	let ctx = TestContext::new("server/bitcoind_cookie_connection").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(0.01)).await;
	assert_eq!(srv.wallet_status().await.total().to_sat(), 1_000_000);
}

#[tokio::test]
async fn round_started_log_can_be_captured() {
	let ctx = TestContext::new("server/capture_log").await;
	let srv = ctx.new_captaind("server", None).await;

	let mut log_stream = srv.subscribe_log::<server_log::RoundStarted>().await;
	while let Some(l) = log_stream.recv().await {
		info!("Captured log: Round started at {}", l.round_seq);
		break;
	}

	let l = srv.wait_for_log::<server_log::RoundStarted>().await;
	info!("Captured log: Round started with round_num {}", l.round_seq);

	// make sure we only capture the log once.
	assert!(srv.wait_for_log::<server_log::RoundStarted>().try_fast().await.is_err());
}

#[tokio::test]
async fn fund_captaind() {
	let ctx = TestContext::new("server/fund_captaind").await;
	let srv = ctx.new_captaind("server", None).await;

	// Query the wallet balance of the server
	assert_eq!(srv.wallet_status().await.total().to_sat(), 0);

	// Fund the server
	ctx.fund_captaind(&srv, btc(10)).await;
	ctx.generate_blocks(1).await;

	// Confirm that the balance is updated
	assert!(srv.wallet_status().await.total().to_sat() > 0);
}

#[tokio::test]
async fn cant_spend_untrusted() {
	let ctx = TestContext::new("server/cant_spend_untrusted").await;

	const NEED_CONFS: u32 = 2;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_tx_untrusted_input_confirmations = NEED_CONFS as usize;
	}).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(srv.wallet_status().await.total().to_sat(), 0);

	// fund server without confirming
	let addr = srv.get_rounds_funding_address().await;
	ctx.bitcoind().fund_addr(addr, btc(10)).await;
	assert_eq!(srv.wallet_status().await.total().to_sat(), 0);

	let mut log_round_err = srv.subscribe_log::<RoundError>().await;

	// Set a time-out on the bark command for the refresh --all
	// The command is expected to time-out
	bark.timeout = Some(Duration::from_millis(10_000));
	let mut bark = Arc::new(bark);

	// we will launch bark to try refresh, it will produce an error log at first,
	// then we'll confirm the server's money and then bark should succeed by retrying
	let bark_clone = bark.clone();
	let attempt_handle = tokio::spawn(async move {
		bark_clone.try_refresh_all().await.unwrap_err();
	});

	// this will at first produce an error
	let err = log_round_err.recv().wait(5_000).await.unwrap().error;
	assert!(err.contains("Insufficient funds"), "err: {err}");

	attempt_handle.await.unwrap();

	// then confirm the money and it should work
	ctx.generate_blocks(NEED_CONFS).await;
	tokio::time::sleep(Duration::from_millis(3000)).await;

	log_round_err.clear();
	Arc::get_mut(&mut bark).unwrap().timeout = None;
	if let Err(err) = bark.try_refresh_all().await {
		let mut round_errs = String::new();
		while let Ok(e) = log_round_err.try_recv() {
			write!(&mut round_errs, "{:?}\n\n", e).unwrap();
			error!("round error: {:?}", e.error);
		}
		panic!("first refresh failed, err: {err:?}, round errs: {round_errs:?}");
	}

	// and the unconfirmed change should be able to be used for a second round
	tokio::time::sleep(Duration::from_millis(2000)).await;
	assert!(log_round_err.try_recv().is_err());
	if let Err(err) = bark.try_refresh_all().await {
		let mut round_errs = String::new();
		while let Ok(e) = log_round_err.try_recv() {
			write!(&mut round_errs, "{:?}\n\n", e).unwrap();
			error!("round error: {:?}", e.error);
		}
		panic!("second refresh failed, err: {err:?}, round errs: {round_errs:?}");
	}
	// should not have produced errors
	assert!(log_round_err.try_recv().is_err());
}

#[tokio::test]
async fn restart_key_stability() {
	//! Test to ensure that the server key stays stable accross loads
	//! but gives new on-chain addresses.

	let ctx = TestContext::new("server/restart_key_stability").await;
	let srv = ctx.new_captaind("server", None).await;

	let server_key1 = srv.ark_info().await.server_pubkey;
	let addr1 = srv.wallet_status().await.rounds.address.require_network(Network::Regtest).unwrap();

	// Fund the server's addr
	ctx.bitcoind().fund_addr(&addr1, btc(1)).await;
	ctx.generate_blocks(1).await;

	// Restart server.
	// bitcoind must be shut down gracefully otherwise it will not restart properly
	srv.shutdown_bitcoind().await;
	srv.stop().await.unwrap();

	let mut new_cfg = srv.config().clone();
	new_cfg.bitcoind.url = String::new();
	let srv = ctx.new_captaind_with_cfg("server", None, move |cfg| {
		*cfg = new_cfg;
	}).await;
	let server_key2 = srv.ark_info().await.server_pubkey;
	let addr2 = srv.wallet_status().await.rounds.address.require_network(Network::Regtest).unwrap();

	assert_eq!(server_key1, server_key2);
	assert_ne!(addr1, addr2);
}

#[tokio::test]
async fn max_vtxo_amount() {
	let ctx = TestContext::new("server/max_vtxo_amount").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.max_vtxo_amount = Some(Amount::from_sat(500_000));
	}).await;
	ctx.fund_captaind(&srv, Amount::from_int_btc(10)).await;
	let mut bark1 = ctx.new_bark_with_funds("bark1", &srv, Amount::from_sat(1_500_000)).await;

	let cfg_max_amount = bark1.ark_info().await.max_vtxo_amount.unwrap();

	// exceeds limit, should fail
	let err = bark1.try_board(Amount::from_sat(600_000)).await.unwrap_err();
	assert!(err.to_string().contains(
		&format!("bad user input: board amount exceeds limit of {}", cfg_max_amount)
	), "err: {err}");

	bark1.board(Amount::from_sat(500_000)).await;
	bark1.board(Amount::from_sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// then try send in a round
	bark1.timeout = Some(Duration::from_millis(3_000));
	let err = bark1.try_refresh_all().await.unwrap_err();
	assert!(err.to_string().contains(
		&format!("output exceeds maximum vtxo amount of {}", cfg_max_amount),
	), "err: {err}");

	// but we can offboard the entire amount!
	bark1.timeout = None;
	let address = ctx.bitcoind().get_new_address();
	bark1.offboard_all(address.clone()).await;
	ctx.generate_blocks(1).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, Amount::from_sat(999_100));
}

#[tokio::test]
async fn sweep_vtxos() {
	//! Testing server spending expired rounds.
	let ctx = TestContext::new("server/sweep_vtxos").await;

	// TODO: in this test, blocks are generated by the server's bitcoin node.
	// Ideally they would be generated by ctx.bitcoind but it will
	// require some synchronization.

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_millis(500000000);
		cfg.vtxo_lifetime = 64;
		cfg.vtxo_sweeper.sweep_threshold = sat(100_000);
	}).await;
	ctx.fund_captaind(&srv, sat(1_000_000)).await;
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, sat(500_000)).await);

	// subscribe to a few log messages
	let mut log_not_sweeping = srv.subscribe_log::<NotSweeping>().await;
	let mut log_sweeping = srv.subscribe_log::<SweepBroadcast>().await;
	let mut log_board_done = srv.subscribe_log::<BoardFullySwept>().await;
	let mut log_round_done = srv.subscribe_log::<RoundFullySwept>().await;
	let mut log_sweeps = srv.subscribe_log::<SweepingOutput>().await;

	// we board one vtxo and then a few blocks later another
	bark.board(sat(75_000)).await;
	ctx.generate_blocks(5).await;
	bark.board(sat(75_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// before either expires not sweeping yet because nothing available
	srv.wait_for_log::<TxIndexUpdateFinished>().await;
	srv.trigger_sweep().await;
	assert_eq!(sat(0), log_not_sweeping.recv().wait(15_000).await.unwrap().available_surplus);

	// we can't make vtxos expire, so we have to refresh them
	ctx.generate_blocks(18).await;
	let b = bark.clone();
	tokio::spawn(async move {
		b.refresh_all().await;
	});
	srv.trigger_round().await;

	let _ = srv.wait_for_log::<RoundFinished>().try_wait(5_000).await;
	ctx.generate_blocks(30).await;

	// now we expire the first one, still not sweeping because not enough surplus
	srv.wait_for_log::<TxIndexUpdateFinished>().wait(6_000).await;
	srv.trigger_sweep().await;
	assert_eq!(sat(73_760), log_not_sweeping.recv().wait(15_000).await.unwrap().available_surplus);

	// now we expire the second, but the amount is not enough to sweep
	ctx.generate_blocks(5).await;
	srv.wait_for_log::<TxIndexUpdateFinished>().wait(6_000).await;
	srv.trigger_sweep().await;
	let surplus = log_sweeping.recv().wait(15_000).await.unwrap().surplus;
	let sweeps = log_sweeps.collect();
	assert_eq!(2, sweeps.len(), "sweeps: {:?}", sweeps);
	assert_eq!(sweeps[0].sweep_type, "board");
	assert_eq!(sweeps[1].sweep_type, "board");
	assert_eq!(sat(147_520), surplus);

	// now we swept both board vtxos, let's sweep the round we created above
	ctx.generate_blocks(30).await;
	srv.wait_for_log::<TxIndexUpdateFinished>().await;
	srv.trigger_sweep().await;
	let surplus = log_sweeping.recv().wait(15_000).await.unwrap().surplus;
	let sweeps = log_sweeps.collect();
	assert_eq!(1, sweeps.len(), "sweeps: {:?}", sweeps);
	assert_eq!(sweeps[0].sweep_type, "vtxo");
	assert_eq!(sat(149_650), surplus);

	// then after a while, we should sweep the connectors,
	// but they don't make the surplus threshold, so we add another board
	bark.board(sat(102_000)).await;
	ctx.generate_blocks(DEEPLY_CONFIRMED).await;

	srv.wait_for_log::<TxIndexUpdateFinished>().await;
	srv.trigger_sweep().await;
	let surplus = log_sweeping.recv().wait(15_000).await.unwrap().surplus;
	let sweeps = log_sweeps.collect();
	assert_eq!(2, sweeps.len(), "sweeps: {:?}", sweeps);
	assert_eq!(sweeps[0].sweep_type, "connector");
	assert_eq!(sweeps[1].sweep_type, "board");
	assert_eq!(sat(101_255), surplus);

	ctx.generate_blocks(DEEPLY_CONFIRMED).await;
	srv.wait_for_log::<TxIndexUpdateFinished>().await;
	let mut log_stats = srv.subscribe_log::<SweeperStats>().await;
	srv.trigger_sweep().await;

	// and eventually the round should be finished
	log_board_done.recv().wait(10_000).await.unwrap();
	info!("board done signal received");
	log_round_done.recv().wait(10_000).await.unwrap();
	info!("Round done signal received");
	let stats = log_stats.recv().fast().await.unwrap();
	assert_eq!(0, stats.nb_pending_utxos);
	assert_eq!(1_242_122, srv.wallet_status().await.total().to_sat());
}

#[tokio::test]
async fn restart_fresh_server() {
	let ctx = TestContext::new("server/restart_fresh_server").await;
	let mut srv = ctx.new_captaind("server", None).await;
	srv.stop().await.unwrap();
	srv.start().await.unwrap();
}

#[tokio::test]
async fn restart_funded_server() {
	let ctx = TestContext::new("server/restart_funded_server").await;
	let mut srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	srv.stop().await.unwrap();
	srv.start().await.unwrap();
}

#[tokio::test]
async fn restart_server_with_payments() {
	let ctx = TestContext::new("server/restart_server_with_payments").await;
	let mut srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;
	ctx.fund_bark(&bark1, sat(1_000_000)).await;
	ctx.fund_bark(&bark2, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	bark2.send_oor(&bark1.address().await, sat(330_000)).await;
	bark1.refresh_all().await;
	bark1.send_oor(&bark2.address().await, sat(350_000)).await;
	srv.stop().await.unwrap();
	srv.start().await.unwrap();
}

#[tokio::test]
async fn full_round() {
	let ctx = TestContext::new("server/full_round").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_millis(2_000);
		cfg.round_submit_time = Duration::from_millis(10_000);
		cfg.round_sign_time = Duration::from_millis(10_000);
		cfg.nb_round_nonces = 2;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// based on nb_round_nonces
	const MAX_OUTPUTS: usize = 16;
	const NB_BARKS: usize = 5;
	const VTXOS_PER_BARK: usize = 4;
	assert!(NB_BARKS * VTXOS_PER_BARK > MAX_OUTPUTS);

	// Since we can have 16 inputs, we will create 5 barks with 4 vtxos each.

	let barks = join_all((1..=NB_BARKS).map(|i| {
		let name = format!("bark{}", i);
		ctx.new_bark_with_funds(name, &srv, sat(40_000))
	})).await;
	ctx.generate_blocks(1).await;

	// have each board 4 times
	for _ in 0..VTXOS_PER_BARK {
		futures::future::join_all(barks.iter().map(|bark| async {
			bark.board(sat(1_000)).await;
		})).await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	}

	let (tx, mut rx) = mpsc::unbounded_channel();

	/// This proxy will keep track of how many times `submit payment` has been called.
	/// Once it reaches MAX_OUTPUTS, it asserts the next one fails.
	/// Once that happened succesfully, it fullfils the result channel.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient, Arc<Mutex<usize>>, Arc<mpsc::UnboundedSender<tonic::Status>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn submit_payment(&mut self, req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
			let mut lock = self.1.lock().await;
			let res = self.upstream().submit_payment(req).await;
			// the last bark should fail being registered
			let ret = if *lock == NB_BARKS-1 {
				let err = res.expect_err("must error at max");
				trace!("proxy: NOK: {}", err);
				self.2.send(err.clone()).unwrap();
				Err(err)
			} else {
				trace!("proxy: OK (nb={})", *lock);
				res.map(|r| r.into_inner())
			};
			*lock += 1;
			ret
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await, Arc::new(Mutex::new(0)), Arc::new(tx));
	let proxy = captaind::proxy::ArkRpcProxyServer::start(proxy).await;
	futures::future::join_all(barks.iter().map(|bark| bark.set_ark_url(&proxy))).await;

	//TODO(stevenroose) need to find a way to ensure that all these happen in the same round
	tokio::spawn(async move {
		futures::future::join_all(barks.iter().map(|bark| async {
			// ignoring error as last one will fail
			let _ = bark.refresh_all().await;
		})).await;
	});

	// then we wait for the error to happen
	let err = rx.recv().wait(30_000).await.unwrap();
	assert!(err.to_string().contains("Message arrived late or round was full"), "err: {err}");
}

#[tokio::test]
async fn double_spend_oor() {
	let ctx = TestContext::new("server/double_spend_oor").await;

	/// This proxy will always duplicate OOR requests and store the latest request in the mutex.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient, Arc<Mutex<Option<protos::ArkoorPackageCosignRequest>>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn request_arkoor_package_cosign(&mut self, req: protos::ArkoorPackageCosignRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			let (mut c1, mut c2) = (self.0.clone(), self.0.clone());
			let (res1, res2) = tokio::join!(
				c1.request_arkoor_package_cosign(req.clone()),
				c2.request_arkoor_package_cosign(req.clone()),
			);
			self.1.lock().await.replace(req);
			match (res1, res2) {
				(Ok(_), Ok(_)) => panic!("one of them should fail"),
				(Err(_), Err(_)) => panic!("one of them should work"),
				(Ok(r), Err(e)) | (Err(e), Ok(r)) => {
					assert!(
						e.to_string().contains("attempted to sign arkoor tx for vtxo already in flux")
							|| e.to_string().contains("attempted to sign arkoor tx for already spent vtxo"),
						"err: {e}",
					);
					Ok(r.into_inner())
				},
			}
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let last_req = Arc::new(Mutex::new(None));
	let proxy = Proxy(srv.get_public_rpc().await, last_req.clone());
	let proxy = ArkRpcProxyServer::start(proxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr = ark::Address::builder()
		.testnet(true)
		.server_pubkey(srv.ark_info().await.server_pubkey)
		.pubkey_policy(*RANDOM_PK)
		.into_address().unwrap();
	bark.send_oor(addr, sat(100_000)).await;

	// then after it's done, fire the request again, which should fail.
	let req = last_req.lock().await.take().unwrap();
	let err = srv.get_public_rpc().await.request_arkoor_package_cosign(req).await.unwrap_err();
	assert!(err.to_string().contains(
		"bad user input: attempted to sign arkoor tx for already spent vtxo",
	), "err: {err}");
}

#[tokio::test]
async fn double_spend_round() {
	let ctx = TestContext::new("server/double_spend_round").await;

	/// This proxy will duplicate all round payment submission requests.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn submit_payment(&mut self, mut req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
			let vtxoid = VtxoId::from_slice(&req.input_vtxos[0].vtxo_id).unwrap();

			let (mut c1, mut c2) = (self.0.clone(), self.0.clone());
			let res1 = c1.submit_payment(req.clone()).await;
			// avoid duplicate cosign key error
			req.vtxo_requests[0].cosign_pubkey = Vec::<u8>::from_hex(
				"028d887bb64dfea78040e7f94284245ea4468c003105d207f9b82cf8d6a66a9064",
			).unwrap();
			let res2 = c2.submit_payment(req).await;

			assert!(res1.is_ok());
			let err = res2.unwrap_err();
			assert!(err.message().contains(
				&format!("vtxo {} already registered", vtxoid),
			), "err: {err}");
			Ok(protos::Empty{})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = ArkRpcProxyServer::start(Proxy(srv.get_public_rpc().await)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let mut l = srv.subscribe_log::<RoundUserVtxoAlreadyRegistered>().await;
	bark.refresh_all().await;
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn test_participate_round_wrong_step() {
	let ctx = TestContext::new("server/test_participate_round_wrong_step").await;
	let srv = ctx.new_captaind_with_funds("server", None, Amount::from_int_btc(10)).await;
	let mut bark = ctx.new_bark_with_funds("bark".to_string(), &srv, Amount::from_sat(1_000_000)).await;
	bark.board(Amount::from_sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	/// This proxy will send a `provide_vtxo_signatures` req instead of `submit_payment` one
	#[derive(Clone)]
	struct ProxyA(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyA {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }
		async fn submit_payment(&mut self, _req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
			self.0.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
				pubkey: RANDOM_PK.serialize().to_vec(), signatures: vec![]
			}).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = ArkRpcProxyServer::start(ProxyA(srv.get_public_rpc().await)).await;
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all().await.expect_err("refresh should fail");
	assert!(err.to_string().contains("current step is payment registration"), "err: {err}");

	/// This proxy will send a `provide_forfeit_signatures` req instead of `provide_vtxo_signatures` one
	#[derive(Clone)]
	struct ProxyB(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyB {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }
		async fn provide_vtxo_signatures(&mut self, _req: protos::VtxoSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
			self.0.provide_forfeit_signatures(protos::ForfeitSignaturesRequest { signatures: vec![] }).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = ArkRpcProxyServer::start(ProxyB(srv.get_public_rpc().await)).await;
	bark.timeout = Some(Duration::from_millis(10_000));
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all().await.expect_err("refresh should fail");
	assert!(err.to_string().contains("current step is vtxo signatures submission"), "err: {err}");

	/// This proxy will send a `submit_payment` req instead of `provide_forfeit_signatures` one
	#[derive(Clone)]
	struct ProxyC(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyC {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }
		async fn provide_forfeit_signatures(&mut self, _req: protos::ForfeitSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
			self.0.submit_payment(protos::SubmitPaymentRequest {
				input_vtxos: vec![], vtxo_requests: vec![], offboard_requests: vec![]
			}).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = ArkRpcProxyServer::start(ProxyC(srv.get_public_rpc().await)).await;
	bark.set_ark_url(&proxy).await;
	bark.timeout = None;
	let err = bark.try_refresh_all().await.expect_err("refresh should fail");
	assert!(err.to_string().contains("Message arrived late or round was full"), "err: {err}");
}

#[tokio::test]
async fn spend_unregistered_board() {
	let ctx = TestContext::new("server/spend_unregistered_board").await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn register_board_vtxo(&mut self, _req: protos::BoardVtxoRequest) -> Result<protos::Empty, tonic::Status> {
			// drop the request
			Ok(protos::Empty{})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = ArkRpcProxyServer::start(Proxy(srv.get_public_rpc().await)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let mut l = srv.subscribe_log::<RoundUserVtxoUnknown>().await;
	tokio::spawn(async move {
		let _ = bark.refresh_all().await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn spend_unconfirmed_board_round() {
	let ctx = TestContext::new("server/spend_unconfirmed_board_round").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &srv, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;

	let mut l = srv.subscribe_log::<UnconfirmedBoardSpendAttempt>().await;
	tokio::spawn(async move {
		let _ = bark.refresh_all().await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn spend_unconfirmed_board_oor() {
	let ctx = TestContext::new("server/spend_unconfirmed_board_oor").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2".to_string(), &srv).await;
	bark1.board(sat(800_000)).await;

	let mut l = srv.subscribe_log::<UnconfirmedBoardSpendAttempt>().await;
	tokio::spawn(async move {
		let _ = bark1.send_oor(bark2.address().await, sat(400_000)).await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn reject_revocation_on_successful_lightning_payment() {
	let ctx = TestContext::new("server/reject_revocation_on_successful_lightning_payment").await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self, req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			trace!("ArkRpcProxy: Calling finish_lightning_payment.");
			// Wait until payment is successful then we drop update so client asks for revocation
			let res = self.upstream().finish_lightning_payment(req).await?.into_inner();
			if res.payment_preimage().len() > 0 {
				trace!("ArkRpcProxy: Received preimage which we are 'dropping' for this test.");
			} else {
				trace!("ArkRpcProxy: Received message but no preimage yet.");
			}

			Ok(protos::LightningPaymentResult {
				progress_message: "intercepted by proxy".into(),
				status: protos::PaymentStatus::Failed.into(),
				payment_hash: vec![],
				payment_preimage: None
			})
		}
	}

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);

	let proxy = ArkRpcProxyServer::start(Proxy(srv.get_public_rpc().await)).await;
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	assert_eq!(bark_1.offchain_balance().await, board_amount);
	let err = bark_1.try_send_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains(
		"This lightning payment has completed. preimage: ",
	), "err: {err}");
}

#[tokio::test]
async fn spend_unconfirmed_board_lightning() {
	let ctx = TestContext::new("server/spend_unconfirmed_board_lightning").await;

	// Start a lightning node to generate an invoice, we won't perform any payment so no need for others
	trace!("Start lightningd-1");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let invoice = lightningd_1.invoice(None, "a testing invoice", "my description").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;
	bark1.board(sat(800_000)).await;

	let mut l = srv.subscribe_log::<UnconfirmedBoardSpendAttempt>().await;
	tokio::spawn(async move {
		let _ = bark1.send_lightning(invoice, Some(sat(400_000))).await;
		// we don't care that that call fails
	});
	l.recv().wait(2500).await;
}

#[tokio::test]
async fn bad_round_input() {
	let ctx = TestContext::new("server/bad_round_input").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(10000000);
		cfg.round_submit_time = Duration::from_secs(30);
	}).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, btc(1)).await;
	bark.board(btc(0.5)).await;
	let [vtxo] = bark.client().await.vtxos().unwrap().try_into().unwrap();

	let ark_info = srv.ark_info().await;
	let mut rpc = srv.get_public_rpc().await;
	let mut stream = rpc.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();
	srv.trigger_round().await;
	let challenge = loop {
		match stream.next().await.unwrap().unwrap() {
			protos::RoundEvent { event: Some(event) } => match event {
				protos::round_event::Event::Attempt(a) => {
					break VtxoOwnershipChallenge::new(a.vtxo_ownership_challenge.try_into().unwrap());
				},
				_ => {},
			},
			_ => panic!("unexpected msg"),
		}
	};

	// build some legit params
	let key = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
	let key2 = Keypair::new(&SECP, &mut bitcoin::secp256k1::rand::thread_rng());
	let vtxo_req = SignedVtxoRequest {
		vtxo: VtxoRequest {
			amount: Amount::from_sat(1000),
			policy: VtxoPolicy::new_pubkey(key.public_key()),
		},
		cosign_pubkey: key2.public_key(),
	};
	let offb_req = OffboardRequest {
		amount: Amount::from_sat(1000),
		script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(rand::random())),
	};

	let input = protos::InputVtxo {
		vtxo_id: vtxo.id().to_bytes().to_vec(),
		ownership_proof: challenge.sign_with(vtxo.id(), &[vtxo_req.clone()], &[offb_req.clone()], key).serialize().to_vec(),
	};

	// let's fire some bad attempts

	info!("no inputs");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![],
		vtxo_requests: vec![protos::SignedVtxoRequest {
			vtxo: Some(protos::VtxoRequest {
				amount: vtxo_req.vtxo.amount.to_sat(),
				policy: vtxo_req.vtxo.policy.serialize(),
			}),
			cosign_pubkey: vtxo_req.cosign_pubkey.serialize().to_vec(),
			public_nonces: iter::repeat({
				let (_sec, pb) = musig::nonce_pair(&key);
				pb.serialize().to_vec()
			}).take(ark_info.nb_round_nonces as usize).collect(),
		}],
		offboard_requests: vec![],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![],
		vtxo_requests: vec![],
		offboard_requests: vec![protos::OffboardRequest {
			amount: offb_req.amount.to_sat(),
			offboard_spk: offb_req.script_pubkey.to_bytes(),
		}],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());

	info!("no outputs");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![input.clone()],
		vtxo_requests: vec![],
		offboard_requests: vec![],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	assert!(err.message().contains("invalid request: zero outputs and zero offboards"),
		"[{}]: {}", err.code(), err.message(),
	);

	info!("unknown input");
	let fake_vtxo = VtxoId::from_slice(&rand::random::<[u8; 36]>()[..]).unwrap();
	let fake_input = protos::InputVtxo {
		vtxo_id: fake_vtxo.to_bytes().to_vec(),
		ownership_proof: challenge.sign_with(vtxo.id(), &[vtxo_req.clone()], &[offb_req.clone()], key).serialize().to_vec(),
	};
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![fake_input],
		vtxo_requests: vec![protos::SignedVtxoRequest {
			vtxo: Some(protos::VtxoRequest {
				amount: vtxo_req.vtxo.amount.to_sat(),
				policy: vtxo_req.vtxo.policy.serialize(),
			}),
			cosign_pubkey: vtxo_req.cosign_pubkey.serialize().to_vec(),
			public_nonces: iter::repeat({
				let (_sec, pb) = musig::nonce_pair(&key);
				pb.serialize().to_vec()
			}).take(ark_info.nb_round_nonces as usize).collect(),
		}],
		offboard_requests: vec![],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::NotFound, "[{}]: {}", err.code(), err.message());
	assert_eq!(err.metadata().get("identifiers").unwrap().to_str().unwrap(), fake_vtxo.to_string());

	info!("non-standard script");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![input.clone()],
		vtxo_requests: vec![],
		offboard_requests: vec![protos::OffboardRequest {
			amount: 1000,
			offboard_spk: vec![0x00],
		}],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	assert!(err.message().contains("non-standard"), "err: {}", err.message());

	info!("op_return too large");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![input.clone()],
		vtxo_requests: vec![],
		offboard_requests: vec![protos::OffboardRequest {
			amount: 1000,
			offboard_spk: ScriptBuf::new_op_return(<&PushBytes>::try_from(&[1u8; 84][..]).unwrap()).to_bytes(),
		}],
	}).fast().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	assert!(err.message().contains("non-standard"), "err: {}", err.message());
}

#[derive(Clone)]
struct NoFinishRoundProxy(captaind::ArkClient);
#[tonic::async_trait]
impl captaind::proxy::ArkRpcProxy for NoFinishRoundProxy {
	fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

	async fn subscribe_rounds(&mut self, req: protos::Empty) -> Result<Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>, tonic::Status> {
		let s = self.upstream().subscribe_rounds(req).await?.into_inner();
		Ok(Box::new(s.map(|r| match r {
			Ok(protos::RoundEvent { event: Some(protos::round_event::Event::Finished(_))}) => {
				Err(tonic::Status::internal("can't have it!"))
			}
			r => r,
		})))
	}
}

#[tokio::test]
async fn claim_forfeit_connector_chain() {
	let ctx = TestContext::new("server/claim_forfeit_connector_chain").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = ArkRpcProxyServer::start(NoFinishRoundProxy(srv.get_public_rpc().await)).await;

	// To make sure we have a chain of connector, we make a bunch of inputs
	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(5_000_000)).await;
	for _ in 0..10 {
		bark.board(sat(400_000)).await;
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let vtxo = bark.vtxos().await.into_iter().next().unwrap();
	let mut log_round = srv.subscribe_log::<RoundFinished>().await;
	assert!(bark.try_refresh_all().await.is_err());
	assert!(bark.vtxos().await.contains(&vtxo));
	assert_eq!(log_round.recv().fast().await.unwrap().nb_input_vtxos, 10);

	// start the exit process
	let mut log_detected = srv.subscribe_log::<ForfeitedExitInMempool>().await;
	bark.start_exit_vtxos([vtxo.id]).await;
	progress_exit_to_broadcast(&bark).try_wait(10_000).await.expect("time-out");
	assert_eq!(log_detected.recv().try_wait(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// confirm the exit
	let mut log_confirmed = srv.subscribe_log::<ForfeitedExitConfirmed>().await;
	ctx.generate_blocks(1).await;
	let msg = log_confirmed.recv().await.unwrap();
	assert_eq!(msg.vtxo, vtxo.id);
	info!("Exit txid: {}", msg.exit_tx);
	ctx.generate_blocks(1).await;

	// wait for connector txs to confirm and watcher to broadcast ff tx
	let mut log_broadcast = srv.subscribe_log::<ForfeitBroadcasted>().await;
	let txid = async {
		loop {
			ctx.generate_blocks(1).await;
			srv.wait_for_log::<TxIndexUpdateFinished>().await;
			if let Ok(m) = log_broadcast.try_recv() {
				break m.forfeit_txid;
			}
		}
	}.wait(15_000).await;

	// and then wait for the forfeit to confirm
	info!("Waiting for tx {} to confirm", txid);
	async {
		loop {
			ctx.generate_blocks(1).await;
			if let Some(tx) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(&txid, None).unwrap() {
				trace!("Tx {} has confirmations: {:?}", txid, tx.confirmations);
				if tx.confirmations.unwrap_or(0) > 0 {
					break;
				}
			}
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
	}.wait(20_000).await;
}

#[tokio::test]
async fn claim_forfeit_round_connector() {
	//! Special case of the forfeit caim test where the connector output is on the round tx
	let ctx = TestContext::new("server/claim_forfeit_round_connector").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = ArkRpcProxyServer::start(NoFinishRoundProxy(srv.get_public_rpc().await)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let [vtxo] = bark.vtxos().await.try_into().expect("1 vtxo");
	let mut log_round = srv.subscribe_log::<RoundFinished>().await;
	assert!(bark.try_refresh_all().await.is_err());
	assert!(bark.vtxos().await.contains(&vtxo));
	assert_eq!(log_round.recv().try_fast().await.expect("time-out").unwrap().nb_input_vtxos, 1);

	// start the exit process
	let mut log_detected = srv.subscribe_log::<ForfeitedExitInMempool>().await;
	bark.start_exit_vtxos([vtxo.id]).await;
	progress_exit_to_broadcast(&bark).try_wait(10_000).await.expect("time-out");
	assert_eq!(log_detected.recv().try_wait(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// confirm the exit
	let mut log_forfeit_broadcasted = srv.subscribe_log::<ForfeitBroadcasted>().await;
	let mut log_confirmed = srv.subscribe_log::<ForfeitedExitConfirmed>().await;
	ctx.generate_blocks(1).await;
	assert_eq!(log_confirmed.recv().try_wait(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// wait until forfeit watcher broadcasts forfeit tx
	let txid = log_forfeit_broadcasted.recv().try_wait(10_000).await.expect("time-out").unwrap().forfeit_txid;

	// and then wait for it to confirm
	info!("Waiting for tx {} to confirm", txid);
	async {
		loop {
			ctx.generate_blocks(1).await;
			if let Some(tx) = ctx.bitcoind().sync_client().custom_get_raw_transaction_info(&txid, None).unwrap() {
				trace!("Tx {} has confirmations: {:?}", txid, tx.confirmations);
				if tx.confirmations.unwrap_or(0) > 0 {
					break;
				}
			}
		}
	}.wait(10_000).await;
}

#[tokio::test]
async fn register_board_is_idempotent() {
	let ctx = TestContext::new("server/register_board_is_idempotent").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark_wallet = ctx.new_bark("bark", &srv).await;

	ctx.fund_bark(&bark_wallet, bitcoin::Amount::from_sat(50_000)).await;
	let board = bark_wallet.board_all().await;

	let bark_client = bark_wallet.client().await;

	let vtxo = bark_client.get_vtxo_by_id(board.vtxos[0].id).unwrap();
	let funding_tx = ctx.bitcoind().await_transaction(&board.funding_txid).await;

	// We will now call the register_board a few times
	let mut rpc = srv.get_public_rpc().await;
	let request = protos::BoardVtxoRequest {
		board_vtxo: vtxo.vtxo.serialize(),
		board_tx: bitcoin::consensus::encode::serialize(&funding_tx),
	};

	for _ in 0..5 {
		rpc.register_board_vtxo(request.clone()).await.unwrap();
	}
}

#[tokio::test]
async fn reject_dust_board_cosign() {
	let ctx = TestContext::new("server/reject_dust_board_cosign").await;
	let srv = ctx.new_captaind("server", None).await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn request_board_cosign(&mut self, mut req: protos::BoardCosignRequest) -> Result<protos::BoardCosignResponse, tonic::Status> {
			req.amount = P2TR_DUST_SAT - 1;
			Ok(self.upstream().request_board_cosign(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	let err = bark.try_board_all().await.unwrap_err();
	assert!(err.to_string().contains(
		"bad user input: board amount must be at least 0.00000330 BTC",
	), "err: {err}");
}

#[tokio::test]
async fn reject_dust_vtxo_request() {
	let ctx = TestContext::new("server/reject_dust_vtxo_request").await;
	let srv = ctx.new_captaind("server", None).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark_client = bark.client().await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient, Arc<Wallet>, Arc<Mutex<Option<VtxoOwnershipChallenge>>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn subscribe_rounds(&mut self, req: protos::Empty) -> Result<Box<
			dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
		>, tonic::Status> {
			let stream = self.upstream().subscribe_rounds(req).await?.into_inner();

			let shared = self.2.clone();

			let s = stream
				.inspect_ok(move |event| {
					if let Some(protos::round_event::Event::Attempt(m)) = &event.event {
						let challenge = VtxoOwnershipChallenge::new(m.vtxo_ownership_challenge.clone().try_into().unwrap());
						shared.try_lock().unwrap().replace(challenge);
					}
				});

			Ok(Box::new(s))
		}

		// Proxy alters the request to make it vtxo request subdust but correctly signed
		async fn submit_payment(&mut self, mut req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
			let [input] = req.input_vtxos.clone().try_into().unwrap();

			req.vtxo_requests[0].vtxo.as_mut().unwrap().amount = P2TR_DUST_SAT - 1;

			let mut vtxo_requests = Vec::with_capacity(req.vtxo_requests.len());
			for r in &req.vtxo_requests {
				vtxo_requests.push(ark::SignedVtxoRequest {
					vtxo: r.vtxo.clone().unwrap().try_into().unwrap(),
					cosign_pubkey: PublicKey::from_slice(&r.cosign_pubkey).unwrap(),
				});
			}

			// Spending input boarded with first derivation
			let keypair = self.1.peak_keypair(0).unwrap();

			let sig = self.2.lock().await.as_ref().unwrap().sign_with(
				VtxoId::from_slice(&input.vtxo_id).unwrap(),
				&vtxo_requests,
				&[],
				keypair,
			);


			req.input_vtxos.get_mut(0).unwrap().ownership_proof = sig.serialize().to_vec();

			Ok(self.upstream().submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await, Arc::new(bark_client), Arc::new(Mutex::new(None)));
	let proxy = ArkRpcProxyServer::start(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	bark.timeout = Some(Duration::from_millis(3_500));
	let err = bark.try_refresh_all().await.unwrap_err();
	assert!(err.to_string().contains(
		"bad user input: vtxo amount must be at least 0.00000330 BTC",
	), "err: {err}");
}

#[tokio::test]
async fn reject_dust_offboard_request() {
	let ctx = TestContext::new("server/reject_dust_offboard_request").await;
	let srv = ctx.new_captaind("server", None).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark_client = bark.client().await;
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient, Arc<Wallet>, Arc<Mutex<Option<VtxoOwnershipChallenge>>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn subscribe_rounds(&mut self, req: protos::Empty) -> Result<Box<
			dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
		>, tonic::Status> {
			let stream = self.upstream().subscribe_rounds(req).await?.into_inner();

			let shared = self.2.clone();

			let s = stream
				.inspect_ok(move |event| {
					if let Some(protos::round_event::Event::Attempt(m)) = &event.event {
						let challenge = VtxoOwnershipChallenge::new(m.vtxo_ownership_challenge.clone().try_into().unwrap());
						shared.try_lock().unwrap().replace(challenge);
					}
				});

			Ok(Box::new(s))
		}

		// Proxy alters the request to make it vtxo request subdust but correctly signed
		async fn submit_payment(&mut self, mut req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
			let [input] = req.input_vtxos.clone().try_into().unwrap();

			req.offboard_requests[0].amount = P2TR_DUST_SAT - 1;

			let mut offboard_requests = Vec::with_capacity(req.offboard_requests.len());
			for r in &req.offboard_requests {
				offboard_requests.push(ark::OffboardRequest {
					script_pubkey: ScriptBuf::from_bytes(r.offboard_spk.clone()),
					amount: Amount::from_sat(r.amount),
				});
			}

			// Spending input boarded with first derivation
			let keypair = self.1.peak_keypair(0).unwrap();

			let sig = self.2.lock().await.as_ref().unwrap().sign_with(
				VtxoId::from_slice(&input.vtxo_id).unwrap(),
				&[],
				&offboard_requests,
				keypair,
			);


			req.input_vtxos.get_mut(0).unwrap().ownership_proof = sig.serialize().to_vec();

			Ok(self.upstream().submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await, Arc::new(bark_client), Arc::new(Mutex::new(None)));
	let proxy = ArkRpcProxyServer::start(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	bark.timeout = Some(Duration::from_millis(10_000));

	let addr = bark.get_onchain_address().await;
	let err = bark.try_offboard_all(&addr).await.unwrap_err();
	assert!(err.to_string().contains("non-standard"), "err: {err}");
}

#[tokio::test]
async fn reject_dust_arkoor_cosign() {
	let ctx = TestContext::new("server/reject_dust_arkoor_cosign").await;
	let srv = ctx.new_captaind("server", None).await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn request_arkoor_package_cosign(&mut self, mut req: protos::ArkoorPackageCosignRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.arkoors[0].outputs[0].amount = P2TR_DUST.to_sat() - 1;
			Ok(self.upstream().request_arkoor_package_cosign(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark2 = ctx.new_bark("bark2", &srv).await;

	let err = bark.try_send_oor(bark2.address().await, sat(10_000), true).await.unwrap_err();
	assert!(err.to_string().contains("arkoor output amounts cannot be below the p2tr dust threshold"), "err: {err}");
}

#[tokio::test]
async fn reject_dust_bolt11_payment() {
	let ctx = TestContext::new("server/reject_dust_bolt11_payment").await;
	let srv = ctx.new_captaind("server", None).await;

	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn start_lightning_payment(&mut self, mut req: protos::LightningPaymentRequest)
			-> Result<protos::ArkoorPackageCosignResponse, tonic::Status>
		{
			req.user_amount_sat = Some(P2TR_DUST_SAT - 1);
			Ok(self.upstream().start_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice = lightningd_1.invoice(None, "test_payment", "A test payment").await;
	let err = bark.try_send_lightning(invoice, Some(sat(100_000))).await.unwrap_err();
	assert!(err.to_string().contains(
		"arkoor output amounts cannot be below the p2tr dust threshold",
	), "err: {err}");
}

#[tokio::test]
async fn server_refuse_claim_invoice_not_settled() {
	let ctx = TestContext::new("server/server_refuse_claim_invoice_not_settled").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn claim_lightning_receive(&mut self, mut req: protos::ClaimLightningReceiveRequest) -> Result<protos::ArkoorCosignResponse, tonic::Status> {
			req.payment_preimage = vec![1; 32];
			Ok(self.upstream().claim_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &proxy.address, btc(3)).await);
	bark.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = invoice_info.clone();
	tokio::spawn(async move { lightningd_1.pay_bolt11(cloned.invoice).await; });
	let err = bark.try_lightning_receive(invoice_info.invoice).await.unwrap_err();

	assert!(err.to_string().contains(
		"input vtxo payment hash does not match preimage",
	), "err: {err}");
}

#[tokio::test]
async fn server_should_release_hodl_invoice_when_subscription_is_cancelled() {
	let ctx = TestContext::new("server/server_should_release_hodl_invoice_when_subscription_is_cancelled").await;
	let cfg_htlc_subscription_timeout = Duration::from_secs(5);

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightningd_2), |cfg| {
		// Set the subscription timeout very short to cancel the subscription quickly
		cfg.htlc_subscription_timeout = cfg_htlc_subscription_timeout
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	tokio::time::sleep(cfg_htlc_subscription_timeout + srv.config().invoice_check_interval).await;

	// cln rpc error code when cannot pay invoice
	let err = lightningd_1.try_pay_bolt11(invoice_info.invoice).await.unwrap_err();
	assert!(err.to_string().contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");
}

#[tokio::test]
async fn server_should_refuse_claim_twice() {
	let ctx = TestContext::new("server/server_should_refuse_claim_twice").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark_1.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_info = bark_1.bolt11_invoice(btc(1)).await;

	let cloned = bark_1.clone();
	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move { cloned.lightning_receive(cloned_invoice_info.invoice).await });
	lightningd_1.pay_bolt11(invoice_info.invoice.clone()).wait(10_000).await;
	res1.await.unwrap();

	assert_eq!(bark_1.offchain_balance().await, sat(300000000));

	// bark should not be able to subscribe to already settled invoice
	let err = bark_1.try_lightning_receive(invoice_info.invoice).await.unwrap_err();
	assert!(err.to_string().contains("invoice already settled"), "err: {err}");
}

#[tokio::test]
async fn server_refuse_too_deep_arkoor_input() {
	let ctx = TestContext::new("server/server_refuse_too_deep_arkoor_input").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn get_ark_info(&mut self, req: protos::Empty) -> Result<protos::ArkInfo, tonic::Status>  {
			let mut info = self.upstream().get_ark_info(req).await?.into_inner();
			info.max_arkoor_depth = 10;
			Ok(info)
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &proxy.address, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let addr = bark2.address().await;
	bark1.send_oor(&addr, sat(100_000)).await;
	bark1.send_oor(&addr, sat(100_000)).await;
	bark1.send_oor(&addr, sat(100_000)).await;
	bark1.send_oor(&addr, sat(100_000)).await;
	bark1.send_oor(&addr, sat(100_000)).await;

	let [vtxo] = bark1.vtxos_no_sync().await.try_into().unwrap();

	let err = bark1.try_send_oor(&addr, sat(100_000), false).await.unwrap_err();
	assert!(err
		.to_string()
		.contains(&format!("bad user input: OOR depth reached maximum of 5, please refresh your VTXO: {}", vtxo.id)),
		"err: {err}"
	);
}

#[tokio::test]
async fn run_two_captainds() {
	let ctx = TestContext::new("server/run_two_captainds").await;
	let _srv1 = ctx.new_captaind("server1", None).await;
	let _srv2 = ctx.new_captaind("server2", None).await;
}

#[tokio::test]
async fn should_refuse_paying_invoice_not_matching_htlcs() {
	let ctx = TestContext::new("aspd/should_refuse_paying_invoice_not_matching_htlcs").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	let dummy_invoice = lightningd_1.invoice(None, "dummy_invoice", "A dummy invoice").await;

	// Start an aspd and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient, String);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn finish_lightning_payment(&mut self, mut req: protos::SignedLightningPaymentDetails) -> Result<protos::LightningPaymentResult, tonic::Status> {
			req.invoice = self.1.to_string();
			Ok(self.upstream().finish_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await, dummy_invoice);
	let proxy = ArkRpcProxyServer::start(proxy).await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice = lightningd_1.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_send_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("htlc payment hash doesn't match invoice"), "err: {err}");
}

#[tokio::test]
async fn should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs() {
	let ctx = TestContext::new("aspd/should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start an aspd and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_2), btc(10)).await;

	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> captaind::ArkClient { self.0.clone() }

		async fn finish_lightning_payment(&mut self, mut req: protos::SignedLightningPaymentDetails) -> Result<protos::LightningPaymentResult, tonic::Status> {
			req.htlc_vtxo_ids.pop();
			Ok(self.upstream().finish_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = ArkRpcProxyServer::start(proxy).await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board(btc(0.5)).await;
	bark_1.board(btc(0.6)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice = lightningd_1.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_send_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("htlc vtxo amount too low for invoice"), "err: {err}");
}
