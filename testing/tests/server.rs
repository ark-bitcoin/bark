
use std::iter;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hex::FromHex;
use bitcoin::{absolute, transaction, Amount, Network, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin::{ScriptBuf, WPubkeyHash};
use bitcoin_ext::{P2TR_DUST, P2TR_DUST_SAT};
use bitcoin_ext::rpc::BitcoinRpcExt;
use futures::future::join_all;
use futures::{Stream, StreamExt, TryStreamExt};
use log::{debug, error, info, trace};
use tokio::sync::{mpsc, Mutex};

use ark::{
	musig, OffboardRequest, ProtocolEncoding, SignedVtxoRequest, VtxoId, VtxoPolicy, VtxoRequest,
	SECP,
};
use ark::challenges::RoundAttemptChallenge;
use ark::tree::signed::builder::SignedTreeBuilder;
use bark::Wallet;
use bark::lightning_invoice::Bolt11Invoice;
use bark_json::cli::RoundStatus;
use bark_json::primitives::WalletVtxoInfo;
use bark_json::exit::ExitState;
use server::secret::Secret;
use server::vtxopool::VtxoTarget;
use server_log::{
	RoundFinished, RoundUserVtxoAlreadyRegistered,
	RoundUserVtxoUnknown, TxIndexUpdateFinished,
	UnconfirmedBoardRegisterAttempt, ForfeitedExitInMempool, ForfeitedExitConfirmed,
	ForfeitBroadcasted, RoundError
};
use server_rpc::protos;

use ark_testing::{Captaind, TestContext, btc, sat, secs, Bark};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{FutureExt, ReceiverExt, ToAltString};

use ark_testing::exit::complete_exit;

lazy_static::lazy_static! {
	static ref RANDOM_PK: PublicKey = "02c7ef7d49b365974cd219f7036753e1544a3cdd2120eb7247dd8a94ef91cf1e49".parse().unwrap();
}

async fn progress_exit_to_broadcast(bark: &Bark) {
	let progress_result = bark.progress_exit().await;
	assert_eq!(false, progress_result.done);
	assert_eq!(None, progress_result.claimable_height);
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
async fn integration() {
	let ctx = TestContext::new("server/integration").await;
	let srv = ctx.new_captaind("server", None).await;

	// Add integration "third".
	let stdout = srv.integration_cmd(&["add", "third"]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);

	// Generate integration API key for "third" with 1 open token count and a 1-hour activity.
	let stdout = srv.integration_cmd(&["generate-api-key", "third", "third_api_key", "1h"]).await;
	let mut parts = stdout.split(' ');
	let response = parts.next().unwrap().trim();
	assert_eq!(response, "API");
	let api_key = parts.last().unwrap().trim();

	// Disable integration API Key for "third".
	let stdout = srv.integration_cmd(&["disable-api-key", "third", "third_api_key"]).await;
	let mut parts = stdout.split(' ');
	assert_eq!(parts.next().unwrap(), "Deleted");

	// Add integration API Key filters for "third".
	let stdout = srv.integration_cmd(&["update-api-key-filters", "third", "third_api_key", "--ip", "127.0.0.1", "--dns", "localhost"]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);

	// Add integration `single-use-board` token configuration for "third" with 1 open token count and a 60 seconds activity.
	let stdout = srv.integration_cmd(&["configure-token-type", "third", "single-use-board", "1", "60"]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);

	// Generate integration token of type single-use-board for "third" with a 60 seconds activity.
	let stdout = srv.integration_cmd(&["generate-token", "third", "single-use-board", "--integration-api-key", api_key]).await;
	let mut parts = stdout.split(' ');
	assert_eq!(parts.next().unwrap(), "Token:");
	let token = parts.next().unwrap().trim();
	trace!("Token: {}", token);

	// Add integration token filters for "third".
	let stdout = srv.integration_cmd(&["update-token-filters", "third", token, "--integration-api-key", api_key, "--ip", "127.0.0.1", "--dns", "localhost"]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);

	// Update integration token status for "third".
	let stdout = srv.integration_cmd(&["update-token-status", "third", token, "abused", "--integration-api-key", api_key]).await;
	let number = stdout.parse::<i64>().expect("Failed to convert stdout to i64");
	assert_ne!(number, 0);

	// Remove integration "third".
	let stdout = srv.integration_cmd(&["remove", "third"]).await;
	let mut parts = stdout.split(' ');
	assert_eq!(parts.next().unwrap(), "Deleted");
}

#[tokio::test]
async fn bitcoind_auth_connection() {
	let ctx = TestContext::new("server/bitcoind_auth_connection").await;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
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

	let mut log_stream = srv.subscribe_log::<server_log::RoundStarted>();
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

	let mut log_round_err = srv.subscribe_log::<RoundError>();

	// Set a time-out on the bark command for the refresh --all
	// The command is expected to time-out
	bark.set_timeout(Duration::from_millis(10_000));
	let mut bark = Arc::new(bark);

	// we will launch bark to try refresh, it will produce an error log at first,
	// then we'll confirm the server's money and then bark should succeed by retrying

	let bark_clone = bark.clone();
	let attempt_handle = tokio::spawn(async move {
		let err = bark_clone.try_refresh_all().await.unwrap_err();
		debug!("First refresh failed: {:#}", err);
	});

	// this will at first produce an error
	let err = log_round_err.recv().wait_millis(15_000).await.unwrap().error;
	assert!(err.contains("Insufficient funds"), "err: {err}");

	attempt_handle.await.unwrap();

	// then confirm the money and it should work
	ctx.generate_blocks(NEED_CONFS).await;
	tokio::time::sleep(Duration::from_millis(3000)).await;

	log_round_err.clear();
	Arc::get_mut(&mut bark).unwrap().unset_timeout();
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
	// reiniting the daemon should not call the create command if the datadir exists
	let srv = ctx.new_captaind_with_cfg("server", None, move |cfg| {
		// adapt the old config only to the new bitcoind
		new_cfg.bitcoind = cfg.bitcoind.clone();
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
	bark1.set_timeout(srv.max_round_delay());
	let err = bark1.try_refresh_all().await.unwrap_err();
	assert!(err.to_string().contains(
		&format!("output exceeds maximum vtxo amount of {}", cfg_max_amount),
	), "err: {err}");

	// but we can offboard the entire amount!
	bark1.unset_timeout();
	let address = ctx.bitcoind().get_new_address();
	bark1.offboard_all(address.clone()).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let balance = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(balance, Amount::from_sat(999_100));
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
async fn restart_custom_cfg_server() {
	let ctx = TestContext::new("server/restart_custom_cfg_server").await;
	let mut srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.vtxo_exit_delta = 24;
	}).await;
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
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	bark2.send_oor(&bark1.address().await, sat(330_000)).await;
	bark1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

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
		cfg.min_board_amount = sat(0);
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
	struct Proxy(Arc<Mutex<usize>>, Arc<mpsc::UnboundedSender<tonic::Status>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			let mut lock = self.0.lock().await;
			let res = upstream.submit_payment(req).await;
			// the last bark should fail being registered
			let ret = if *lock == NB_BARKS-1 {
				let err = res.expect_err("must error at max");
				trace!("proxy: NOK: {}", err);
				self.1.send(err.clone()).unwrap();
				Err(err)
			} else {
				trace!("proxy: OK (nb={})", *lock);
				res.map(|r| r.into_inner())
			};
			*lock += 1;
			ret
		}
	}

	let proxy = Proxy(Arc::new(Mutex::new(0)), Arc::new(tx));
	let proxy = srv.get_proxy_rpc(proxy).await;
	futures::future::join_all(barks.iter().map(|bark| bark.set_ark_url(&proxy))).await;

	//TODO(stevenroose) need to find a way to ensure that all these happen in the same round
	tokio::spawn(async move {
		futures::future::join_all(barks.iter().map(|bark| async {
			// ignoring error as last one will fail
			let _ = bark.refresh_all().await;
		})).await;
	});

	// then we wait for the error to happen
	let err = rx.recv().wait_millis(30_000).await.unwrap();
	assert!(err.to_string().contains("Message arrived late or round was full"), "err: {err}");
}

#[tokio::test]
async fn double_spend_oor() {
	let ctx = TestContext::new("server/double_spend_oor").await;

	/// This proxy will always duplicate OOR requests and store the latest request in the mutex.
	#[derive(Clone)]
	struct Proxy(Arc<Mutex<Option<protos::ArkoorPackageCosignRequest>>>);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_arkoor_package_cosign(
			&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			let (mut c1, mut c2) = (upstream.clone(), upstream.clone());
			let (res1, res2) = tokio::join!(
				c1.request_arkoor_package_cosign(req.clone()),
				c2.request_arkoor_package_cosign(req.clone()),
			);
			self.0.lock().await.replace(req);
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
	let proxy = srv.get_proxy_rpc(Proxy(last_req.clone())).await;

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
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			let vtxoid = VtxoId::from_slice(&req.input_vtxos[0].vtxo_id).unwrap();

			let (mut c1, mut c2) = (upstream.clone(), upstream.clone());
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
	let proxy = srv.get_proxy_rpc(Proxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let mut l = srv.subscribe_log::<RoundUserVtxoAlreadyRegistered>();
	bark.refresh_all().await;
	l.recv().wait_millis(2500).await;
}

#[tokio::test]
async fn test_participate_round_wrong_step() {
	let ctx = TestContext::new("server/test_participate_round_wrong_step").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let mut bark = ctx.new_bark_with_funds("bark".to_string(), &srv, sat(1_000_000)).await;
	bark.board(Amount::from_sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	/// This proxy will send a `provide_vtxo_signatures` req instead of `submit_payment` one
	#[derive(Clone)]
	struct ProxyA;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyA {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, _req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			upstream.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
				pubkey: RANDOM_PK.serialize().to_vec(), signatures: vec![]
			}).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = srv.get_proxy_rpc(ProxyA).await;
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all().await.expect_err("refresh should time out");
	assert!(err.to_string().contains("current step is payment registration"), "err: {err}");

	/// This proxy will send a `provide_forfeit_signatures` req instead of `provide_vtxo_signatures` one
	#[derive(Clone)]
	struct ProxyB;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyB {
		async fn provide_vtxo_signatures(
			&self, upstream: &mut ArkClient, _req: protos::VtxoSignaturesRequest,
		) -> Result<protos::Empty, tonic::Status> {
			upstream.provide_forfeit_signatures(protos::ForfeitSignaturesRequest { signatures: vec![] }).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = srv.get_proxy_rpc(ProxyB).await;
	bark.set_timeout(srv.max_round_delay());
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all().await.expect_err("refresh should fail");
	assert!(err.to_string().contains("current step is vtxo signatures submission"), "err: {err}");

	/// This proxy will send a `submit_payment` req instead of `provide_forfeit_signatures` one
	#[derive(Clone)]
	struct ProxyC;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyC {
		async fn provide_forfeit_signatures(
			&self, upstream: &mut ArkClient, _req: protos::ForfeitSignaturesRequest,
		) -> Result<protos::Empty, tonic::Status> {
			upstream.submit_payment(protos::SubmitPaymentRequest {
				input_vtxos: vec![], vtxo_requests: vec![], offboard_requests: vec![]
			}).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = srv.get_proxy_rpc(ProxyC).await;
	bark.set_ark_url(&proxy).await;
	bark.unset_timeout();
	let res = bark.try_refresh_all().await.expect("should get pending state");
	if let RoundStatus::Pending { .. } = res {
		// since from the bark POV we sent our forfeits, it should keep the pending state
	} else {
		panic!("should be pending state")
	}
}

#[tokio::test]
async fn spend_unregistered_board() {
	let ctx = TestContext::new("server/spend_unregistered_board").await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, _upstream: &mut ArkClient, _req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// drop the request
			Ok(protos::Empty{})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.get_proxy_rpc(Proxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let mut l = srv.subscribe_log::<RoundUserVtxoUnknown>();
	tokio::spawn(async move {
		let _ = bark.refresh_all().await;
		// we don't care that that call fails
	});
	l.recv().wait(srv.max_round_delay()).await;
}

#[tokio::test]
async fn reject_revocation_on_successful_lightning_payment() {
	let ctx = TestContext::new("server/reject_revocation_on_successful_lightning_payment").await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn finish_lightning_payment(
			&self, upstream: &mut ArkClient, req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			trace!("ArkRpcProxy: Calling finish_lightning_payment.");
			// Wait until payment is successful then we drop update so client asks for revocation
			let res = upstream.finish_lightning_payment(req).await?.into_inner();
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

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);

	let proxy = srv.get_proxy_rpc(Proxy).await;
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	assert_eq!(bark_1.spendable_balance().await, board_amount);
	let err = bark_1.try_pay_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("This lightning payment has completed. preimage: "), "err: {err}");
}

#[tokio::test]
async fn bad_round_input() {
	let ctx = TestContext::new("server/bad_round_input").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(10000000);
		cfg.round_submit_time = Duration::from_secs(30);
	}).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, btc(1)).await;
	bark.board_and_confirm_and_register(&ctx, btc(0.5)).await;
	let [vtxo] = bark.client().await.spendable_vtxos().unwrap().try_into().unwrap();

	let ark_info = srv.ark_info().await;
	let mut rpc = srv.get_public_rpc().await;
	let mut stream = rpc.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();
	srv.trigger_round().await;
	let challenge = loop {
		match stream.next().await.unwrap().unwrap() {
			protos::RoundEvent { event: Some(event) } => match event {
				protos::round_event::Event::Attempt(a) => {
					break RoundAttemptChallenge::new(a.round_attempt_challenge.try_into().unwrap());
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
		cosign_pubkey: Some(key2.public_key()),
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
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![],
		vtxo_requests: vec![],
		offboard_requests: vec![protos::OffboardRequest {
			amount: offb_req.amount.to_sat(),
			offboard_spk: offb_req.script_pubkey.to_bytes(),
		}],
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());

	info!("no outputs");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![input.clone()],
		vtxo_requests: vec![],
		offboard_requests: vec![],
	}).ready().await.unwrap_err();
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
	}).ready().await.unwrap_err();
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
	}).ready().await.unwrap_err();
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
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	assert!(err.message().contains("non-standard"), "err: {}", err.message());
}

#[derive(Clone)]
struct NoFinishRoundProxy;
#[tonic::async_trait]
impl captaind::proxy::ArkRpcProxy for NoFinishRoundProxy {
	async fn subscribe_rounds(
		&self, upstream: &mut ArkClient, req: protos::Empty,
	) -> Result<Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>, tonic::Status> {
		let s = upstream.subscribe_rounds(req).await?.into_inner();
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
	let proxy = srv.get_proxy_rpc(NoFinishRoundProxy).await;

	// To make sure we have a chain of connector, we make a bunch of inputs
	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(5_000_000)).await;
	for _ in 0..10 {
		bark.board(sat(400_000)).await;
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let vtxo = bark.vtxos().await.into_iter().next().unwrap();
	let mut log_round = srv.subscribe_log::<RoundFinished>();
	assert!(bark.try_refresh_all().await.is_err());
	assert_eq!(bark.inround_balance().await, sat(4_000_000), "vtxos: {:?}", bark.vtxos().await);
	assert_eq!(log_round.recv().ready().await.unwrap().nb_input_vtxos, 10);

	// start the exit process
	let mut log_detected = srv.subscribe_log::<ForfeitedExitInMempool>();
	bark.start_exit_vtxos([vtxo.id]).await;
	progress_exit_to_broadcast(&bark).try_wait_millis(10_000).await.expect("time-out");
	assert_eq!(log_detected.recv().try_wait_millis(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// confirm the exit
	let mut log_confirmed = srv.subscribe_log::<ForfeitedExitConfirmed>();
	ctx.generate_blocks(1).await;
	let msg = log_confirmed.recv().await.unwrap();
	assert_eq!(msg.vtxo, vtxo.id);
	info!("Exit txid: {}", msg.exit_tx);
	ctx.generate_blocks(1).await;

	// wait for connector txs to confirm and watcher to broadcast ff tx
	let mut log_broadcast = srv.subscribe_log::<ForfeitBroadcasted>();
	let txid = async {
		loop {
			ctx.generate_blocks(1).await;
			srv.wait_for_log::<TxIndexUpdateFinished>().await;
			if let Ok(m) = log_broadcast.try_recv() {
				break m.forfeit_txid;
			}
		}
	}.wait_millis(15_000).await;

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
	}.wait_millis(20_000).await;
}

#[tokio::test]
async fn claim_forfeit_round_connector() {
	//! Special case of the forfeit caim test where the connector output is on the round tx
	let ctx = TestContext::new("server/claim_forfeit_round_connector").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.get_proxy_rpc(NoFinishRoundProxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let [vtxo] = bark.vtxos().await.try_into().expect("1 vtxo");
	let mut log_round = srv.subscribe_log::<RoundFinished>();
	assert!(bark.try_refresh_all().await.is_err());
	assert_eq!(bark.inround_balance().await, sat(800_000));
	assert_eq!(log_round.recv().ready().await.expect("time-out").nb_input_vtxos, 1);

	// start the exit process
	let mut log_detected = srv.subscribe_log::<ForfeitedExitInMempool>();
	bark.start_exit_vtxos([vtxo.id]).await;
	progress_exit_to_broadcast(&bark).try_wait_millis(10_000).await.expect("time-out");
	assert_eq!(log_detected.recv().try_wait_millis(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// confirm the exit
	let mut log_forfeit_broadcasted = srv.subscribe_log::<ForfeitBroadcasted>();
	let mut log_confirmed = srv.subscribe_log::<ForfeitedExitConfirmed>();
	ctx.generate_blocks(1).await;
	assert_eq!(log_confirmed.recv().try_wait_millis(10_000).await.expect("time-out").unwrap().vtxo, vtxo.id);

	// wait until forfeit watcher broadcasts forfeit tx
	let txid = log_forfeit_broadcasted.recv().try_wait_millis(10_000).await.expect("time-out").unwrap().forfeit_txid;

	// and then wait for it to confirm
	info!("Waiting for tx {} to confirm", txid);
	async {
		let rpc = ctx.bitcoind().sync_client();
		loop {
			ctx.generate_blocks(1).await;
			if let Some(tx) = rpc.custom_get_raw_transaction_info(&txid, None).unwrap() {
				trace!("Tx {} has confirmations: {:?}", txid, tx.confirmations);
				if tx.confirmations.unwrap_or(0) > 0 {
					break;
				}
			}
		}
	}.wait_millis(10_000).await;
}

#[tokio::test]
async fn register_board_is_idempotent() {
	let ctx = TestContext::new("server/register_board_is_idempotent").await;
	let srv = ctx.new_captaind("server", None).await;
	let bark_wallet = ctx.new_bark("bark", &srv).await;

	ctx.fund_bark(&bark_wallet, bitcoin::Amount::from_sat(50_000)).await;
	let board = bark_wallet.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark_client = bark_wallet.client().await;

	let vtxo = bark_client.get_vtxo_by_id(board.vtxos[0].id).unwrap();

	// We will now call the register_board a few times
	let mut rpc = srv.get_public_rpc().await;
	let request = protos::BoardVtxoRequest {
		board_vtxo: vtxo.vtxo.serialize(),
	};

	for _ in 0..5 {
		rpc.register_board_vtxo(request.clone()).await.unwrap();
	}
}

#[tokio::test]
async fn register_unconfirmed_board() {
	let ctx = TestContext::new("server/register_unconfirmed_board").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(2_000_000)).await;

	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let unconfirmed_board = bark.board(sat(800_000)).await;

	let bark_client = bark.client().await;

	let vtxo = bark_client.get_vtxo_by_id(unconfirmed_board.vtxos[0].id).unwrap();

	let unconfirmed_board_request = protos::BoardVtxoRequest {
		board_vtxo: vtxo.vtxo.serialize(),
	};

	#[derive(Clone)]
	struct Proxy {
		pub unconfirmed_board_request: protos::BoardVtxoRequest,
	}
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, upstream: &mut ArkClient, _req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Ok(upstream.register_board_vtxo(self.unconfirmed_board_request.clone()).await?.into_inner())
		}
	}

	let proxy = Proxy {
		unconfirmed_board_request,
	};
	let proxy = srv.get_proxy_rpc(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	let mut l = srv.subscribe_log::<UnconfirmedBoardRegisterAttempt>();
	tokio::spawn(async move {
		bark.maintain().await;
		// we don't care that that call fails
	});
	l.recv().wait_millis(2500).await;
}

#[tokio::test]
async fn reject_dust_board_cosign() {
	let ctx = TestContext::new("server/reject_dust_board_cosign").await;
	// Need to set the `min_board_amount` less than dust to check we
	// reject signing on dust always.
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.min_board_amount = sat(0);
	}).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_board_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::BoardCosignRequest,
		) -> Result<protos::BoardCosignResponse, tonic::Status> {
			req.amount = P2TR_DUST_SAT - 1;
			Ok(upstream.request_board_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	let err = bark.try_board_all().await.unwrap_err();
	assert!(err.to_string().contains(
		"bad user input: board amount must be at least 0.00000330 BTC",
	), "err: {err}");
}

#[tokio::test]
async fn reject_below_minimum_board_cosign() {
	let ctx = TestContext::new("server/reject_below_minimum_board_cosign").await;

	// Set up server with `min_board_amount` of 30 000 sats
	const MIN_BOARD_AMOUNT_SATS: u64 = 30_000;

	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.min_board_amount = sat(MIN_BOARD_AMOUNT_SATS);
	}).await;

	// We need to modify the client's requested amount to board via a proxy as the client
	// side check would prevent a board below the minimum.
	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_board_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::BoardCosignRequest,
		) -> Result<protos::BoardCosignResponse, tonic::Status> {
			req.amount = MIN_BOARD_AMOUNT_SATS - 1;
			Ok(upstream.request_board_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(100_000)).await;

	let err = bark.try_board_all().await.unwrap_err();
	assert!(err.to_string().contains(
		"bad user input: board amount must be at least 0.00030000 BTC",
	), "err: {err}");
}

#[tokio::test]
async fn reject_dust_vtxo_request() {
	let ctx = TestContext::new("server/reject_dust_vtxo_request").await;
	let srv = ctx.new_captaind("server", None).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_all_and_confirm_and_register(&ctx).await;

	let bark_client = bark.client().await;

	let [vtxo] = bark.vtxos().await.try_into().unwrap();

	#[derive(Clone)]
	struct Proxy {
		vtxo: WalletVtxoInfo,
		wallet: Arc<Wallet>,
		challenge:  Arc<Mutex<Option<RoundAttemptChallenge>>>
	}
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn subscribe_rounds(
			&self, upstream: &mut ArkClient, req: protos::Empty,
		) -> Result<Box<
			dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
		>, tonic::Status> {
			let stream = upstream.subscribe_rounds(req).await?.into_inner();

			let shared = self.challenge.clone();

			let s = stream.inspect_ok(move |event| {
				if let Some(protos::round_event::Event::Attempt(m)) = &event.event {
					let challenge = RoundAttemptChallenge::new(m.round_attempt_challenge.clone().try_into().unwrap());
					shared.try_lock().unwrap().replace(challenge);
				}
			});

			Ok(Box::new(s))
		}

		// Proxy alters the request to make it vtxo request subdust but correctly signed
		async fn submit_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.vtxo_requests[0].vtxo.as_mut().unwrap().amount = P2TR_DUST_SAT - 1;

			let mut vtxo_requests = Vec::with_capacity(req.vtxo_requests.len());
			for r in &req.vtxo_requests {
				vtxo_requests.push(ark::SignedVtxoRequest {
					vtxo: r.vtxo.clone().unwrap().try_into().unwrap(),
					cosign_pubkey: Some(PublicKey::from_slice(&r.cosign_pubkey).unwrap()),
				});
			}

			// Spending input boarded with first derivation
			let (_, keypair) = self.wallet.pubkey_keypair(&self.vtxo.user_pubkey).unwrap().unwrap();

			let sig = self.challenge.lock().await.as_ref().unwrap().sign_with(
				self.vtxo.id,
				&vtxo_requests,
				&[],
				keypair,
			);

			req.input_vtxos.get_mut(0).unwrap().ownership_proof = sig.serialize().to_vec();

			Ok(upstream.submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy {
		vtxo: vtxo.clone(),
		wallet: Arc::new(bark_client),
		challenge: Arc::new(Mutex::new(None)),
	};
	let proxy = srv.get_proxy_rpc(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	bark.set_timeout(srv.max_round_delay());
	let err = bark.try_refresh_all().await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"bad user input: vtxo amount must be at least 0.00000330 BTC",
	), "err: {err:#}");
}

#[tokio::test]
async fn reject_dust_offboard_request() {
	let ctx = TestContext::new("server/reject_dust_offboard_request").await;
	let srv = ctx.new_captaind("server", None).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_all_and_confirm_and_register(&ctx).await;

	let bark_client = bark.client().await;

	let [vtxo] = bark.vtxos().await.try_into().unwrap();

	#[derive(Clone)]
	struct Proxy {
		pub vtxo: WalletVtxoInfo,
		pub wallet: Arc<Wallet>,
		pub challenge:  Arc<Mutex<Option<RoundAttemptChallenge>>>
	}
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn subscribe_rounds(
			&self, upstream: &mut ArkClient, req: protos::Empty,
		) -> Result<Box<
			dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
		>, tonic::Status> {
			let stream = upstream.subscribe_rounds(req).await?.into_inner();

			let shared = self.challenge.clone();

			let s = stream
				.inspect_ok(move |event| {
					if let Some(protos::round_event::Event::Attempt(m)) = &event.event {
						let challenge = RoundAttemptChallenge::new(m.round_attempt_challenge.clone().try_into().unwrap());
						shared.try_lock().unwrap().replace(challenge);
					}
				});

			Ok(Box::new(s))
		}

		// Proxy alters the request to make it vtxo request subdust but correctly signed
		async fn submit_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.offboard_requests[0].amount = P2TR_DUST_SAT - 1;

			let mut offboard_requests = Vec::with_capacity(req.offboard_requests.len());
			for r in &req.offboard_requests {
				offboard_requests.push(ark::OffboardRequest {
					script_pubkey: ScriptBuf::from_bytes(r.offboard_spk.clone()),
					amount: Amount::from_sat(r.amount),
				});
			}

			// Spending input boarded with first derivation
			let (_, keypair) = self.wallet.pubkey_keypair(&self.vtxo.user_pubkey).unwrap().unwrap();

			let sig = self.challenge.lock().await.as_ref().unwrap().sign_with(
				self.vtxo.id,
				&[],
				&offboard_requests,
				keypair,
			);


			req.input_vtxos.get_mut(0).unwrap().ownership_proof = sig.serialize().to_vec();

			Ok(upstream.submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy {
		vtxo: vtxo.clone(),
		wallet: Arc::new(bark_client),
		challenge: Arc::new(Mutex::new(None)),
	};
	let proxy = srv.get_proxy_rpc(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	bark.set_timeout(srv.max_round_delay());

	let addr = bark.get_onchain_address().await;
	let err = bark.try_offboard_all(&addr).await.unwrap_err();
	assert!(err.to_string().contains("non-standard"), "err: {err}");
}

#[tokio::test]
async fn reject_dust_arkoor_cosign() {
	let ctx = TestContext::new("server/reject_dust_arkoor_cosign").await;
	let srv = ctx.new_captaind("server", None).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_arkoor_package_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.arkoors[0].outputs[0].amount = P2TR_DUST.to_sat() - 1;
			Ok(upstream.request_arkoor_package_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	bark.board_all_and_confirm_and_register(&ctx).await;

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
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningPaymentRequest,
		) -> Result<protos::StartLightningPaymentResponse, tonic::Status> {
			req.user_amount_sat = Some(P2TR_DUST_SAT - 1);
			Ok(upstream.start_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	bark.board_all_and_confirm_and_register(&ctx).await;

	let invoice = lightningd_1.invoice(None, "test_payment", "A test payment").await;
	let err = bark.try_pay_lightning(invoice, Some(sat(100_000))).await.unwrap_err();
	assert!(err.to_string().contains(
		"arkoor output amounts cannot be below the p2tr dust threshold",
	), "err: {err}");
}

#[tokio::test]
async fn server_refuse_claim_invoice_not_settled() {
	let ctx = TestContext::new("server/server_refuse_claim_invoice_not_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn claim_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::ClaimLightningReceiveRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.payment_preimage = vec![1; 32];
			Ok(upstream.claim_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &proxy.address, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = invoice_info.clone();
	tokio::spawn(async move { lightning.sender.pay_bolt11(cloned.invoice).await; });
	let err = bark.try_lightning_receive(invoice_info.invoice).await.unwrap_err();
	assert!(err.to_string().contains("bad user input: preimage doesn't match payment hash"), "err: {err}");
}

#[tokio::test]
async fn server_should_release_hodl_invoice_when_subscription_is_cancelled() {
	let ctx = TestContext::new("server/server_should_release_hodl_invoice_when_subscription_is_cancelled").await;
	let cfg_htlc_subscription_timeout = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
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
	let err = lightning.sender.try_pay_bolt11(invoice_info.invoice).await.unwrap_err();
	assert!(err.to_string().contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");
}

#[tokio::test]
async fn server_should_refuse_claim_twice() {
	let ctx = TestContext::new("server/server_should_refuse_claim_twice").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	bark.lightning_receive(invoice_info.invoice.clone()).wait_millis(10_000).await;

	// Wait for the onboarding round to be deeply enough confirmed
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	// We use that to sync and get onboarded vtxos
	bark.spendable_balance().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(bark.spendable_balance().await, btc(3));

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let pub_nonces = receive.htlc_vtxos.iter()
		.map(|_| musig::nonce_pair(&keypair).1)
		.collect::<Vec<_>>();
	let policy =  VtxoPolicy::new_pubkey(keypair.public_key());

	let err = srv.get_public_rpc().await.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: receive.payment_hash.to_byte_array().to_vec(),
		payment_preimage: receive.payment_preimage.to_vec(),
		vtxo_policy: policy.serialize(),
		user_pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
	}).await.unwrap_err();

	assert!(err.to_string().contains("payment status in incorrect state: settled"), "err: {err}");
}

#[tokio::test]
async fn server_should_refuse_claim_twice_intra_ark_ln_receive() {
	let ctx = TestContext::new("server/server_should_refuse_claim_twice_intra_ark_ln_receive").await;

	trace!("Start lightningd-1");
	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(400_000)).await;

	let invoice_info = bark1.bolt11_invoice(sat(30_000)).await;
	let receive = bark1.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		bark2.pay_lightning(cloned_invoice_info.invoice, None).wait_millis(10_000).await;
	});

	bark1.lightning_receive(invoice_info.invoice.clone()).wait_millis(10_000).await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let pub_nonces = receive.htlc_vtxos.iter()
		.map(|_| musig::nonce_pair(&keypair).1)
		.collect::<Vec<_>>();
	let policy =  VtxoPolicy::new_pubkey(keypair.public_key());

	let err = srv.get_public_rpc().await.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: receive.payment_hash.to_byte_array().to_vec(),
		payment_preimage: receive.payment_preimage.to_vec(),
		vtxo_policy: policy.serialize(),
		user_pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
	}).await.unwrap_err();

	assert!(err.to_string().contains("payment status in incorrect state: settled"), "err: {err}");
}

#[tokio::test]
async fn server_refuse_too_deep_arkoor_input() {
	let ctx = TestContext::new("server/server_refuse_too_deep_arkoor_input").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(1)).await;
	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn get_ark_info(
			&self, upstream: &mut ArkClient, req: protos::Empty,
		) -> Result<protos::ArkInfo, tonic::Status>  {
			let mut info = upstream.get_ark_info(req).await?.into_inner();
			info.max_arkoor_depth = 10;
			Ok(info)
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;

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
	let ctx = TestContext::new("server/should_refuse_paying_invoice_not_matching_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let dummy_invoice = lightning.receiver.invoice(None, "dummy_invoice", "A dummy invoice").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy(String);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn finish_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			req.invoice = self.0.clone();
			Ok(upstream.finish_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy(dummy_invoice)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("htlc payment hash doesn't match invoice"), "err: {err}");
}

#[tokio::test]
async fn should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn finish_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			req.htlc_vtxo_ids.pop();
			Ok(upstream.finish_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board(btc(0.5)).await;
	bark_1.board(btc(0.6)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.maintain().await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None).await.unwrap_err();
	assert!(err.to_string().contains("htlc vtxo amount too low for invoice"), "err: {err}");
}

#[tokio::test]
async fn captaind_config_change(){
	let ctx = TestContext::new("server/captaind_config_change").await;
	let mut srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.vtxo_exit_delta = 12;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	let bark1 = ctx.new_bark("bark1", &srv).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;
	ctx.fund_bark(&bark1, sat(1_000_000)).await;
	ctx.fund_bark(&bark2, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	srv.stop().await.unwrap();

	srv.config_mut().vtxo_exit_delta = 24;

	srv.start().await.unwrap();

	bark1.set_ark_url(&srv).await;
	bark2.set_ark_url(&srv).await;

	// old vtxos still have the same exit_delta

	let vtxos1 = bark1.vtxos().await;
	let vtxos2 = bark2.vtxos().await;
	assert_eq!(vtxos1[0].exit_delta, 12);
	assert_eq!(vtxos2[0].exit_delta, 12);
	assert_eq!(srv.config().vtxo_exit_delta, 24);

	// transactions still work

	bark2.send_oor(&bark1.address().await, sat(330_000)).await;
	bark1.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.send_oor(&bark2.address().await, sat(350_000)).await;

	assert_eq!(bark1.spendable_balance().await, sat(180_000));
	assert_eq!(bark2.spendable_balance().await, sat(820_000));

	// new vtxo should have new exit_delta
	let new_vtxo = bark1.vtxos().await;
	assert_eq!(new_vtxo[0].exit_delta, 24);
}

#[tokio::test]
async fn test_ephemeral_keys() {
	let ctx = TestContext::new("server/test_ephemeral_keys").await;
	let srv = ctx.new_server_with_cfg("server", None, |_| { }).await;
	let db = srv.database();

	let pubkey = srv.generate_ephemeral_cosign_key(secs(60)).await.unwrap().public_key();
	assert_eq!(srv.get_ephemeral_cosign_key(pubkey).await.unwrap().public_key(), pubkey);
	assert_eq!(srv.drop_ephemeral_cosign_key(pubkey).await.unwrap().public_key(), pubkey);
	assert!(db.fetch_ephemeral_tweak(pubkey).await.unwrap().is_none());
	assert!(db.drop_ephemeral_tweak(pubkey).await.unwrap().is_none());

	// let's expire one
	let pubkey = srv.generate_ephemeral_cosign_key(secs(1)).await.unwrap().public_key();
	assert_eq!(srv.get_ephemeral_cosign_key(pubkey).await.unwrap().public_key(), pubkey);
	tokio::time::sleep(Duration::from_millis(1500)).await;
	// to trigger the cleanup
	let _ = srv.generate_ephemeral_cosign_key(secs(1)).await.unwrap().public_key();
	assert!(db.fetch_ephemeral_tweak(pubkey).await.unwrap().is_none());
	assert!(db.drop_ephemeral_tweak(pubkey).await.unwrap().is_none());
}

#[tokio::test]
async fn test_cosign_vtxo_tree() {
	let ctx = TestContext::new("server/test_cosign_vtxo_tree").await;
	let srv = ctx.new_server_with_cfg("server", None, |_| { }).await;
	let db = srv.database();

	let expiry = 100_000;
	let exit_delta = srv.ark_info().vtxo_exit_delta;

	let vtxo_pubkey = "035e160cd261ac8ffcd2866a5aab2116bc90fbefdb1d739531e121eee612583802".parse().unwrap();
	let policy = VtxoPolicy::new_pubkey(vtxo_pubkey);
	let vtxos = (1..5).map(|i| VtxoRequest {
		amount: Amount::from_sat(1000 * i),
		policy: policy.clone(),
	}).collect::<Vec<_>>();

	let user_cosign_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
	let user_cosign_pubkey = user_cosign_key.public_key();

	let server_pubkey = srv.server_pubkey();
	let server_cosign_pubkey = srv.generate_ephemeral_cosign_key(secs(60)).await.unwrap().public_key();

	let builder = SignedTreeBuilder::new(
		vtxos.iter().cloned(), user_cosign_pubkey, expiry, server_pubkey, server_cosign_pubkey, exit_delta,
	);

	let funding_tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![],
		output: vec![builder.funding_txout()],
	};
	let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
	let builder = builder.set_utxo(utxo).generate_user_nonces(&user_cosign_key);
	let user_pub_nonces = builder.user_pub_nonces().to_vec();

	let cosign = srv.cosign_vtxo_tree(
		vtxos.iter().cloned(), user_cosign_pubkey, server_cosign_pubkey, expiry, utxo, user_pub_nonces,
	).await.unwrap();

	builder.verify_cosign_response(&cosign).unwrap();
	let tree = builder.build_tree(&cosign, &user_cosign_key).unwrap();

	srv.register_cosigned_vtxo_tree(
		vtxos.iter().cloned(), user_cosign_pubkey, server_cosign_pubkey, expiry, utxo, tree.cosign_sigs,
	).await.unwrap();

	assert!(db.fetch_ephemeral_tweak(server_cosign_pubkey).await.unwrap().is_none());
}

#[tokio::test]
async fn should_refuse_oor_input_vtxo_that_is_being_exited() {
	let ctx = TestContext::new("server/should_refuse_oor_input_vtxo_that_is_being_exited").await;
	let srv = ctx.new_captaind("server", None).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;


	bark.board(sat(400_000)).await;
	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// We created 2 vtxos, exit A so wallet will be able to spend B. But then we tweak the request to try spending A.
	let [vtxo_a, _vtxo_b] = bark.vtxos().await.try_into().unwrap();

	bark.start_exit_vtxos(&[vtxo_a.id]).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(596_429));

	#[derive(Clone)]
	struct Proxy(VtxoId);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_arkoor_package_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.arkoors[0].input_id = self.0.to_bytes().to_vec();
			Ok(upstream.request_arkoor_package_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy(vtxo_a.id)).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_send_oor(&bark2.address().await, sat(100_000), false).await.unwrap_err();
	assert!(err.to_string().contains(format!("bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id).as_str()), "err: {err}");
}

#[tokio::test]
async fn should_refuse_ln_pay_input_vtxo_that_is_being_exited() {
	let ctx = TestContext::new("server/should_refuse_ln_pay_input_vtxo_that_is_being_exited").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// We created 2 vtxos, exit A so wallet will be able to spend B. But then we tweak the request to try spending A.
	let [vtxo_a, _vtxo_b] = bark.vtxos().await.try_into().unwrap();

	bark.start_exit_vtxos(&[vtxo_a.id]).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(596_429));

	#[derive(Clone)]
	struct Proxy(VtxoId);
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningPaymentRequest,
		) -> Result<protos::StartLightningPaymentResponse, tonic::Status> {
			req.input_vtxo_ids = vec![self.0.to_bytes().to_vec()];
			Ok(upstream.start_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy(vtxo_a.id)).await;

	bark.set_ark_url(&proxy.address).await;

	let invoice = lightningd.invoice(Some(sat(100_000)), "real invoice", "A real invoice").await;

	let err = bark.try_pay_lightning(&invoice, None).await.unwrap_err();
	assert!(err.to_string().contains(format!("bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id).as_str()), "err: {err}");
}

#[tokio::test]
async fn should_refuse_round_input_vtxo_that_is_being_exited() {
	let ctx = TestContext::new("server/should_refuse_round_input_vtxo_that_is_being_exited").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let mut bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// We created 2 vtxos, exit A so wallet will be able to spend B. But then we tweak the request to try spending A.
	let [vtxo_a, _vtxo_b] = bark.vtxos().await.try_into().unwrap();

	bark.start_exit_vtxos(&[vtxo_a.id]).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(596_429));

	#[derive(Clone)]
	struct Proxy {
		pub wallet: Arc<Wallet>,
		pub challenge: Arc<Mutex<Option<RoundAttemptChallenge>>>,
		pub vtxo: WalletVtxoInfo
	}
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn subscribe_rounds(
			&self, upstream: &mut ArkClient, req: protos::Empty,
		) -> Result<Box<
			dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
		>, tonic::Status> {
			let shared = self.challenge.clone();
			let stream = upstream.subscribe_rounds(req).await?.into_inner()
				.inspect_ok(move |event| {
					if let Some(protos::round_event::Event::Attempt(m)) = &event.event {
						let challenge = RoundAttemptChallenge::new(m.round_attempt_challenge.clone().try_into().unwrap());
						shared.try_lock().unwrap().replace(challenge);
					}
				});

			Ok(Box::new(stream))
		}

		async fn submit_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SubmitPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// Spending input boarded with first derivation
			let (_, keypair) = self.wallet.pubkey_keypair(&self.vtxo.user_pubkey).unwrap().unwrap();

			let mut vtxo_requests = Vec::with_capacity(req.vtxo_requests.len());
			for r in &req.vtxo_requests {
				vtxo_requests.push(ark::SignedVtxoRequest {
					vtxo: r.vtxo.clone().unwrap().try_into().unwrap(),
					cosign_pubkey: Some(PublicKey::from_slice(&r.cosign_pubkey).unwrap()),
				});
			}

			let sig = self.challenge.lock().await.as_ref().unwrap().sign_with(
				self.vtxo.id,
				&vtxo_requests,
				&[],
				keypair,
			);

			*req.input_vtxos.get_mut(0).unwrap() = protos::InputVtxo {
				vtxo_id: self.vtxo.id.to_bytes().to_vec(),
				ownership_proof: sig.serialize().to_vec(),
			};

			Ok(upstream.submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy {
		wallet: Arc::new(bark.client().await),
		challenge: Arc::new(Mutex::new(None)),
		vtxo: vtxo_a.clone(),
	};
	let proxy = srv.get_proxy_rpc(proxy).await;

	bark.set_ark_url(&proxy.address).await;
	bark.set_timeout(srv.max_round_delay());

	let err = bark.try_refresh_all().await.unwrap_err();
	assert!(err.to_string().contains(format!("bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id).as_str()), "err: {err}");
}


#[tokio::test]
async fn should_refuse_subdust_lightning_receive_request() {
	let ctx = TestContext::new("server/should_refuse_subdust_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningReceiveRequest,
		) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
			req.amount_sat = P2TR_DUST_SAT - 1;
			Ok(upstream.start_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_bolt11_invoice(sat(30_000)).await.unwrap_err();
	assert!(err.to_string().contains(format!("Requested amount must be at least 0.00000330 BTC").as_str()), "err: {err}");
}

#[tokio::test]
async fn should_refuse_over_max_vtxo_amount_lightning_receive_request() {
	let ctx = TestContext::new("server/should_refuse_over_max_vtxo_amount_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightningd), |cfg| {
		cfg.max_vtxo_amount = Some(sat(1_000_000));
	}).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	#[derive(Clone)]
	struct Proxy;
	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningReceiveRequest,
		) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
			req.amount_sat = 1_000_001;
			Ok(upstream.start_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.get_proxy_rpc(Proxy).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_bolt11_invoice(sat(30_000)).await.unwrap_err();
	assert!(err.to_string().contains(format!("Requested amount exceeds limit of 0.01000000 BTC").as_str()), "err: {err}");
}

#[tokio::test]
async fn server_can_use_multi_input_from_vtxo_pool() {
	let ctx = TestContext::new("server/server_can_use_multi_input_from_vtxo_pool").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 5, amount: sat(100_000) },
		];
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = sat(200_000);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	bark.lightning_receive(invoice_info.invoice.clone()).wait_millis(10_000).await;

	// We use that to sync and get onboarded vtxos
	let balance = bark.spendable_balance().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(balance, pay_amount + board_amount);
}

#[tokio::test]
async fn server_can_use_vtxo_pool_change_for_next_receive() {
	let ctx = TestContext::new("server/server_can_use_vtxo_pool_change_for_next_receive").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 1, amount: sat(100_000) },
		];
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let first_pay_amount = sat(50_000);
	let second_pay_amount = sat(25_000);

	let sender = Arc::new(lightning.sender);

	// First block consumes only vtxo of the pool
	{
		let invoice_info = bark.bolt11_invoice(first_pay_amount).await;

		let cloned_invoice_info = invoice_info.clone();
		let cloned_sender = sender.clone();
		let res1 = tokio::spawn(async move {
			cloned_sender.pay_bolt11(cloned_invoice_info.invoice).await
		});


		bark.lightning_receive(invoice_info.invoice.clone()).wait_millis(10_000).await;
		// HTLC settlement on lightning side
		res1.ready().await.unwrap();
	}

	// Second block consumes change from the first block
	{
		let invoice_info = bark.bolt11_invoice(second_pay_amount).await;

		let cloned_invoice_info = invoice_info.clone();
		let cloned_sender = sender.clone();
		let res1 = tokio::spawn(async move {
			cloned_sender.pay_bolt11(cloned_invoice_info.invoice).await
		});


		bark.lightning_receive(invoice_info.invoice.clone()).wait_millis(10_000).await;
		// HTLC settlement on lightning side
		res1.ready().await.unwrap();
	}

	// We use that to sync and get onboarded vtxos
	let balance = bark.spendable_balance().await;

	assert_eq!(balance, first_pay_amount + second_pay_amount + board_amount);
}
