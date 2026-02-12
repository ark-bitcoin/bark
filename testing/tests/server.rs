
use std::iter;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hex::FromHex;
use bitcoin::{absolute, transaction, Address, Amount, Network, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey, rand::thread_rng};
use bitcoin_ext::P2TR_DUST_SAT;
use bitcoin_ext::rpc::BitcoinRpcExt;
use futures::future::join_all;
use futures::{Stream, StreamExt, TryStreamExt};
use log::{debug, info, trace};
use tokio::sync::{mpsc, Mutex};

use ark::{
	musig, ProtocolEncoding, ServerVtxo, SignedVtxoRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest, SECP
};
use ark::arkoor::{ArkoorCosignRequest, ArkoorDestination};
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignRequest};
use ark::challenges::RoundAttemptChallenge;
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use ark::tree::signed::builder::SignedTreeBuilder;
use ark::tree::signed::{LeafVtxoCosignContext, UnlockPreimage};
use bark::Wallet;
use bark::lightning_invoice::Bolt11Invoice;
use bark_json::primitives::WalletVtxoInfo;
use bark_json::exit::ExitState;
use server::secret::Secret;
use server::vtxopool::VtxoTarget;
use server_log::{
	ForfeitBroadcasted, ForfeitedExitConfirmed, ForfeitedExitInMempool, FullRound,
	RoundError, RoundFinished, RoundUserVtxoAlreadyRegistered, TxIndexUpdateFinished,
};
use server_rpc::protos::{self, lightning_payment_status};

use ark_testing::{Captaind, TestContext, btc, sat, secs, Bark};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{FutureExt, ReceiverExt, ToAltString};

use ark_testing::exit::complete_exit;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

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

	// Use a long round interval to disable automatic rounds, then trigger manually
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_tx_untrusted_input_confirmations = NEED_CONFS as usize;
		cfg.round_interval = Duration::from_secs(3600);
	}).await;
	srv.wait_for_initial_round().await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(srv.wallet_status().await.total().to_sat(), 0);

	// fund server without confirming
	let addr = srv.get_rounds_funding_address().await;
	ctx.bitcoind().fund_addr(addr, btc(10)).await;
	assert_eq!(srv.wallet_status().await.total().to_sat(), 0);

	let mut log_round_err = srv.subscribe_log::<RoundError>();

	// Spawn bark refresh first so it's ready to join the round.
	// The round will fail with "Insufficient funds" because the server's
	// 10 BTC funding is unconfirmed and needs NEED_CONFS confirmations.
	let bark = Arc::new(bark);
	let bark_ref = bark.clone();
	let attempt_handle = tokio::spawn(async move {
		let err = bark_ref.try_refresh_all_with_retries(0).await.unwrap_err();
		debug!("First refresh failed: {:#}", err);
	});

	srv.trigger_round().await;

	let err = log_round_err.recv().wait_millis(30_000).await.unwrap().error;
	assert!(err.contains("Insufficient funds"), "err: {err}");

	attempt_handle.await.unwrap();

	// then confirm the money and it should work
	ctx.generate_blocks(NEED_CONFS).await;
	tokio::time::sleep(Duration::from_millis(3000)).await;

	log_round_err.clear();
	let bark_ref = bark.clone();
	let refresh_handle = tokio::spawn(async move {
		bark_ref.try_refresh_all_no_retry().await
	});
	srv.trigger_round().await;

	refresh_handle.await.unwrap().expect("first refresh failed");

	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// and the unconfirmed change should be able to be used for a second round
	tokio::time::sleep(Duration::from_millis(2000)).await;

	let bark_ref = bark.clone();
	let refresh_handle = tokio::spawn(async move {
		bark_ref.try_refresh_all_no_retry().await
	});
	srv.trigger_round().await;

	refresh_handle.await.unwrap().expect("second refresh failed");
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

#[ignore]
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
	let err = bark1.try_board(Amount::from_sat(600_000)).await.unwrap_err().to_alt_string();
	assert!(err.contains(
		&format!("bad user input: board amount exceeds limit of {}", cfg_max_amount)
	), "err: {err}");

	bark1.board(Amount::from_sat(500_000)).await;
	bark1.board(Amount::from_sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// then try send in a round
	bark1.set_timeout(srv.max_round_delay());
	let err = bark1.try_refresh_all_no_retry().await.unwrap_err().to_alt_string();
	assert!(err.contains(
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
		cfg.round_interval = Duration::from_millis(100_000_000);
		cfg.round_submit_time = Duration::from_millis(15_000);
		cfg.round_sign_time = Duration::from_millis(10_000);
		cfg.nb_round_nonces = 2;
		cfg.min_board_amount = sat(0);
	}).await;
	srv.wait_for_initial_round().await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// based on nb_round_nonces
	const MAX_OUTPUTS: usize = 16; // 4**cfg.nb_round_nonces
	assert_eq!(MAX_OUTPUTS, 4usize.pow(srv.config().nb_round_nonces as u32));
	const NB_BARKS: usize = 17;
	assert!(NB_BARKS > MAX_OUTPUTS);

	// Since we can have 16 outputs, we will create 17 barks with 1 output each.

	let barks = join_all((1..=NB_BARKS).map(|i| {
		let name = format!("bark{}", i);
		ctx.new_bark_with_funds(name, &srv, sat(40_000))
	})).await;
	ctx.generate_blocks(1).await;

	// board their funds
	futures::future::join_all(barks.iter().map(|bark| async {
		bark.board(sat(1_000)).await;
	})).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let (tx, mut rx) = mpsc::unbounded_channel();

	/// This proxy will keep track of how many times `submit payment` has been called.
	/// Once it reaches MAX_OUTPUTS, it asserts the next one fails.
	/// Once that happened succesfully, it fullfils the result channel.
	#[derive(Clone)]
	struct Proxy(Arc<Mutex<usize>>, Arc<mpsc::UnboundedSender<tonic::Status>>);
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, req: protos::SubmitPaymentRequest,
		) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
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
	let proxy = srv.start_proxy_no_mailbox(proxy).await;
	futures::future::join_all(barks.iter().map(|bark| bark.set_ark_url(&proxy))).await;

	let mut log_full = srv.subscribe_log::<FullRound>();
	srv.trigger_round().await;
	tokio::spawn(async move {
		futures::future::join_all(barks.iter().map(|bark| async {
			// ignoring error as last one will fail
			let _ = bark.refresh_all_no_retry().await;
		})).await;
	});

	let full = log_full.recv().await.unwrap();
	assert_eq!(full.max_output_vtxos, MAX_OUTPUTS);

	// then we wait for the error to happen
	let err = rx.recv().wait_millis(30_000).await.unwrap().to_alt_string();
	assert!(err.contains("Message arrived late or round was full"), "err: {err}");
}

#[tokio::test]
async fn double_spend_arkoor() {
	let ctx = TestContext::new("server/double_spend_arkoor").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	// Instantiate bark
	let bark = ctx.new_bark_with_funds("bark".to_string(), &srv, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark_client = bark.client().await;
	bark_client.maintenance().await.unwrap();

	// Let's try to construct a few conflicting arkoor transactions
	let vtxo = bark_client.vtxos().await
		.unwrap().into_iter().next().unwrap().vtxo;
	let vtxo_keypair = bark_client.pubkey_keypair(&vtxo.user_pubkey()).await
		.unwrap().unwrap().1;

	let pk1 = bark_client.derive_store_next_keypair().await.unwrap().0.public_key();
	let pk2 = bark_client.derive_store_next_keypair().await.unwrap().0.public_key();

	let builder1 = ArkoorPackageBuilder::new_single_output_with_checkpoints(
		[vtxo.clone()],
		ArkoorDestination {
			total_amount: sat(100_000),
			policy: VtxoPolicy::new_pubkey(*RANDOM_PK),
		},
		VtxoPolicy::new_pubkey(pk1),
	).unwrap();
	let builder2 = ArkoorPackageBuilder::new_single_output_with_checkpoints(
		[vtxo.clone()],
		ArkoorDestination {
			total_amount: sat(200_000), // other amount
			policy: VtxoPolicy::new_pubkey(*RANDOM_PK),
		},
		VtxoPolicy::new_pubkey(pk1),
	).unwrap();
	let builder3 = ArkoorPackageBuilder::new_single_output_with_checkpoints(
		[vtxo.clone()],
		ArkoorDestination {
			total_amount: sat(100_000),
			policy: VtxoPolicy::new_pubkey(*RANDOM_PK),
		},
		VtxoPolicy::new_pubkey(pk2), // other change pk
	).unwrap();

	// And the corresponding requests to the server
	use protos::ArkoorPackageCosignRequest;
	let req1: ArkoorPackageCosignRequest = builder1
		.generate_user_nonces(&[vtxo_keypair]).unwrap()
		.cosign_request()
		.convert_vtxo(|vtxo| vtxo.id())
		.into();

	let req2: ArkoorPackageCosignRequest = builder2
		.generate_user_nonces(&[vtxo_keypair]).unwrap()
		.cosign_request()
		.convert_vtxo(|vtxo| vtxo.id())
		.into();

	let req3: ArkoorPackageCosignRequest = builder3
		.generate_user_nonces(&[vtxo_keypair]).unwrap()
		.cosign_request()
		.convert_vtxo(|vtxo| vtxo.id())
		.into();

	// Create 3 rpc-clients so we can send 3 requests in paralel
	let mut rpc1 = srv.get_public_rpc().await;
	let mut rpc2 = srv.get_public_rpc().await;
	let mut rpc3 = srv.get_public_rpc().await;

	let (r1, r2, r3)  = tokio::join!(
		rpc1.request_arkoor_cosign(req1.clone()),
		rpc2.request_arkoor_cosign(req2.clone()),
		rpc3.request_arkoor_cosign(req3.clone()),
	);

	let succeeded = match (r1, r2, r3) {
		(Ok(_), Err(_), Err(_)) => 1,
		(Err(_), Ok(_), Err(_)) => 2,
		(Err(_), Err(_), Ok(_)) => 3,
		(a, b, c) => panic!("Only one request should succeed {:?}, {:?}, {:?}", a, b, c),
	};

	// Make the same set of requests again, this time in sequence to avoid the flux lock
	// We want idempotency
	let r1 = rpc1.request_arkoor_cosign(req1.clone()).await;
	let r2 = rpc2.request_arkoor_cosign(req2.clone()).await;
	let r3 = rpc3.request_arkoor_cosign(req3.clone()).await;

	match (r1, r2, r3) {
		(Ok(_), Err(_), Err(_)) => assert_eq!(succeeded, 1, "Different requests succeeded"),
		(Err(_), Ok(_), Err(_)) => assert_eq!(succeeded, 2, "Different requests succeeded"),
		(Err(_), Err(_), Ok(_)) => assert_eq!(succeeded, 3, "Different requests succeeded"),
		(a, b, c) => panic!("Only one request should succeed {:?}, {:?}, {:?}", a, b, c),
	}
}

#[tokio::test]
async fn double_spend_round() {
	let ctx = TestContext::new("server/double_spend_round").await;

	/// This proxy will duplicate all round payment submission requests.
	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, mut req: protos::SubmitPaymentRequest,
		) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
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
			Ok(res1.unwrap().into_inner())
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyA {
		async fn submit_payment(
			&self, upstream: &mut ArkClient, _req: protos::SubmitPaymentRequest,
		) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
			upstream.provide_vtxo_signatures(protos::VtxoSignaturesRequest {
				pubkey: RANDOM_PK.serialize().to_vec(), signatures: vec![]
			}).await?;
			Ok(protos::SubmitPaymentResponse {
				unlock_hash: rand::random::<[u8; 32]>().to_vec(),
			})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(ProxyA).await;
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all_no_retry().await.expect_err("refresh should time out").to_alt_string();
	assert!(err.contains("current step is payment registration"), "err: {err}");

	/// This proxy will send a `submit_payment` req instead of `provide_vtxo_signatures` one
	#[derive(Clone)]
	struct ProxyB;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for ProxyB {
		async fn provide_vtxo_signatures(
			&self, upstream: &mut ArkClient, _req: protos::VtxoSignaturesRequest,
		) -> Result<protos::Empty, tonic::Status> {
			upstream.submit_payment(protos::SubmitPaymentRequest {
				input_vtxos: vec![],
				vtxo_requests: vec![],
				#[allow(deprecated)]
				offboard_requests: vec![],
			}).await?;
			Ok(protos::Empty{})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(ProxyB).await;
	bark.set_timeout(srv.max_round_delay());
	bark.set_ark_url(&proxy).await;
	let err = bark.try_refresh_all_no_retry().await.expect_err("refresh should fail").to_alt_string();
	assert!(err.contains("Message arrived late or round was full."), "err: {err}");
}

#[tokio::test]
async fn spend_unregistered_board() {
	let ctx = TestContext::new("server/spend_unregistered_board").await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, _upstream: &mut ArkClient, _req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// drop the request
			Ok(protos::Empty{})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let err = bark.try_refresh_all_no_retry().await.unwrap_err().to_alt_string();
	assert!(err.contains("failed to register vtxos"), "err: {err}");
}

#[tokio::test]
async fn reject_revocation_on_successful_lightning_payment() {
	let ctx = TestContext::new("server/reject_revocation_on_successful_lightning_payment").await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn check_lightning_payment(
			&self, upstream: &mut ArkClient,
			req: protos::CheckLightningPaymentRequest,
		) -> Result<protos::LightningPaymentStatus, tonic::Status> {
			let res = upstream.check_lightning_payment(req).await?.into_inner();
			let status = res.payment_status.unwrap();

			match status {
				lightning_payment_status::PaymentStatus::Pending(_) => {
					Ok(protos::LightningPaymentStatus {
						payment_status: Some(lightning_payment_status::PaymentStatus::Pending(protos::Empty {})),
					})
				},
				_ => {
					Ok(protos::LightningPaymentStatus {
						payment_status: Some(lightning_payment_status::PaymentStatus::Failed(protos::Empty {})),
					})
				},
			}
		}
	}

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	assert_eq!(bark_1.spendable_balance().await, board_amount);
	let err = bark_1.try_pay_lightning(invoice, None, true).await.unwrap_err().to_alt_string();
	assert!(err.contains("This lightning payment has completed. preimage: "), "err: {err}");
}

#[tokio::test]
async fn bad_round_input() {
	let ctx = TestContext::new("server/bad_round_input").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(10000000);
		cfg.round_submit_time = Duration::from_secs(30);
	}).await;
	srv.wait_for_initial_round().await;
	let bark = ctx.new_bark_with_funds("bark", &srv, btc(1)).await;
	bark.board_and_confirm_and_register(&ctx, btc(0.5)).await;
	let [vtxo] = bark.client().await.spendable_vtxos().await
		.unwrap().try_into().unwrap();

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
		cosign_pubkey: key2.public_key(),
		nonces: vec![],
	};

	let input = protos::InputVtxo {
		vtxo_id: vtxo.id().to_bytes().to_vec(),
		ownership_proof: challenge
			.sign_with(vtxo.id(), &[vtxo_req.clone()], &key)
			.serialize().to_vec(),
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
		#[allow(deprecated)]
		offboard_requests: vec![],
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![],
		vtxo_requests: vec![],
		#[allow(deprecated)]
		offboard_requests: vec![],
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());

	info!("no outputs");
	let err = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![input.clone()],
		vtxo_requests: vec![],
		#[allow(deprecated)]
		offboard_requests: vec![],
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "[{}]: {}", err.code(), err.message());
	assert!(err.message().contains("invalid request: no outputs"),
		"[{}]: {}", err.code(), err.message(),
	);

	info!("unknown input");
	let fake_vtxo = VtxoId::from_slice(&rand::random::<[u8; 36]>()[..]).unwrap();
	let fake_input = protos::InputVtxo {
		vtxo_id: fake_vtxo.to_bytes().to_vec(),
		ownership_proof: challenge.sign_with(
			vtxo.id(), &[vtxo_req.clone()], &key,
		).serialize().to_vec(),
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
		#[allow(deprecated)]
		offboard_requests: vec![],
	}).ready().await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::NotFound, "[{}]: {}", err.code(), err.message());
	assert_eq!(err.metadata().get("identifiers").unwrap().to_str().unwrap(), fake_vtxo.to_string());
}

#[derive(Clone)]
struct NoFinishRoundProxy;
#[async_trait::async_trait]
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

#[ignore]
#[tokio::test]
async fn claim_forfeit_connector_chain() {
	let ctx = TestContext::new("server/claim_forfeit_connector_chain").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.start_proxy_no_mailbox(NoFinishRoundProxy).await;

	// To make sure we have a chain of connector, we make a bunch of inputs
	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(5_000_000)).await;
	for _ in 0..10 {
		bark.board(sat(400_000)).await;
	}
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let vtxo = bark.vtxos().await.into_iter().next().unwrap();
	let mut log_round = srv.subscribe_log::<RoundFinished>();
	assert!(bark.try_refresh_all_no_retry().await.is_err());
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

#[ignore]
#[tokio::test]
async fn claim_forfeit_round_connector() {
	//! Special case of the forfeit caim test where the connector output is on the round tx
	let ctx = TestContext::new("server/claim_forfeit_round_connector").await;

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let proxy = srv.start_proxy_no_mailbox(NoFinishRoundProxy).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &proxy.address, sat(1_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// we do a refresh, but make it seem to the client that it failed
	let [vtxo] = bark.vtxos().await.try_into().expect("1 vtxo");
	let mut log_round = srv.subscribe_log::<RoundFinished>();
	assert!(bark.try_refresh_all_no_retry().await.is_err());
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
async fn reject_dust_board_cosign() {
	let ctx = TestContext::new("server/reject_dust_board_cosign").await;
	// Need to set the `min_board_amount` less than dust to check we
	// reject signing on dust always.
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.min_board_amount = sat(0);
	}).await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_board_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::BoardCosignRequest,
		) -> Result<protos::BoardCosignResponse, tonic::Status> {
			req.amount = P2TR_DUST_SAT - 1;
			Ok(upstream.request_board_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(1_000_000)).await;

	let err = bark.try_board_all().await.unwrap_err().to_alt_string();
	assert!(err.contains(
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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_board_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::BoardCosignRequest,
		) -> Result<protos::BoardCosignResponse, tonic::Status> {
			req.amount = MIN_BOARD_AMOUNT_SATS - 1;
			Ok(upstream.request_board_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;
	let bark = ctx.new_bark_with_funds("bark", &proxy.address, sat(100_000)).await;

	let err = bark.try_board_all().await.unwrap_err().to_alt_string();
	assert!(err.contains(
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
	#[async_trait::async_trait]
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
		) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
			req.vtxo_requests[0].vtxo.as_mut().unwrap().amount = P2TR_DUST_SAT - 1;

			let vtxo_requests = req.vtxo_requests.iter().map(|r| {
				SignedVtxoRequest {
					vtxo: r.vtxo.clone().unwrap().try_into().unwrap(),
					cosign_pubkey: PublicKey::from_slice(&r.cosign_pubkey).unwrap(),
					nonces: vec![],
				}
			}).collect::<Vec<_>>();

			// Spending input boarded with first derivation
			let (_, keypair) = self.wallet.pubkey_keypair(&self.vtxo.user_pubkey).await.unwrap().unwrap();

			let sig = self.challenge.lock().await.as_ref().unwrap()
				.sign_with(self.vtxo.id, &vtxo_requests, &keypair);

			req.input_vtxos.get_mut(0).unwrap().ownership_proof = sig.serialize().to_vec();

			Ok(upstream.submit_payment(req).await?.into_inner())
		}
	}

	let proxy = Proxy {
		vtxo: vtxo.clone(),
		wallet: Arc::new(bark_client),
		challenge: Arc::new(Mutex::new(None)),
	};
	let proxy = srv.start_proxy_no_mailbox(proxy).await;

	bark.set_ark_url(&proxy.address).await;

	bark.set_timeout(srv.max_round_delay());
	let err = bark.try_refresh_all_no_retry().await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"bad user input: vtxo amount must be at least 0.00000330 BTC",
	), "err: {err:#}");
}

#[tokio::test]
async fn server_refuse_claim_invoice_not_settled() {
	let ctx = TestContext::new("server/server_refuse_claim_invoice_not_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn claim_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::ClaimLightningReceiveRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.payment_preimage = vec![1; 32];
			Ok(upstream.claim_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &proxy.address, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = invoice_info.clone();
	tokio::spawn(async move { lightning.sender.pay_bolt11(cloned.invoice).await; });
	let err = bark.try_lightning_receive(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: preimage doesn't match payment hash"), "err: {err}");
}

#[tokio::test]
async fn server_should_release_hold_invoice_when_subscription_is_canceled() {
	let ctx = TestContext::new("server/server_should_release_hold_invoice_when_subscription_is_canceled").await;
	let cfg_htlc_forward_timeout = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// Set the receive_htlc_forward_timeout very short so the subscription
		// gets canceled quickly when the receiver doesn't prepare the claim
		cfg.receive_htlc_forward_timeout = cfg_htlc_forward_timeout
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	// Spawn the payment - it will be held by the server until claimed or canceled
	let cloned_invoice_info = invoice_info.clone();
	let sender = Arc::new(lightning.sender);
	let cloned_sender = sender.clone();
	let payment_result = tokio::spawn(async move {
		cloned_sender.try_pay_bolt11(cloned_invoice_info.invoice).await
	});

	// Wait for the HTLC forward timeout to elapse plus time for server to process
	tokio::time::sleep(cfg_htlc_forward_timeout + srv.config().invoice_check_interval).await;

	// The payment should fail because the subscription was canceled (receiver didn't claim)
	let err = payment_result.await.unwrap().unwrap_err().to_alt_string();
	assert!(err.contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");

	// Verify the hold invoice was released by trying to pay again - should also fail
	let err = sender.try_pay_bolt11(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");
}

#[tokio::test]
async fn server_generated_invoice_has_configured_expiry() {
	let ctx = TestContext::new("server/server_generated_invoice_has_configured_expiry").await;
	let cfg_invoice_expiry = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// Set invoice expiry very short so invoice expires quickly
		cfg.invoice_expiry = cfg_invoice_expiry;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let payment_hash = invoice.payment_hash().to_byte_array().to_vec();

	// Wait for the invoice to expire and for the server to process the cancellation
	tokio::time::sleep(cfg_invoice_expiry + srv.config().invoice_check_interval).await;

	// Verify the server has canceled the HTLC subscription due to invoice expiry
	let mut rpc = srv.get_public_rpc().await;
	let resp = rpc.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: payment_hash,
		wait: false,
	}).await.unwrap().into_inner();
	assert_eq!(resp.status, protos::LightningReceiveStatus::Canceled as i32,
		"expected CANCELED status, got {:?}", resp.status);

	// Sender also rejects expired invoice, confirming expiry was set correctly in the invoice
	let err = lightning.sender.try_pay_bolt11(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("Invoice expired"), "err: {err}");
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
	let policy =  VtxoPolicy::new_pubkey(keypair.public_key());
	let cosign_req = ArkoorPackageCosignRequest { requests: Vec::<ArkoorCosignRequest<VtxoId>>::new() };

	let err = srv.get_public_rpc().await.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: receive.payment_hash.to_byte_array().to_vec(),
		payment_preimage: receive.payment_preimage.to_vec(),
		vtxo_policy: policy.serialize(),
		cosign_request: Some(cosign_req.into()),
	}).await.unwrap_err().to_alt_string();

	assert!(err.contains("payment status in incorrect state: settled"), "err: {err}");
}

#[tokio::test]
async fn server_returned_htlc_recv_vtxos_should_be_identical_cln() {
	let ctx = TestContext::new("server/server_returned_htlc_recv_vtxos_should_be_identical_cln").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();

	let mut client = srv.get_public_rpc().await;

	// Need to initiate payment for server to return htlc vtxos
	tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	// Wait for the payment to be received
	client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: receive.payment_hash.to_vec(),
		wait: true,
	}).wait_millis(10_000).await.unwrap().into_inner();

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_1 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};
	let vtxos_1 = client.prepare_lightning_receive_claim(req_1.clone()).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	// We test once again with the same request
	let vtxos_2 = client.prepare_lightning_receive_claim(req_1).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	// we change keypair to make sure server don't use it on second request
	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_2 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};

	let vtxos_3 = client.prepare_lightning_receive_claim(req_2).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	assert_eq!(vtxos_1, vtxos_2, "should have the same VTXOs");
	assert_eq!(vtxos_1, vtxos_3, "should have the same VTXOs");
}

#[tokio::test]
async fn server_returned_htlc_recv_vtxos_should_be_identical_intra_ark() {
	let ctx = TestContext::new("server/server_returned_htlc_recv_vtxos_should_be_identical_intra_ark").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await;
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark-2", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;
	bark2.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();

	let mut client = srv.get_public_rpc().await;

	// Need to initiate payment for server to return htlc vtxos
	tokio::spawn(async move {
		bark2.pay_lightning(cloned_invoice_info.invoice, None).wait_millis(10_000).await;
	});

	// Wait for the payment to be received
	client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: receive.payment_hash.to_vec(),
		wait: true,
	}).wait_millis(10_000).await.unwrap().into_inner();

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_1 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};
	let vtxos_1 = client.prepare_lightning_receive_claim(req_1.clone()).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	// We test once again with the same request
	let vtxos_2 = client.prepare_lightning_receive_claim(req_1).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	// we change keypair to make sure server don't use it on second request
	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_2 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};

	let vtxos_3 = client.prepare_lightning_receive_claim(req_2).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo>, _>>().unwrap();

	assert_eq!(vtxos_1, vtxos_2, "should have the same VTXOs");
	assert_eq!(vtxos_1, vtxos_3, "should have the same VTXOs");
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
	let policy =  VtxoPolicy::new_pubkey(keypair.public_key());
	let cosign_req = ArkoorPackageCosignRequest { requests: Vec::<ArkoorCosignRequest<VtxoId>>::new() };

	let err = srv.get_public_rpc().await.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: receive.payment_hash.to_byte_array().to_vec(),
		payment_preimage: receive.payment_preimage.to_vec(),
		vtxo_policy: policy.serialize(),
		cosign_request: Some(cosign_req.into()),
	}).await.unwrap_err().to_alt_string();

	assert!(err.contains("payment status in incorrect state: settled"), "err: {err}");
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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.invoice = self.0.clone();
			Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(dummy_invoice)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains("htlc payment hash doesn't match invoice"), "err: {err}");
}

#[tokio::test]
async fn should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.htlc_vtxo_ids.pop();
			Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board(btc(0.5)).await;
	bark_1.board(btc(0.6)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.maintain().await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains("htlc vtxo amount too low for invoice"), "err: {err}");
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

	let expiry = 100_000;
	let exit_delta = srv.ark_info().vtxo_exit_delta;

	let vtxo_key = Keypair::from_str("b44d09e86c02df6b57b6e92ac1c63b72c8781d5ed90d6f42073e4f47945d9e0d").unwrap();
	let policy = VtxoPolicy::new_pubkey(vtxo_key.public_key());
	let vtxos = (1..5).map(|i| VtxoRequest {
		amount: Amount::from_sat(1000 * i),
		policy: policy.clone(),
	}).collect::<Vec<_>>();

	let user_cosign_key = Keypair::from_str("5255d132d6ec7d4fc2a41c8f0018bb14343489ddd0344025cc60c7aa2b3fda6a").unwrap();
	let user_cosign_pubkey = user_cosign_key.public_key();
	let unlock_preimge = rand::random::<UnlockPreimage>();

	let server_pubkey = srv.server_pubkey();
	let server_cosign_pubkey = srv.generate_ephemeral_cosign_key(secs(60)).await.unwrap().public_key();

	let builder = SignedTreeBuilder::new(
		vtxos.iter().cloned(), user_cosign_pubkey, unlock_preimge, expiry, server_pubkey,
		server_cosign_pubkey, exit_delta,
	).unwrap();

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
		vtxos.iter().cloned(), user_cosign_pubkey, unlock_preimge, server_cosign_pubkey, expiry,
		utxo, user_pub_nonces,
	).await.unwrap();

	builder.verify_cosign_response(&cosign).unwrap();
	let tree = builder.build_tree(&cosign, &user_cosign_key).unwrap();

	let mut vtxos = tree.into_cached_tree().output_vtxos().collect::<Vec<_>>();
	for vtxo in vtxos.iter_mut() {
		let (ctx, req) = LeafVtxoCosignContext::new(vtxo, &funding_tx, &vtxo_key);
		let resp = srv.cosign_hashlocked_leaf(&req, vtxo, &funding_tx);
		assert!(ctx.finalize(vtxo, resp));
	}

	let vtxos = vtxos.into_iter().map(ServerVtxo::from).collect::<Vec<_>>();
	srv.register_vtxos(&vtxos).await.unwrap();
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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_arkoor_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.parts[0].input_vtxo_id = self.0.to_bytes().to_vec();
			Ok(upstream.request_arkoor_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(vtxo_a.id)).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_send_oor(&bark2.address().await, sat(100_000), false).await
		.expect_err("Server should refuse oor").to_alt_string();
	assert!(err.contains(
		&format!("bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id)
	), "err: {err}");
}

#[tokio::test]
async fn mailbox_post_and_process_with_auth() {
	let ctx = TestContext::new("server/mailbox_post_and_process_with_auth").await;
	let srv = ctx.new_captaind("server", None).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	let _board = bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark2 = ctx.new_bark("bark2", &srv).await;
	let bark2_mailbox_kp = bark2.client().await.mailbox_keypair().unwrap();

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;

	let mailbox_id = MailboxIdentifier::from_pubkey(bark2_mailbox_kp.public_key());
	let unblinded_id = mailbox_id.to_vec();
	let expiry_ok = chrono::Local::now() + Duration::from_secs(60);
	let mailbox_auth = MailboxAuthorization::new(&bark2_mailbox_kp, expiry_ok);
	let authorization = Some(mailbox_auth.serialize().to_vec());

	let read_mailbox = protos::mailbox_server::MailboxRequest {
		authorization,
		unblinded_id: unblinded_id.clone(),
		checkpoint: 0,
	};

	// First, we check that everything is ok with correct authorization
	trace!("reading empty mailbox");
	let mailbox_msgs = mb_rpc.read_mailbox(read_mailbox.clone()).await.unwrap().into_inner();
	assert_eq!(mailbox_msgs.messages.len(), 0);

	trace!("starting subscribe mailbox");
	let mut stream = mb_rpc.subscribe_mailbox(read_mailbox.clone()).await.unwrap().into_inner();

	let addr = bark2.address().await;
	// Send arkoor package to mailbox
	let sent_amount = sat(100_000);
	bark.send_oor(addr, sent_amount).await;

	let mut read_vtxo = None::<Vtxo<VtxoPolicy>>;

	trace!("reading mailbox");
	let mailbox_msgs = mb_rpc.read_mailbox(read_mailbox).await.unwrap().into_inner();
	assert_eq!(mailbox_msgs.messages.len(), 1);
	match mailbox_msgs.messages[0].message.as_ref().unwrap() {
		Message::Arkoor(arkoor) => {
			assert_eq!(arkoor.vtxos.len(), 1);
			let vtxo = Vtxo::<VtxoPolicy>::deserialize(&arkoor.vtxos[0]).unwrap();
			assert_eq!(vtxo.amount(), sent_amount);
			let _ = read_vtxo.insert(vtxo);
		},
	}

	// Now we check that the server rejects requests with incorrect authorization
	let invalid_as_mailbox_kp = bark2.client().await.derive_store_next_keypair().await
		.expect("derive keypair").0;
	let invalid_mailbox_auth = MailboxAuthorization::new(&invalid_as_mailbox_kp, expiry_ok);
	let invalid_authorization = Some(invalid_mailbox_auth.serialize().to_vec());

	let incorrect_read_mailbox = protos::mailbox_server::MailboxRequest {
		authorization: invalid_authorization,
		unblinded_id: unblinded_id.clone(),
		checkpoint: 0,
	};

	trace!("reading mailbox incorrect authorization");
	let err = mb_rpc.read_mailbox(incorrect_read_mailbox.clone()).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: authorization doesn't match mailbox id"), "err: {err}");

	trace!("subscribing mailbox incorrect authorization");
	let err = mb_rpc.subscribe_mailbox(incorrect_read_mailbox).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: authorization doesn't match mailbox id"), "err: {err}");

	// Now we check that the server rejects requests with expired authorization
	let expiry_expired = chrono::Local::now() - Duration::from_secs(60);
	let expired_mailbox_auth = MailboxAuthorization::new(&bark2_mailbox_kp, expiry_expired);
	let expired_authorization = Some(expired_mailbox_auth.serialize().to_vec());

	let expired_read_mailbox = protos::mailbox_server::MailboxRequest {
		authorization: expired_authorization.clone(),
		unblinded_id: unblinded_id.clone(),
		checkpoint: 0,
	};

	trace!("reading mailbox expired authorization");
	let err = mb_rpc.read_mailbox(expired_read_mailbox.clone()).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: mailbox authorization expired"), "err: {err}");

	trace!("subscribing mailbox expired authorization");
	let err = mb_rpc.subscribe_mailbox(expired_read_mailbox).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: mailbox authorization expired"), "err: {err}");

	// Now we check that the server rejects requests with no authorization
	let no_auth_read_mailbox = protos::mailbox_server::MailboxRequest {
		authorization: None,
		unblinded_id: unblinded_id.clone(),
		checkpoint: 0,
	};

	trace!("reading mailbox without authorization");
	let err = mb_rpc.read_mailbox(no_auth_read_mailbox.clone()).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: mailbox authorization required"), "err: {err}");

	trace!("subscribing mailbox without authorization");
	let err = mb_rpc.subscribe_mailbox(no_auth_read_mailbox).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: mailbox authorization required"), "err: {err}");

	trace!("processing mailbox");
	loop {
		match stream.next().await.unwrap().unwrap() {
			protos::mailbox_server::MailboxMessage { checkpoint, message } => {
				match message.unwrap() {
					Message::Arkoor(arkoor) => {
						assert_eq!(arkoor.vtxos.len(), 1);
						let vtxo = Vtxo::<VtxoPolicy>::deserialize(&arkoor.vtxos[0]).unwrap();
						assert_eq!(read_vtxo.unwrap(), vtxo);
					},
				}
				assert_ne!(checkpoint, 0);
				return
			},
		}
	}
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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_lightning_pay_htlc_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::LightningPayHtlcCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.parts[0].input_vtxo_id = self.0.to_bytes().to_vec();
			Ok(upstream.request_lightning_pay_htlc_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(vtxo_a.id)).await;

	bark.set_ark_url(&proxy.address).await;

	let invoice = lightningd.invoice(Some(sat(100_000)), "real invoice", "A real invoice").await;

	let err = bark.try_pay_lightning(&invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains(&format!(
		"bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id,
	)), "err: {err}");
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
	#[async_trait::async_trait]
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
		) -> Result<protos::SubmitPaymentResponse, tonic::Status> {
			// Spending input boarded with first derivation
			let (_, keypair) = self.wallet.pubkey_keypair(&self.vtxo.user_pubkey).await.unwrap().unwrap();

			let vtxo_requests = req.vtxo_requests.iter().map(|r| {
				SignedVtxoRequest {
					vtxo: r.vtxo.clone().unwrap().try_into().unwrap(),
					cosign_pubkey: PublicKey::from_slice(&r.cosign_pubkey).unwrap(),
					nonces: vec![],
				}
			}).collect::<Vec<_>>();

			let sig = self.challenge.lock().await.as_ref().unwrap()
				.sign_with(self.vtxo.id, &vtxo_requests, &keypair);

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
	let proxy = srv.start_proxy_no_mailbox(proxy).await;

	bark.set_ark_url(&proxy.address).await;
	bark.set_timeout(srv.max_round_delay());

	let err = bark.try_refresh_all_no_retry().await.unwrap_err().to_alt_string();
	assert!(err.contains(&format!(
		"bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id,
	)), "err: {err:#}");
}


#[tokio::test]
async fn should_allow_dust_lightning_receive_request() {
	let ctx = TestContext::new("server/should_allow_dust_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark.try_bolt11_invoice(sat(300)).await.unwrap();
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
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningReceiveRequest,
		) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
			req.amount_sat = 1_000_001;
			Ok(upstream.start_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_bolt11_invoice(sat(30_000)).await.unwrap_err().to_alt_string();
	assert!(err.contains("Requested amount exceeds limit of 0.01000000 BTC"), "err: {err}");
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
			VtxoTarget { count: 5, amount: sat(100_000) },
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

/// Tests the register_board endpoint.
///
/// This test covers:
/// - Registering a valid board
/// - Idempotency (registering the same board multiple times)
/// - Rejecting an unconfirmed board
/// - Rejecting a board with wrong server pubkey
#[tokio::test]
async fn test_register_board() {
	let ctx = TestContext::new("server/test_register_board").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.required_board_confirmations = 6;
	}).await;

	// Create keypair for the board cosigning
	let client_cosign_keypair = Keypair::new(&*SECP, &mut thread_rng());

	// Get server info and calculate expiry height
	let ark_info = srv.ark_info().await;
	let current_height = ctx.bitcoind().get_block_count().await as u32;
	let expiry_height = current_height + ark_info.vtxo_expiry_delta as u32;

	// Create a board builder to get the funding script
	let board_amount = sat(100_000);
	let board_fee = Amount::ZERO;
	let board_builder = ark::board::BoardBuilder::new(
		client_cosign_keypair.public_key(),
		expiry_height,
		ark_info.server_pubkey,
		ark_info.vtxo_exit_delta,
	);

	// Create the funding tx that pays to the board's funding script
	// NB: In production, you should get the server's cosignature BEFORE funding.
	// We're doing it backwards here because this is a test and we like to live dangerously.
	// Don't copy this code unless you enjoy losing money.
	let funding_script = board_builder.funding_script_pubkey();
	let funding_address = Address::from_script(&funding_script, Network::Regtest).unwrap();
	let funding_txid = ctx.bitcoind().fund_addr(&funding_address, board_amount).await;
	let funding_tx = ctx.bitcoind().await_transaction(funding_txid).await;
	let vout = funding_tx.output.iter().position(|o| o.script_pubkey == funding_script).unwrap();
	let board_utxo = OutPoint::new(funding_txid, vout as u32);

	// Set funding details and generate nonces
	let board_builder = board_builder
		.set_funding_details(board_amount, board_fee, board_utxo).unwrap()
		.generate_user_nonces();

	// Request server to cosign the board
	let cosign_request = protos::BoardCosignRequest {
		amount: board_amount.to_sat(),
		utxo: board_utxo.serialize(),
		expiry_height,
		user_pubkey: client_cosign_keypair.public_key().serialize().to_vec(),
		pub_nonce: board_builder.user_pub_nonce().serialize().to_vec(),
	};

	let mut rpc = srv.get_public_rpc().await;
	let cosign_response = rpc.request_board_cosign(cosign_request).await.unwrap().into_inner();

	// Build the VTXO from the cosign response
	let board_cosign: ark::board::BoardCosignResponse = cosign_response.try_into().unwrap();
	let vtxo = board_builder.build_vtxo(&board_cosign, &client_cosign_keypair).unwrap();

	// === Now the fun begins ===

	let register_request = protos::BoardVtxoRequest {
		board_vtxo: vtxo.serialize(),
	};

	// Wait for the funding tx to propagate to server's bitcoind
	srv.bitcoind().await_transaction(funding_txid).await;

	// Try to register the board before it's confirmed - should fail
	let err = rpc.register_board_vtxo(register_request.clone()).await.unwrap_err();
	assert!(err.message().contains("requires 6"), "err: {err}");

	// Try with 3 confirmations - should still fail (need 6)
	let height = ctx.generate_blocks(3).await;
	srv.bitcoind().wait_for_blockheight(height).await;
	let err = rpc.register_board_vtxo(register_request.clone()).await.unwrap_err();
	assert!(err.message().contains("requires 6"), "err: {err}");

	// Try with 6 confirmations - should succeed
	let height = ctx.generate_blocks(3).await;
	srv.bitcoind().wait_for_blockheight(height).await;
	rpc.register_board_vtxo(register_request.clone()).await.unwrap();

	// Registering again should be idempotent
	rpc.register_board_vtxo(register_request.clone()).await.unwrap();

	// Should still be idempotent after more blocks
	let height = ctx.generate_blocks(1).await;
	srv.bitcoind().wait_for_blockheight(height).await;
	rpc.register_board_vtxo(register_request.clone()).await.unwrap();

	// === The client turns evil ===
	//
	// From here on, we test scenarios where a malicious client tries to
	// trick the server into accepting invalid boards.

	// This doesn't match the actual server keypair used by captaind
	let fake_server_keypair = Keypair::new(&*SECP, &mut thread_rng());

	// Create a board with the fake server keypair
	let cosign_keypair = Keypair::new(&*SECP, &mut thread_rng());
	let board_builder = ark::board::BoardBuilder::new(
		cosign_keypair.public_key(),
		expiry_height,
		fake_server_keypair.public_key(),
		ark_info.vtxo_exit_delta,
	);

	// Fund the board
	let funding_script = board_builder.funding_script_pubkey();
	let funding_address = Address::from_script(&funding_script, Network::Regtest).unwrap();
	let funding_txid = ctx.bitcoind().fund_addr(&funding_address, board_amount).await;
	let funding_tx = ctx.bitcoind().await_transaction(funding_txid).await;
	let vout = funding_tx.output.iter().position(|o| o.script_pubkey == funding_script).unwrap();
	let utxo = OutPoint::new(funding_txid, vout as u32);

	// Set funding details and generate nonces
	let board_builder = board_builder
		.set_funding_details(board_amount, board_fee, utxo).unwrap()
		.generate_user_nonces();

	// Do the server cosigning ourselves with the fake server keypair
	let server_builder = ark::board::BoardBuilder::new_for_cosign(
		cosign_keypair.public_key(),
		expiry_height,
		fake_server_keypair.public_key(),
		ark_info.vtxo_exit_delta,
		board_amount,
		board_fee,
		utxo,
		*board_builder.user_pub_nonce(),
	);
	let cosign_response = server_builder.server_cosign(&fake_server_keypair);

	// This is a fully signed VTXO by a different server. The client could
	// double-spend here because it knows all the keys.
	let vtxo = board_builder
		.build_vtxo(&cosign_response, &cosign_keypair)
		.unwrap();

	let height = ctx.generate_blocks(6).await;
	srv.bitcoind().wait_for_blockheight(height).await;

	// Try to register the board with the wrong server pubkey - should fail
	let register_request = protos::BoardVtxoRequest {
		board_vtxo: vtxo.serialize(),
	};
	let err = rpc.register_board_vtxo(register_request).await.unwrap_err();
	assert!(err.message().contains("server pubkey"), "err: {err}");
}

#[tokio::test]
async fn empty_round_does_not_replay_stale_attempt() {
	//! Test that stale Attempt events from empty rounds are not replayed.
	//!
	//! When a round starts, the server broadcasts an Attempt event and stores
	//! it as last_round_event. If no clients join and the round times out
	//! (empty round), this Attempt becomes stale. Without clearing it, new
	//! subscribers would receive this stale event and try to join a round
	//! that no longer exists.
	//!
	//! This test verifies that:
	//! 1. After an empty round times out, last_round_event is cleared
	//! 2. New subscribers don't receive the stale Attempt
	//! 3. When a fresh round starts, subscribers receive the new Attempt

	let ctx = TestContext::new("server/empty_round_does_not_replay_stale_attempt").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.round_submit_time = Duration::from_millis(500); // Short signup window
	}).await;

	// Wait for the initial empty round to time out (server auto-starts a round on boot)
	srv.wait_for_initial_round().await;

	// Now subscribe to round events via gRPC - after the empty round finished.
	// At this point, last_round_event should be cleared.
	let mut rpc = srv.get_public_rpc().await;
	let mut stream = rpc.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();

	// Verify we don't immediately get a stale Attempt.
	// Use try_fast() - should timeout because no event is pending.
	assert!(stream.next().try_fast().await.is_err(), "should not receive stale Attempt");

	// Trigger a new round
	srv.trigger_round().await;

	// Now we should receive the fresh Attempt
	let event = stream.next().wait(Duration::from_secs(5)).await.unwrap().unwrap();
	assert!(matches!(event.event, Some(protos::round_event::Event::Attempt(_))));
}

#[tokio::test]
async fn initiate_lightning_payment_fails_without_register_vtxos() {
	let ctx = TestContext::new("server/initiate_lightning_payment_fails_without_register_vtxos").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

	// Create a proxy that drops register_vtxos calls (returns success without calling upstream)
	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_vtxos(
			&self, _upstream: &mut ArkClient, _req: protos::RegisterVtxosRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// Drop the call - return success but don't register with upstream
			Ok(protos::Empty {})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "test_payment", "A test payment").await;

	// The payment should fail because register_vtxos was dropped,
	// so initiate_lightning_payment will fail when trying to mark server_may_own_descendants
	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err();
	assert!(err.to_string().contains("does not exist") || err.to_string().contains("NULL signed_tx"),
		"Expected error about missing or unsigned transaction, got: {err}");
}
