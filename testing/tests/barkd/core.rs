
use ark_testing::TestContext;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::wallet_api;

/// Verify that `barkd` responds to `GET /ping`.
#[tokio::test]
async fn ping_barkd() {
	let ctx = TestContext::new("barkd/ping_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	// `wait_for_init` (called internally by start) already proved ping works;
	// this test provides explicit REST-level coverage.
	barkd.ping().await;
}

/// Verify that `GET /bitcoin/tip` returns the current block height.
#[tokio::test]
async fn bitcoin_tip_barkd() {
	let ctx = TestContext::new("barkd/bitcoin_tip_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let height = ctx.bitcoind().get_block_count().await;

	let tip = barkd.tip().await;
	assert_eq!(
		tip.tip_height as u64, height,
		"barkd tip height should match current chain height",
	);
}

/// Verify that `GET /wallet/connected` reports true after wallet creation.
#[tokio::test]
async fn wallet_connected_barkd() {
	let ctx = TestContext::new("barkd/wallet_connected_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let resp = barkd.connected().await;
	assert!(resp.connected, "wallet should be connected to the Ark server after creation");
}

/// Verify that `GET /wallet/ark-info` returns valid server parameters.
#[tokio::test]
async fn wallet_ark_info_barkd() {
	let ctx = TestContext::new("barkd/wallet_ark_info_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let expected = srv.ark_info().await;
	let info = barkd.ark_info().await;

	assert_eq!(info.network, expected.network);
	assert_eq!(info.server_pubkey, expected.server_pubkey);
	assert_eq!(info.mailbox_pubkey, expected.mailbox_pubkey);
	assert_eq!(info.round_interval, expected.round_interval);
	assert_eq!(info.nb_round_nonces, expected.nb_round_nonces);
	assert_eq!(info.vtxo_exit_delta, expected.vtxo_exit_delta);
	assert_eq!(info.vtxo_expiry_delta, expected.vtxo_expiry_delta);
}

/// Verify that `GET /wallet/next-round` returns a future timestamp.
#[tokio::test]
async fn wallet_next_round_barkd() {
	let ctx = TestContext::new("barkd/wallet_next_round_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let next_round = barkd.next_round().await;
	let now = chrono::Local::now();

	assert!(
		next_round.start_time > now,
		"next round start_time {:?} should be in the future (now: {:?})",
		next_round.start_time, now,
	);
}

/// With `--no-auth`, unauthenticated requests are accepted.
#[tokio::test]
async fn no_auth_flag_allows_unauthenticated_requests() {
	let ctx = TestContext::new("barkd/no_auth_flag_allows_unauthenticated_requests").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv)
		.no_auth()
		.create().await;

	let unauthed = Configuration {
		base_path: barkd.base_url(),
		..Configuration::default()
	};
	wallet_api::wallet_exists(&unauthed).await
		.expect("unauthenticated request should succeed when --no-auth is set");
}

/// Auth can only be disabled by the `--no-auth` flag: `BARKD_NO_AUTH` in the
/// environment must not weaken a daemon started without the flag.
#[tokio::test]
async fn no_auth_env_var_is_ignored() {
	let ctx = TestContext::new("barkd/no_auth_env_var_is_ignored").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv)
		.env("BARKD_NO_AUTH", "true")
		.create().await;

	let unauthed = Configuration {
		base_path: barkd.base_url(),
		..Configuration::default()
	};
	let err = match wallet_api::wallet_exists(&unauthed).await {
		Err(e) => e.to_string(),
		Ok(_) => panic!("BARKD_NO_AUTH must not disable auth"),
	};
	assert!(err.contains("401"), "expected 401, got: {}", err);
}
