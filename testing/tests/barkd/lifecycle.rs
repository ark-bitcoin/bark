//! Tests for barkd's single-instance guarantee: the `barkd.lock` datadir lock.

use std::process::Stdio;
use std::time::Duration;

use ark_testing::TestContext;
use ark_testing::daemon::barkd::Barkd;
use ark_testing::ports::pick_port;
use bark_rest_client::apis::wallet_api;
use bark_rest_client::models::WalletDeleteRequest;

/// A second barkd on the same datadir must fail fast, leaving the incumbent untouched.
#[tokio::test]
async fn second_barkd_on_same_datadir_refuses_to_start() {
	let ctx = TestContext::new("barkd/second_barkd_on_same_datadir_refuses_to_start").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	// A reserved port: the process must die on the lock, not on a bind collision.
	let port = pick_port().to_string();
	let mut cmd = Barkd::base_cmd();
	cmd.args(["--datadir", barkd.datadir().to_str().unwrap(), "--port", &port])
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::piped());
	let output = tokio::time::timeout(Duration::from_secs(10), async {
		cmd.output().await.expect("failed to spawn second barkd")
	}).await.expect("second barkd should fail fast, not hang");

	assert!(!output.status.success(), "second barkd on the same datadir must exit nonzero");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("another barkd is already running"),
		"second barkd must fail on the datadir lock, got: {}", stderr,
	);

	// The incumbent is unaffected.
	barkd.ping().await;
}

/// A wallet delete wipes the wallet data; the daemon's lock and auth token
/// survive so clients keep working without a restart.
#[tokio::test]
async fn wallet_delete_keeps_daemon_files() {
	let ctx = TestContext::new("barkd/wallet_delete_keeps_daemon_files").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let token_path = barkd.datadir().join("auth_token");
	let token = std::fs::read_to_string(&token_path)
		.expect("an auth token should exist in the datadir");

	let config = barkd.client_config();
	let fingerprint = wallet_api::wallet_exists(&config).await.unwrap()
		.fingerprint.expect("a wallet should be loaded");
	wallet_api::wallet_delete(&config, WalletDeleteRequest {
		dangerous: true,
		fingerprint,
	}).await.expect("wallet delete should succeed");

	assert!(barkd.datadir().join("barkd.lock").exists(), "the datadir lock must survive");
	let surviving = std::fs::read_to_string(&token_path)
		.expect("the auth token must survive a wallet delete");
	assert_eq!(surviving, token, "the auth token must be unchanged");

	// The surviving token still authenticates against the running server.
	let exists = wallet_api::wallet_exists(&config).await
		.expect("the stored token must still authenticate");
	assert_eq!(exists.fingerprint, None, "the wallet should be gone");
}
