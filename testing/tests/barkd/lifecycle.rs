//! Tests for barkd's single-instance guarantee: the `barkd.lock` datadir lock.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use ark_testing::{TestContext, require_bark_version};
use ark_testing::constants::env::BARK_EXEC;
use ark_testing::daemon::barkd::{Barkd, BarkdChainSource};
use ark_testing::ports::pick_port;
use ark_testing::util::resolve_path;
use bark_rest_client::apis::wallet_api;
use bark_rest_client::models::WalletDeleteRequest;

/// CLI creation must not change a datadir that a daemon owns, even without a wallet.
#[tokio::test]
async fn cli_create_refuses_running_daemon() {
	require_bark_version!(> "0.7.1");
	let bark_exec = resolve_path(std::env::var(BARK_EXEC).expect("BARK_EXEC env not set"))
		.expect("failed to resolve BARK_EXEC");
	let ctx = TestContext::new_minimal("barkd/cli_create_refuses_running_daemon").await;
	let datadir = ctx.datadir.join("barkd");
	// No wallet is created, so neither endpoint is contacted.
	let barkd = Barkd::new("barkd", datadir.clone(), "http://127.0.0.1:1".into(),
		BarkdChainSource::Esplora("http://127.0.0.1:1".into()), None);
	barkd.start().await.unwrap();
	let token = std::fs::read(datadir.join("auth_token")).unwrap();
	let sentinel = datadir.join("creation-sentinel");
	std::fs::write(&sentinel, b"keep").unwrap();
	let lock = std::fs::File::options().read(true).write(true)
		.open(datadir.join("barkd.lock")).unwrap();

	for force in [true, false] {
		let mut cmd = Command::new(&bark_exec);
		cmd.arg("--datadir").arg(&datadir).args(["--no-logfile", "create", "--regtest"]);
		if force { cmd.arg("--force"); }
		let output = tokio::time::timeout(Duration::from_secs(30), cmd.kill_on_drop(true).output())
			.await.expect("CLI creation hung").unwrap();
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(!output.status.success());
		assert!(stderr.contains("another barkd is already running"), "{stderr}");
		assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
		assert_eq!(std::fs::read(datadir.join("auth_token")).unwrap(), token);
		assert!(matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
		barkd.ping().await;
	}

	barkd.stop().await.unwrap();
	// After shutdown, creation must reach validation and release its lock on failure.
	for _ in 0..2 {
		let output = tokio::time::timeout(Duration::from_secs(30), Command::new(&bark_exec)
			.arg("--datadir").arg(&datadir)
			.args(["--no-logfile", "create", "--regtest", "--force"])
			.kill_on_drop(true).output(),
		).await.expect("CLI creation hung after daemon shutdown").unwrap();
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(!output.status.success());
		assert!(stderr.contains("You need to provide a chain source"), "{stderr}");
		lock.try_lock().expect("failed creation left the lifecycle lock held");
		lock.unlock().unwrap();
	}
}

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

/// The same barkd process accepts a new wallet after a delete, even when a
/// create fails in between.
///
/// A delete leaves no config.toml, so a create that carries no configuration
/// fails. Such a failure must keep the running barkd's lock and auth token:
/// without them, barkd cannot serve the datadir until it restarts.
#[tokio::test]
async fn wallet_create_after_delete_needs_no_restart() {
	let ctx = TestContext::new("barkd/wallet_create_after_delete_needs_no_restart").await;

	let srv = ctx.captaind("server").create().await;
	// The daemon writes to the wallet db once per interval. A short one makes
	// a task that outlives the delete write into the wiped datadir.
	let barkd = ctx.barkd("barkd1", &srv)
		.cfg(|cfg| cfg.daemon_sync_interval_secs = 1)
		.create().await;

	let datadir = barkd.datadir();
	let config = barkd.client_config();
	let fingerprint = wallet_api::wallet_exists(&config).await.unwrap()
		.fingerprint.expect("a wallet should be loaded");
	wallet_api::wallet_delete(&config, WalletDeleteRequest {
		dangerous: true,
		fingerprint: fingerprint.clone(),
	}).await.expect("wallet delete should succeed");

	// No daemon task may bring the wallet db back after the wipe.
	tokio::time::sleep(Duration::from_secs(3)).await;
	assert!(!datadir.join("db.sqlite").exists(), "the wallet db must stay gone");

	// The delete took config.toml with the wallet, so a create without
	// configuration fails.
	barkd.create_wallet().await
		.expect_err("a create without configuration should fail");

	assert!(datadir.join("barkd.lock").exists(), "a failed create must keep the datadir lock");
	assert!(datadir.join("auth_token").exists(), "a failed create must keep the auth token");
	barkd.ping().await;

	barkd.create_wallet_from_args(barkd.create_wallet_request()).await
		.expect("barkd should accept a new wallet without a restart");

	let new_fingerprint = wallet_api::wallet_exists(&config).await
		.expect("the new wallet should be queryable")
		.fingerprint.expect("the new wallet should be loaded");
	assert_ne!(new_fingerprint, fingerprint, "the new wallet must have its own seed");

	// The new wallet reaches both its database and the Ark server.
	barkd.ark_address().await;
	assert!(barkd.connected().await.connected, "the new wallet should reach the Ark server");
}

/// A gap limit given to `POST /wallet/create` is persisted to config.toml.
///
/// It is config, not a one-shot recovery knob, so it has to outlive the create
/// call and apply to later imports too. Deleting the wallet first wipes
/// config.toml, so the re-create writes a fresh one from the request alone.
#[tokio::test]
async fn wallet_create_persists_gap_limit() {
	let ctx = TestContext::new("barkd/wallet_create_persists_gap_limit").await;
	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let datadir = barkd.datadir();
	let config = barkd.client_config();
	let fingerprint = wallet_api::wallet_exists(&config).await.unwrap()
		.fingerprint.expect("a wallet should be loaded");
	wallet_api::wallet_delete(&config, WalletDeleteRequest {
		dangerous: true,
		fingerprint,
	}).await.expect("wallet delete should succeed");

	let mut req = barkd.create_wallet_request();
	req.gap_limit = Some(10_000);
	barkd.create_wallet_from_args(req).await
		.expect("barkd should accept a create-time gap limit");

	let written = std::fs::read_to_string(datadir.join("config.toml"))
		.expect("the re-created wallet should have a config file");
	assert!(written.contains("vtxo_key_gap_limit = 10000"),
		"the requested gap limit should be persisted, got: {written}");
}
