use std::sync::Arc;

use bark::BarkNetwork;

use ark_testing::{Bark, TestContext, require_bark_version};
use ark_testing::util::ToAltString;

#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/bark_create_is_atomic").await;
	let srv = ctx.captaind("server").create().await;

	// Create a bark defines the folder
	let _  = ctx.bark("bark_ok", &srv).try_create().await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_ok").is_dir());

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.bark("bark_twice", &srv).try_create().await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	let _ = ctx.bark("bark_twice", &srv).try_create().await.expect_err("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	// We stop the server
	// This ensures that clients cannot be created
	srv.stop().await.unwrap();
	let err = ctx.bark("bark_fails", &srv).try_create().await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"Failed to connect to provided server (if you are sure use the --force flag)"
	), "{:?}", err);
	assert!(!ctx.datadir.join("bark_fails").is_dir());
}

#[tokio::test]
async fn bark_address_works_offline() {
	require_bark_version!(> "0.1.3");

	let ctx = TestContext::new("bark/bark_address_works_offline").await;
	let srv = ctx.captaind("server").create().await;
	let bark = ctx.bark("bark", &srv).create().await;

	// Derive idx 0 with the server up so the key exists in the DB.
	let addr_with_server = bark.address().await;

	srv.stop().await.unwrap();

	let addr_without_server = bark.address_at_idx(0).await;
	assert_eq!(addr_with_server, addr_without_server,
		"address at idx 0 should match whether or not the server is reachable");

	// Derive a brand-new address with the server down.
	let new_addr_without_server = bark.address().await;
	assert_ne!(new_addr_without_server, addr_with_server,
		"new address should use a freshly derived key");
}

#[tokio::test]
async fn bark_create_force_flag() {
	let ctx = TestContext::new("bark/bark_create_force_flag").await;
	let srv = ctx.captaind("server").create().await;

	// Stop the server to simulate unavailability
	srv.stop().await.unwrap();

	// Attempt to create with force_create should succeed
	let datadir = ctx.datadir.join("bark");
	let bitcoind = Arc::new(ctx.new_bitcoind("bark_bitcoind").await);
	let cfg = ctx.bark_default_cfg(&srv, Some(&bitcoind));
	Bark::try_new_with_create_opts(
		"bark", datadir, BarkNetwork::Regtest, cfg, Some(bitcoind), None, None, true,
	).await.unwrap();

	assert!(std::path::Path::is_dir(ctx.datadir.join("bark").as_path()));
}
