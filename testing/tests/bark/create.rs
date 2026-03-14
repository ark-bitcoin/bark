use bark::BarkNetwork;

use ark_testing::{Bark, TestContext};
use ark_testing::util::ToAltString;

#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/bark_create_is_atomic").await;
	let srv = ctx.new_captaind("server", None).await;

	// Create a bark defines the folder
	let _  = ctx.try_new_bark("bark_ok", &srv).await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_ok").is_dir());

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.try_new_bark("bark_twice", &srv).await.expect("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	let _ = ctx.try_new_bark("bark_twice", &srv).await.expect_err("Can create bark");
	assert!(ctx.datadir.join("bark_twice").is_dir());

	// We stop the server
	// This ensures that clients cannot be created
	srv.stop().await.unwrap();
	let err = ctx.try_new_bark("bark_fails", &srv).await.unwrap_err();
	assert!(err.to_alt_string().contains(
		"Failed to connect to provided server (if you are sure use the --force flag): Failed to connect to Ark server: transport error"
	), "{:?}", err);
	assert!(!ctx.datadir.join("bark_fails").is_dir());
}

#[tokio::test]
async fn bark_create_force_flag() {
	let ctx = TestContext::new("bark/bark_create_force_flag").await;
	let srv = ctx.new_captaind("server", None).await;

	// Stop the server to simulate unavailability
	srv.stop().await.unwrap();

	// Attempt to create with force_create should succeed
	let datadir = ctx.datadir.join("bark");
	let bitcoind = ctx.new_bitcoind("bark_bitcoind").await;
	let cfg = ctx.bark_default_cfg(&srv, Some(&bitcoind));
	Bark::try_new_with_create_opts(
		"bark", datadir, BarkNetwork::Regtest, cfg, Some(bitcoind), None, None, true,
	).await.unwrap();

	assert!(std::path::Path::is_dir(ctx.datadir.join("bark").as_path()));
}
