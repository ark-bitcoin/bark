
use std::str::FromStr;

use ark_testing::TestContext;
use bark_rest_client::apis::Error;
use bark_rest_client::apis::wallet_api;

/// `GET /wallet/mnemonic` returns the wallet's BIP-39 phrase by default.
#[tokio::test]
async fn mnemonic_exposed_by_default() {
	let ctx = TestContext::new("barkd/mnemonic_exposed_by_default").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let resp = wallet_api::mnemonic(&barkd.client_config()).await
		.expect("mnemonic endpoint should return 200");
	bip39::Mnemonic::from_str(&resp.mnemonic)
		.expect("response should be a valid BIP-39 mnemonic");
}

/// With `BARKD_EXPOSE_MNEMONIC=false`, the endpoint responds 404.
#[tokio::test]
async fn mnemonic_disabled_returns_404() {
	let ctx = TestContext::new("barkd/mnemonic_disabled_returns_404").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd_disabled", &srv)
		.env("BARKD_EXPOSE_MNEMONIC", "false")
		.create().await;

	match wallet_api::mnemonic(&barkd.client_config()).await {
		Ok(_) => panic!("mnemonic endpoint should be disabled"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 404),
		Err(other) => panic!("expected 404 ResponseError, got {:?}", other),
	}
}
