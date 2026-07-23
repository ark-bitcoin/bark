
use std::str::FromStr;

use ark_testing::TestContext;
use bark_rest_client::apis::Error;
use bark_rest_client::apis::wallet_api;

/// `GET /wallet/mnemonic` is disabled by default and responds 404.
#[tokio::test]
async fn mnemonic_disabled_by_default() {
	let ctx = TestContext::new("barkd/mnemonic_disabled_by_default").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	match wallet_api::mnemonic(&barkd.client_config()).await {
		Ok(_) => panic!("mnemonic endpoint should be disabled by default"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 404),
		Err(other) => panic!("expected 404 ResponseError, got {:?}", other),
	}
}

/// With `BARKD_EXPOSE_MNEMONIC=true`, the endpoint returns the BIP-39 phrase.
#[tokio::test]
async fn mnemonic_returned_when_enabled() {
	let ctx = TestContext::new("barkd/mnemonic_returned_when_enabled").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd_enabled", &srv)
		.env("BARKD_EXPOSE_MNEMONIC", "true")
		.create().await;

	let resp = wallet_api::mnemonic(&barkd.client_config()).await
		.expect("mnemonic endpoint should return 200 when enabled");
	bip39::Mnemonic::from_str(&resp.mnemonic)
		.expect("response should be a valid BIP-39 mnemonic");
}
