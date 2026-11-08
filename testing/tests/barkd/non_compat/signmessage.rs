use std::str::FromStr;

use ark::Address;
use ark_testing::TestContext;
use bark_json::web::{SignMessageRequest, VerifyMessageRequest};
use bark_rest_client::apis::Error;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::message_api;

async fn verify_message(
	config: &Configuration,
	message: &str,
	signature: &str,
	pubkey: Option<String>,
	address: Option<String>,
) -> bool {
	let req = VerifyMessageRequest {
		message: message.into(),
		signature: signature.into(),
		pubkey: pubkey,
		address: address,
	};
	message_api::verify_message(config, req).await
		.expect("message/verify endpoint should return 200")
		.valid
}

/// Sign with the key of one of the wallet's own addresses and verify
/// against both the address and its user pubkey.
#[tokio::test]
async fn sign_message_with_address() {
	let ctx = TestContext::new("barkd/sign_message_with_address").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;
	let config = barkd.client_config();

	let address = barkd.ark_address().await;
	let message = "hello ark";
	let signed = message_api::sign_message(&config, SignMessageRequest {
		message: message.into(),
		address: address.clone(),
	}).await.expect("message/sign endpoint should return 200");

	let signature = signed.signature.to_string();
	assert!(verify_message(&config, message, &signature, None, Some(address.clone())).await,
		"signature should verify against the address");

	let pubkey = Address::from_str(&address).unwrap().policy().user_pubkey().to_string();
	assert!(verify_message(&config, message, &signature, Some(pubkey), None).await,
		"signature should verify against the address' user pubkey");

	assert!(!verify_message(&config, "hello bark", &signature, None, Some(address)).await,
		"a tampered message should not verify");

	// test bad requests
	let other = ctx.bark("other", &srv).create().await;
	let foreign_address = other.address().await;

	match message_api::sign_message(&config, SignMessageRequest {
		message: "hello ark".into(),
		address: foreign_address,
	}).await {
		Ok(_) => panic!("signing with a foreign address should fail"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 400),
		Err(other) => panic!("expected 400 ResponseError, got {:?}", other),
	}

	let req = VerifyMessageRequest {
		message: "hello ark".into(),
		signature: "00".repeat(64),
		pubkey: None,
		address: None,
	};
	match message_api::verify_message(&config, req).await {
		Ok(_) => panic!("verifying without pubkey or address should fail"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 400),
		Err(other) => panic!("expected 400 ResponseError, got {:?}", other),
	}

	let req = VerifyMessageRequest {
		message: "hello ark".into(),
		signature: "not a signature".into(),
		pubkey: None,
		address: Some(barkd.ark_address().await),
	};
	match message_api::verify_message(&config, req).await {
		Ok(_) => panic!("verifying a malformed signature should fail"),
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 400),
		Err(other) => panic!("expected 400 ResponseError, got {:?}", other),
	}
}
