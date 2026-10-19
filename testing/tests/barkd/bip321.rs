
use bark_rest_client::apis::Error;
use bark_rest_client::apis::wallet_api;
use bark_rest_client::models::{PaymentMethodKind, SendRequest};

use ark_testing::{btc, require_bark_version, sat, TestContext};

use crate::helpers::wait_for_spendable;

/// Verify that `POST /wallet/bip321?uppercase=true` bundles an Ark address, a
/// BOLT11 invoice, and an on-chain address into a single upper-cased URI.
#[tokio::test]
async fn bip321_uri_barkd() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("barkd/bip321_uri_barkd").await;

	// A lightning-enabled server is required to mint the BOLT11 invoice.
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;

	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let amount = sat(50_000);
	let resp = barkd.bip321_uri(Some(amount), true, None, None, true).await;

	assert!(resp.ark.is_some(), "ark address should be present");
	assert!(resp.bolt11.is_some(), "bolt11 invoice should be present when an amount is given");
	assert!(resp.onchain.is_some(), "onchain address should be present when requested");

	let uri = resp.bip321;
	assert!(uri.starts_with("BITCOIN:"), "uri should be upper-cased: {}", uri);
	assert!(uri.contains("ARK="), "uri should carry the ark destination: {}", uri);
	assert!(uri.contains("LIGHTNING="), "uri should carry the bolt11 destination: {}", uri);
	// With no label/message every component is case-insensitive, so the whole
	// URI must already equal its upper-cased form.
	assert_eq!(uri, uri.to_uppercase(), "uri should be fully upper-cased: {}", uri);
}

/// Without an amount or the on-chain flag, only an Ark address is bundled, and
/// without `uppercase` the URI is returned in its normal (lower-case) form.
#[tokio::test]
async fn bip321_uri_ark_only_barkd() {
	let ctx = TestContext::new("barkd/bip321_uri_ark_only_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).create().await;

	let resp = barkd.bip321_uri(None, false, None, None, false).await;

	assert!(resp.ark.is_some(), "ark address should always be present");
	assert!(resp.bolt11.is_none(), "no bolt11 invoice without an amount");
	assert!(resp.onchain.is_none(), "no onchain address unless requested");
	assert!(resp.bip321.starts_with("bitcoin:"), "uri should be lower-case: {}", resp.bip321);
	assert!(resp.bip321.contains("ark="), "uri should carry the ark destination: {}", resp.bip321);
}

/// `POST /wallet/send` pays a BIP 321 URI: a method kind the URI does not
/// offer is refused, the Ark address is picked over the on-chain one by
/// default, and the amount can come from the URI.
#[tokio::test]
async fn send_to_bip321_uri_barkd() {
	let ctx = TestContext::new("barkd/send_to_bip321_uri_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let config = sender.client_config();

	let uri = recipient.bip321_uri(None, true, None, None, false).await.bip321;
	let send = |destination: &str, amount_sat, method| SendRequest {
		destination: destination.to_string(),
		amount_sat,
		comment: None,
		retry_for_secs: None,
		method,
	};

	let no_lightning = send(&uri, Some(50_000), Some(PaymentMethodKind::Lightning));
	match wallet_api::send(&config, no_lightning).await {
		Err(Error::ResponseError(rc)) => assert_eq!(rc.status, 400),
		other => panic!("expected 400 for a method the URI lacks, got {:?}", other.map(|r| r.message)),
	}

	let resp = wallet_api::send(&config, send(&uri, Some(50_000), None)).await
		.expect("sending to the URI failed");
	assert_eq!(resp.payment_hash, None, "the Ark address should be picked: {}", resp.message);
	wait_for_spendable(&recipient, sat(50_000)).await;

	let uri = format!("bitcoin:?amount=0.0003&ark={}", recipient.ark_address().await);
	wallet_api::send(&config, send(&uri, None, Some(PaymentMethodKind::Ark))).await
		.expect("sending to a URI with an amount failed");
	wait_for_spendable(&recipient, sat(80_000)).await;
}
