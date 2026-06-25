
use ark_testing::{btc, sat, TestContext};

/// Verify that `POST /wallet/bip321?uppercase=true` bundles an Ark address, a
/// BOLT11 invoice, and an on-chain address into a single upper-cased URI.
#[tokio::test]
async fn bip321_uri_barkd() {
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
