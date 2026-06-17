use std::str::FromStr;

use ark_testing::{TestContext, btc, sat};

use bark::payment_request::BarkExtension;
use bip321::{Bip321Uri, ExtensionHandler};

/// Verify that URIs produced by the BIP 321 builder are spec-valid: they round
/// trip through the standalone `bip321` parser (not bark's lenient payment
/// parser) and pass its `validate()` check. This guards against the builder
/// emitting strings that other BIP 321 wallets would reject.
#[tokio::test]
async fn build_valid_bip321_uri() {
	let ctx = TestContext::new("bark_sdk/build_valid_bip321_uri").await;

	// Server needs a lightning node so bark can create bolt11 invoices.
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let mut wallet = ctx.bark_sdk("bark", &srv).create().await;
	let onchain = wallet.onchain().expect("sdk test wallet has an onchain wallet");
	let amount = sat(50_000);

	// -- Full URI: amount + label + message + onchain + ark + lightning --
	{
		let mut onchain = onchain.write().await;
		let built = wallet.bip321_uri()
			.amount(amount)
			.onchain_wallet(&mut *onchain)
			.label("test-label".to_string())
			.message("test-message".to_string())
			.build().await.unwrap();

		let serialized = built.to_string();
		assert!(serialized.starts_with("bitcoin:"), "URI must use the bitcoin scheme: {}", serialized);

		// Re-parse with the standalone spec parser and validate.
		let uri = Bip321Uri::<BarkExtension>::from_str(&serialized)
			.expect("builder output must parse as a BIP 321 URI");
		uri.validate().expect("builder output must be a valid BIP 321 URI");

		assert_eq!(uri.amount(), Some(&amount));
		assert_eq!(uri.label().map(|l| l.as_str()), Some("test-label"));
		assert_eq!(uri.message().map(|m| m.as_str()), Some("test-message"));

		// One bolt11 invoice for the requested amount.
		assert_eq!(uri.lightning().len(), 1);
		assert_eq!(
			uri.lightning()[0].inner().amount_milli_satoshis(),
			Some(amount.to_sat() * 1000),
		);

		// One regtest onchain address in the `tb=` param.
		assert_eq!(uri.tb().len(), 1);
		assert!(uri.bc().is_empty());

		// One ark address in the extension.
		let ark_params = uri.extensions().serialize_params();
		assert_eq!(ark_params.len(), 1);
		assert_eq!(ark_params[0].0, "ark");
	}

	// -- Minimal URI: ark only, no amount (the builder's default-ish case) --
	{
		let built = wallet.bip321_uri()
			.ark(true)
			.build().await.unwrap();

		let uri = Bip321Uri::<BarkExtension>::from_str(&built.to_string())
			.expect("builder output must parse as a BIP 321 URI");
		uri.validate().expect("builder output must be a valid BIP 321 URI");

		assert_eq!(uri.amount(), None);
		assert!(uri.lightning().is_empty());
		assert!(uri.tb().is_empty());
		assert!(uri.bc().is_empty());

		let ark_params = uri.extensions().serialize_params();
		assert_eq!(ark_params.len(), 1);
		assert_eq!(ark_params[0].0, "ark");
	}

	// -- All methods enabled but no amount: lightning is skipped (it needs an
	// amount to build an invoice), so only onchain + ark are present. --
	{
		let mut onchain = onchain.write().await;
		let built = wallet.bip321_uri()
			.onchain_wallet(&mut *onchain)
			.lightning_bolt11(true)
			.ark(true)
			.build().await.unwrap();

		let uri = Bip321Uri::<BarkExtension>::from_str(&built.to_string())
			.expect("builder output must parse as a BIP 321 URI");
		uri.validate().expect("builder output must be a valid BIP 321 URI");

		assert_eq!(uri.amount(), None);
		assert!(uri.lightning().is_empty(), "lightning requires an amount and must be skipped");

		// One regtest onchain address in the `tb=` param.
		assert_eq!(uri.tb().len(), 1);
		assert!(uri.bc().is_empty());

		// One ark address in the extension.
		let ark_params = uri.extensions().serialize_params();
		assert_eq!(ark_params.len(), 1);
		assert_eq!(ark_params[0].0, "ark");
	}
}
