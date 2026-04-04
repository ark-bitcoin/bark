use std::str::FromStr;

use ark::{SECP, VtxoPolicy};
use ark::lightning::{Bolt11Invoice, Invoice};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::ArkoorAddressError;
use bark::payment_request::{
	PaymentRequest, AvailablePaymentMethod, PaymentMethodParsingError, PaymentMethod
};
use bitcoin::secp256k1::{Keypair, rand::thread_rng};

use ark_testing::{btc, sat, TestContext};

fn new_ark_address(testnet: bool) -> ark::Address {
	let foreign_server = Keypair::new(&SECP, &mut thread_rng()).public_key();
	let user_pubkey = Keypair::new(&SECP, &mut thread_rng()).public_key();
	ark::Address::new(
		testnet,
		foreign_server,
		VtxoPolicy::new_pubkey(user_pubkey),
		vec![],
	)
}

/// Single integration test exercising `parse_payment_request` with various payment
/// strings. We set up one server and two bark wallets, then run all assertions
/// within the same test to avoid repeated setup overhead.
///
/// Where the BIP 321 builder supports building a URI, wallet_1 builds and wallet_2
/// parses. Cases that the builder cannot produce (foreign ark addresses, bare
/// strings, invalid-network literals) are constructed manually.
#[tokio::test]
async fn parse_payment_request() {
	let ctx = TestContext::new("bark/parse_payment_request").await;

	// Server needs a lightning node so bark can create bolt11 invoices.
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let uri_builder_bark = ctx.bark("bark1", &srv).create().await;
	let uri_parser_bark = ctx.bark("bark2", &srv).funded(sat(200_000)).create().await;

	let amount = sat(50_000);

	// -- BIP 321 with invalid ark address (foreign server, manual URI) --
	{
		let btc_addr = ctx.bitcoind().get_new_address();
		let foreign_ark_addr = new_ark_address(true);

		let uri = format!("bitcoin:?tb={}&ark={}", btc_addr, foreign_ark_addr.clone());
		let request = uri_builder_bark.try_parse_payment_request(&uri).await.unwrap();

		let ark_method = request.options.iter()
			.find(|m| matches!(m.method, PaymentMethod::Ark(_)))
			.expect("ark method should be present");
		assert_eq!(ark_method.method, PaymentMethod::Ark(foreign_ark_addr.clone()));
		assert_eq!(ark_method.errors, vec![PaymentMethodParsingError::InvalidArkAddress(ArkoorAddressError::ServerMismatch)]);

		// With mainnet address
		let mainnet_addr = {
			let addr_str = "bc1qrrz8r05xuyjh667a2nfgvh96d5x47aug0prxwm";
			bitcoin::Address::from_str(addr_str).unwrap()
		};
		let uri = format!("bitcoin:{}?ark={}", mainnet_addr.assume_checked_ref(), foreign_ark_addr.clone());
		let request = uri_builder_bark.try_parse_payment_request(&uri).await.unwrap();

		let onchain_method = request.options.iter()
			.find(|m| matches!(m.method, PaymentMethod::Bitcoin(_)))
			.expect("onchain method should be present");
		assert_eq!(onchain_method.method, PaymentMethod::Bitcoin(mainnet_addr));
		assert_eq!(onchain_method.errors, vec![PaymentMethodParsingError::NetworkMismatch]);

		let ark_method = request.options.iter()
			.find(|m| matches!(m.method, PaymentMethod::Ark(_)))
			.expect("ark method should be present");
		assert_eq!(ark_method.method, PaymentMethod::Ark(foreign_ark_addr));
		assert_eq!(ark_method.errors, vec![PaymentMethodParsingError::InvalidArkAddress(ArkoorAddressError::ServerMismatch)]);
	}

	// -- Bare lightning invoice (built by wallet_1, parsed by wallet_2) --
	{
		let bolt11 = uri_builder_bark.bolt11_invoice(amount).await;
		let bolt11 = Bolt11Invoice::from_str(&bolt11.invoice).unwrap();
		let request = uri_parser_bark.try_parse_payment_request(&bolt11.to_string()).await.unwrap();

		assert_eq!(request, PaymentRequest {
			amount: Some(amount),
			label: None,
			message: Some(bolt11.description().to_string()),
			options: vec![AvailablePaymentMethod {
				method: PaymentMethod::Invoice(Invoice::Bolt11(bolt11)),
				errors: vec![],
			}],
		});
	}

	// -- Lightning address --
	{
		let lightning_address = LightningAddress::from_str("user@example.com").unwrap();
		let request = uri_parser_bark.try_parse_payment_request(
			&lightning_address.to_string(),
		).await.unwrap();

		assert_eq!(request, PaymentRequest {
			amount: None,
			label: None,
			message: None,
			options: vec![AvailablePaymentMethod {
				method: PaymentMethod::LightningAddress(lightning_address),
				errors: vec![],
			}],
		});
	}

	// -- Bare ark address (built by wallet_1, parsed by wallet_2) --
	{
		let wallet1 = uri_builder_bark.client().await;
		let ark_addr = wallet1.new_address().await.unwrap();

		let request = uri_parser_bark.try_parse_payment_request(&ark_addr.to_string()).await.unwrap();

		assert_eq!(request, PaymentRequest {
			amount: None,
			label: None,
			message: None,
			options: vec![AvailablePaymentMethod {
				method: PaymentMethod::Ark(ark_addr),
				errors: vec![],
			}],
		});
	}

	// -- Bare ark address from foreign server (manual) --
	{
		let foreign_ark_addr = new_ark_address(true);
		let request = uri_parser_bark.try_parse_payment_request(&foreign_ark_addr.to_string()).await.unwrap();

		assert_eq!(request, PaymentRequest {
			amount: None,
			label: None,
			message: None,
			options: vec![AvailablePaymentMethod {
				method: PaymentMethod::Ark(foreign_ark_addr),
				errors: vec![PaymentMethodParsingError::InvalidArkAddress(ArkoorAddressError::ServerMismatch)],
			}],
		});
	}

	// -- Bare onchain address --
	{
		let btc_addr = ctx.bitcoind().get_new_address();
		let request = uri_parser_bark.try_parse_payment_request(&btc_addr.to_string()).await.unwrap();

		assert_eq!(request, PaymentRequest {
			amount: None,
			label: None,
			message: None,
			options: vec![AvailablePaymentMethod {
				method: PaymentMethod::Bitcoin(btc_addr.into_unchecked()),
				errors: vec![],
			}],
		});
	}

	// -- Onchain address for invalid network (mainnet address on regtest, manual) --
	{
		let mainnet_addr = "bc1qrrz8r05xuyjh667a2nfgvh96d5x47aug0prxwm";
		let request = uri_parser_bark.try_parse_payment_request(mainnet_addr).await.unwrap();

		assert_eq!(request.options.len(), 1);
		assert_eq!(request.options[0].method, PaymentMethod::Bitcoin(bitcoin::Address::from_str(mainnet_addr).unwrap()));
		assert_eq!(request.options[0].errors, vec![PaymentMethodParsingError::NetworkMismatch]);
	}

	// -- Lightning invoice for invalid network (mainnet invoice on regtest, manual) --
	{
		let mainnet_invoice = "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q9qrsgq9vlvyj8cqvq6ggvpwd53jncp9nwc47xlrsnenq2zp70fq83qlgesn4u3uyf4tesfkkwwfg3qs54qe426hp3tz7z6sweqdjg05axsrjqp9yrrwc";
		let request = uri_parser_bark.try_parse_payment_request(mainnet_invoice).await.unwrap();

		assert_eq!(request.options.len(), 1);
		assert_eq!(request.options[0].method, PaymentMethod::Invoice(Invoice::Bolt11(Bolt11Invoice::from_str(mainnet_invoice).unwrap())));
		assert_eq!(request.options[0].errors, vec![PaymentMethodParsingError::NetworkMismatch]);
	}

	// -- Ark address for invalid network (mainnet address on regtest, manual) --
	{
		let ark_addr = new_ark_address(false);

		let request = uri_parser_bark.try_parse_payment_request(&ark_addr.to_string()).await.unwrap();

		assert_eq!(request.options.len(), 1);
		assert_eq!(request.options[0].method, PaymentMethod::Ark(ark_addr));
		assert_eq!(request.options[0].errors, vec![PaymentMethodParsingError::InvalidArkAddress(ArkoorAddressError::NetworkMismatch)]);
	}
}
