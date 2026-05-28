use std::str::FromStr;

use ark::{SECP, VtxoPolicy};
use ark::lightning::{Bolt11Invoice, Invoice};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::{ArkoorAddressError, FeeEstimate};
use bark::payment_request::{
	PaymentRequest, AvailablePaymentMethod, PaymentMethodParsingError, PaymentMethod
};
use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use bitcoin::Amount;
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

	// Fee estimation needs a VTXO to spend.
	let [vtxo] = uri_parser_bark
		.board_and_confirm_and_register(&ctx, sat(100_000)).await.try_into().unwrap();

	let amount = sat(50_000);

	// -- BIP 321 with ark + lightning + onchain --
	{
		let mut wallet1 = uri_builder_bark.client().await;
		let mut onchain1 = uri_builder_bark.onchain_client().await;
		let uri = wallet1.bip321_uri()
			.amount(amount).unwrap()
			.enable_all(&mut onchain1).unwrap()
			.label("test-label".to_string())
			.message("test-message".to_string())
			.build().await.unwrap();

		let request = uri_parser_bark.try_parse_payment_request(&uri.to_string()).await.unwrap();

		assert_eq!(request.amount, Some(amount));
		assert_eq!(request.label.as_deref(), Some("test-label"));
		assert_eq!(request.message.as_deref(), Some("test-message"));
		assert_eq!(request.options.len(), 3);
		assert!(request.options.iter().any(|m| m.method.is_bitcoin()), "should have onchain method");
		assert!(request.options.iter().any(|m| m.method.is_ark()), "should have ark method");
		assert!(request.options.iter().any(|m| m.method.is_lightning()), "should have lightning method");
		assert!(
			request.options.iter().all(|m| m.errors.is_empty()),
			"all methods should be valid",
		);
	}

	// -- BIP 321 with ark only --
	{
		let mut wallet1 = uri_builder_bark.client().await;
		let uri = wallet1.bip321_uri()
			.amount(amount).unwrap()
			.ark(false)
			.build().await.unwrap();

		let request = uri_parser_bark.try_parse_payment_request(&uri.to_string()).await.unwrap();

		assert!(request.options[0].method.is_ark());
		assert!(request.options[0].errors.is_empty());

		let fees = uri_parser_bark.estimate_payment_fees(request, None).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount,
			fee: Amount::ZERO,
			net_amount: amount,
			vtxos_spent: vec![vtxo],
		});
	}

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

	// -- BIP 321 with amount only (onchain) --
	{
		let mut wallet1 = uri_builder_bark.client().await;
		let mut onchain1 = uri_builder_bark.onchain_client().await;
		let uri = wallet1.bip321_uri()
			.amount(amount).unwrap()
			.onchain(&mut onchain1)
			.build().await.unwrap();
		let request = uri_parser_bark.try_parse_payment_request(&uri.to_string()).await.unwrap();

		assert_eq!(request.amount, Some(amount));
		assert_eq!(request.options.len(), 1);
		assert!(request.options[0].method.is_bitcoin());
		assert!(request.options[0].errors.is_empty(), "valid address should have no errors");

		let fees = uri_parser_bark.estimate_payment_fees(request, None).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount + Amount::from_sat(938),
			fee: Amount::from_sat(938),
			net_amount: amount,
			vtxos_spent: vec![vtxo],
		});
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

		let fees = uri_parser_bark.estimate_payment_fees(request, None).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount,
			fee: Amount::ZERO,
			net_amount: amount,
			vtxos_spent: vec![vtxo],
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

		let fees = uri_parser_bark.estimate_payment_fees(request, Some(amount)).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount,
			fee: Amount::ZERO,
			net_amount: amount,
			vtxos_spent: vec![vtxo],
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

		let fees = uri_parser_bark.estimate_payment_fees(request, Some(amount)).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount,
			fee: Amount::ZERO,
			net_amount: amount,
			vtxos_spent: vec![vtxo],
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

		let fees = uri_parser_bark.estimate_payment_fees(request, Some(amount)).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount,
			fee: Amount::ZERO,
			net_amount: amount,
			vtxos_spent: vec![vtxo],
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

		let fees = uri_parser_bark.estimate_payment_fees(request, Some(amount)).await;
		assert_eq!(fees.len(), 1);
		assert_eq!(fees[0].1, FeeEstimate {
			gross_amount: amount + Amount::from_sat(854),
			fee: Amount::from_sat(854),
			net_amount: amount,
			vtxos_spent: vec![vtxo],
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
