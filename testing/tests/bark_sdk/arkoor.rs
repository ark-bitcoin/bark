use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;

use ark::VtxoPolicy;
use ark::address::VtxoDelivery;

use ark_testing::{TestContext, sat};

/// An address that lists no delivery mechanism this bark can use is refused
/// before the arkoor is built, so the sender keeps its funds.
#[tokio::test]
async fn send_to_unsupported_delivery_is_refused() {
	let ctx = TestContext::new("bark_sdk/send_to_unsupported_delivery_is_refused").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	// Same server and policy as a payable address, but the only way it offers
	// to hand over the VTXO is a mechanism this bark doesn't know.
	let address = receiver.new_address().await.expect("new address");
	let address = ark::Address::new(
		address.is_testnet(),
		address.ark_id(),
		address.policy().clone(),
		vec![VtxoDelivery::Unknown { delivery_type: 0xff, data: vec![1, 2, 3] }],
	);

	let err = sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect_err("send to an undeliverable address must fail");
	assert!(format!("{:#}", err).contains("Unknown delivery mechanism"), "err: {err:#}");

	// The send never started: no action is pending and no VTXO was spent.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(sender.balance().await.unwrap().spendable, sat(400_000));
}

/// An address that lists no delivery mechanism at all is the receiver's
/// choice to pick up the VTXO out-of-band: the payment succeeds and bark
/// never attempts a delivery.
#[tokio::test]
async fn send_to_address_without_delivery_succeeds() {
	let ctx = TestContext::new("bark_sdk/send_to_address_without_delivery_succeeds").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;

	// A hard-coded recipient key on an address that opts out of delivery.
	let recipient_pubkey = PublicKey::from_str(
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	).unwrap();
	let own = sender.new_address().await.expect("new address");
	let address = ark::Address::new(
		own.is_testnet(),
		own.ark_id(),
		VtxoPolicy::new_pubkey(recipient_pubkey),
		vec![],
	);

	sender.send_arkoor_payment(&address, sat(100_000)).await
		.expect("send to a delivery-less address must succeed");

	// The send ran to completion and only the change remains spendable.
	assert!(sender.pending_arkoor_sends().await.unwrap().is_empty());
	assert_eq!(sender.balance().await.unwrap().spendable, sat(300_000));
}
