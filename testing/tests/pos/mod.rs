//! End-to-end tests of posd, the point-of-sale service.
//!
//! posd runs in the test process against a real Ark server, a barkd that
//! forwards Lightning receives, lightningd nodes and bitcoind. The store
//! owner's wallet registers the store and then goes offline for every sale.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::{Amount, Network};
use bitcoin_ext::BlockDelta;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use ark::SECP;
use bark::Wallet;
use bark::payment_request::PaymentRequest;

use ark_testing::{Captaind, TestContext, btc, sat};
use ark_testing::context::LightningPaymentSetup;
use ark_testing::pos::Posd;
use pos::registration::Registration;


const SALE_TIMEOUT: Duration = Duration::from_secs(90);

/// A store: the Ark server, posd, an owner token and a paired terminal.
struct Store {
	srv: Arc<Captaind>,
	lightning: LightningPaymentSetup,
	posd: Posd,
	owner_seed: bip39::Mnemonic,
	owner_token: String,
	till: String,
	// Kept alive for posd.
	_forwarder: ark_testing::Barkd,
}

/// The public descriptor of the host app's on-chain account of the owner.
fn owner_descriptor() -> String {
	let xpriv = Xpriv::new_master(Network::Regtest, &[42u8; 32]).unwrap();
	format!("tr({}/0/*)", Xpub::from_priv(&SECP, &xpriv))
}

async fn store_setup(ctx: &TestContext) -> Store {
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.ln_receive_ark_address_hints = true;
		}).create().await;
	// Lightning receives draw their VTXOs from the pool. Confirm the pool
	// transaction, so a node that starts later knows the VTXO anchor.
	srv.wait_for_vtxopool(ctx).await;
	ctx.generate_blocks(1).await;
	let forwarder = ctx.barkd("forwarder", &*srv).create().await;

	// The owner registers the store, then goes offline.
	let owner_seed = bip39::Mnemonic::generate(12).unwrap();
	let owner = ctx.bark_sdk("owner", &srv).mnemonic(owner_seed.clone()).create().await;
	// The owner's wallet signs the registration with its plain message
	// signing: nothing in the wallet is specific to the point of sale.
	let address = owner.new_address().await.unwrap();
	let registration = Registration {
		name: "Café Uvita".into(),
		ark_address: address.to_string(),
		mailbox_id: owner.mailbox_identifier().to_string(),
		onchain_descriptor: owner_descriptor(),
		currency: "CRC".into(),
		timestamp: chrono::Utc::now().timestamp() as u64,
	};
	let signature = owner.sign_message(registration.message().as_bytes(), &address)
		.await.unwrap().expect("the owner holds the key");

	let posd = Posd::start(ctx, &srv, &forwarder).await;
	posd.register(serde_json::to_value(&registration).unwrap(), signature.to_string()).await;
	let challenge = posd.challenge(&registration.ark_address).await;
	let login_sig = owner.sign_message(challenge.as_bytes(), &address)
		.await.unwrap().expect("the owner holds the key");
	let owner_token = posd.login(&registration.ark_address, &challenge, login_sig.to_string()).await;
	drop(owner);
	let till = posd.pair(&owner_token, "Front till").await;

	Store { srv, lightning, posd, owner_seed, owner_token, till, _forwarder: forwarder }
}

async fn new_sale(store: &Store, body: Value) -> Value {
	store.posd.ok(Method::POST, "/api/v1/sales", Some(&store.till), Some(body)).await
}

/// A payer that pays a payment request the default way.
async fn pay(payer: &Wallet, payment_request: &str) -> String {
	let req: PaymentRequest = payer.parse_payment_request(payment_request).await.unwrap();
	let option = req.default_option().expect("no usable payment option").clone();
	let kind = option.method.type_str().to_string();
	payer.send_payment(&option.method, None, None::<String>, true).await.unwrap();
	kind
}

/// The owner restores the wallet from the seed phrase and sees the funds.
async fn owner_restores(ctx: &TestContext, store: &Store, at_least: Amount) {
	let restored = ctx.bark_sdk("owner-restored", &store.srv)
		.mnemonic(store.owner_seed.clone()).create().await;
	let deadline = tokio::time::Instant::now() + SALE_TIMEOUT;
	loop {
		restored.sync().await;
		let balance = restored.balance().await.unwrap();
		if balance.spendable >= at_least {
			return;
		}
		assert!(tokio::time::Instant::now() < deadline,
			"owner has {} spendable, expected at least {}", balance.spendable, at_least);
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
}

#[tokio::test]
async fn pos_sale_paid_by_lightning() {
	let ctx = TestContext::new("pos/pos_sale_paid_by_lightning").await;
	let store = store_setup(&ctx).await;

	// 12,500 CRC at the test price is 20,000 sats, below the on-chain minimum.
	let sale = new_sale(&store, json!({ "fiat_amount": "12500", "memo": "2 coffees" })).await;
	assert_eq!(sale["state"], "open");
	assert_eq!(sale["amount_sat"], 20_000);
	assert_eq!(sale["fiat_amount"], "12500.00");
	assert_eq!(sale["onchain_address"], Value::Null);
	let pr = sale["payment_request"].as_str().unwrap();
	assert!(pr.starts_with("bitcoin:?lightning="), "{}", pr);
	assert!(pr.contains("&ark-lightning="), "{}", pr);

	store.lightning.external.pay_bolt11(sale["lightning_invoice"].as_str().unwrap()).await;
	let id = sale["id"].as_str().unwrap();
	let paid = store.posd.wait_sale_state(&store.till, id, "paid", SALE_TIMEOUT).await;
	assert_eq!(paid["paid_rail"], "lightning");

	owner_restores(&ctx, &store, sat(15_000)).await;

	let csv = reqwest::Client::new().get(format!("{}/api/v1/sales.csv", store.posd.url))
		.bearer_auth(&store.till).send().await.unwrap().text().await.unwrap();
	assert!(csv.contains(id) && csv.contains("2 coffees") && csv.contains(",paid,lightning,"), "{}", csv);
}

#[tokio::test]
async fn pos_sale_paid_by_ark() {
	let ctx = TestContext::new("pos/pos_sale_paid_by_ark").await;
	let store = store_setup(&ctx).await;
	let payer = ctx.bark_sdk("payer", &store.srv).boarded(sat(200_000))
		.cfg(|cfg| cfg.direct_pay_min_expiry = BlockDelta::new(10))
		.create().await;

	let sale = new_sale(&store, json!({ "amount_sat": 30_000 })).await;
	let id = sale["id"].as_str().unwrap();
	let kind = pay(&payer, sale["payment_request"].as_str().unwrap()).await;
	let paid = store.posd.wait_sale_state(&store.till, id, "paid", SALE_TIMEOUT).await;
	assert_eq!(paid["paid_rail"], "ark", "payer chose {}", kind);
	assert_eq!(paid["received_sat"], 30_000);

	// A second payment of the same sale is recorded as excess. The
	// forwarding invoice was canceled when the Ark payment arrived, so pay
	// the hinted invoice again: the server refuses a settled invoice.
	let again = payer.parse_payment_request(sale["payment_request"].as_str().unwrap()).await.unwrap();
	let option = again.default_option().expect("an option").clone();
	assert!(payer.send_payment(&option.method, None, None::<String>, true).await.is_err(),
		"the server must refuse to pay a settled hinted invoice twice");

	owner_restores(&ctx, &store, sat(30_000)).await;
}

#[tokio::test]
async fn pos_payer_without_long_lived_vtxos_pays_lightning() {
	let ctx = TestContext::new("pos/pos_payer_without_long_lived_vtxos_pays_lightning").await;
	let store = store_setup(&ctx).await;
	// No VTXO lives this long, so the payer must not pay the hinted invoice.
	let payer = ctx.bark_sdk("payer", &store.srv).boarded(sat(200_000))
		.cfg(|cfg| cfg.direct_pay_min_expiry = BlockDelta::new(60_000))
		.create().await;

	let sale = new_sale(&store, json!({ "amount_sat": 25_000 })).await;
	let id = sale["id"].as_str().unwrap();
	pay(&payer, sale["payment_request"].as_str().unwrap()).await;
	let paid = store.posd.wait_sale_state(&store.till, id, "paid", SALE_TIMEOUT).await;
	assert_eq!(paid["paid_rail"], "lightning");
}

#[tokio::test]
async fn pos_sale_paid_onchain() {
	let ctx = TestContext::new("pos/pos_sale_paid_onchain").await;
	let store = store_setup(&ctx).await;

	// At or above the 50,000-sat minimum, the sale offers an address.
	let sale = new_sale(&store, json!({ "amount_sat": 60_000 })).await;
	let id = sale["id"].as_str().unwrap();
	let address = sale["onchain_address"].as_str().expect("an on-chain address").to_string();
	assert!(sale["payment_request"].as_str().unwrap()
		.starts_with(&format!("bitcoin:{}?amount=0.0006&lightning=", address)));
	let second = new_sale(&store, json!({ "amount_sat": 60_000 })).await;
	assert_ne!(second["onchain_address"].as_str().unwrap(), address, "each sale has its own address");

	ctx.bitcoind().fund_addr(&address, sat(60_000)).await;
	store.posd.wait_sale_state(&store.till, id, "in-progress", SALE_TIMEOUT).await;
	ctx.generate_blocks(1).await;
	let paid = store.posd.wait_sale_state(&store.till, id, "paid", SALE_TIMEOUT).await;
	assert_eq!(paid["paid_rail"], "onchain");
	assert_eq!(paid["received_sat"], 60_000);
}

#[tokio::test]
async fn pos_pairing_and_lightning_address() {
	let ctx = TestContext::new("pos/pos_pairing_and_lightning_address").await;
	let store = store_setup(&ctx).await;
	let posd = &store.posd;

	// A pairing code works once.
	let invite = posd.ok(Method::POST, "/api/v1/owner/invites", Some(&store.owner_token), None).await;
	let body = json!({ "code": invite["code"], "device_name": "Back till" });
	let paired = posd.ok(Method::POST, "/api/v1/pair", None, Some(body.clone())).await;
	let (status, _) = posd.call(Method::POST, "/api/v1/pair", None, Some(body)).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let back_till = paired["token"].as_str().unwrap();

	// The owner revokes the device, and its token stops working.
	let devices = posd.ok(Method::GET, "/api/v1/owner/devices", Some(&store.owner_token), None).await;
	let back = devices["devices"].as_array().unwrap().iter()
		.find(|d| d["name"] == "Back till").unwrap()["id"].as_i64().unwrap();
	let (status, _) = posd.call(Method::DELETE, &format!("/api/v1/owner/devices/{}", back),
		Some(&store.owner_token), None).await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	let (status, _) = posd.call(Method::GET, "/api/v1/terminal", Some(back_till), None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	posd.ok(Method::GET, "/api/v1/terminal", Some(&store.till), None).await;

	// A terminal cannot use owner endpoints.
	let (status, _) = posd.call(Method::POST, "/api/v1/owner/invites", Some(&store.till), None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);

	// Lightning address.
	let updated = posd.ok(Method::PATCH, "/api/v1/owner/store", Some(&store.owner_token),
		Some(json!({ "lightning_address_name": "cafe" }))).await;
	assert!(updated["lightning_address"].as_str().unwrap().starts_with("cafe@"));
	let pay_request = posd.ok(Method::GET, "/.well-known/lnurlp/cafe", None, None).await;
	assert_eq!(pay_request["tag"], "payRequest");
	let callback = pay_request["callback"].as_str().unwrap();
	let path = callback.strip_prefix(&posd.url).unwrap();
	let invoice = posd.ok(Method::GET, &format!("{}?amount=21000000", path), None, None).await;
	store.lightning.external.pay_bolt11(invoice["pr"].as_str().unwrap()).await;

	let deadline = tokio::time::Instant::now() + SALE_TIMEOUT;
	loop {
		let sales = posd.ok(Method::GET, "/api/v1/owner/sales", Some(&store.owner_token), None).await;
		let sale = &sales["sales"][0];
		assert_eq!(sale["device_name"], Value::Null);
		assert_eq!(sale["amount_sat"], 21_000);
		assert_eq!(sale["ark_invoice"], Value::Null, "a Lightning address sale has no hinted invoice");
		if sale["state"] == "paid" {
			break;
		}
		assert!(tokio::time::Instant::now() < deadline, "Lightning address sale not paid");
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

/// A manual demo, not run by default. It starts a full stack, prints a
/// pairing link for the terminal and pays every sale the terminal creates
/// from a scuttle wallet. Run it with
/// `cargo nextest run -p ark-testing --test pos --run-ignored only pos_demo`
/// and open the link in a browser. POS_DEMO_SECS sets how long it runs.
#[tokio::test]
#[ignore]
async fn pos_demo() {
	let ctx = TestContext::new("pos/pos_demo").await;
	let store = store_setup(&ctx).await;
	let payer = ctx.bark_sdk("payer", &store.srv).boarded(sat(2_000_000))
		.cfg(|cfg| cfg.direct_pay_min_expiry = BlockDelta::new(10))
		.create().await;
	let invite = store.posd.ok(Method::POST, "/api/v1/owner/invites", Some(&store.owner_token), None).await;
	println!("POS_DEMO_PAIRING_URL {}", invite["url"].as_str().unwrap());
	eprintln!("POS_DEMO_PAIRING_URL {}", invite["url"].as_str().unwrap());

	let secs = std::env::var("POS_DEMO_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(900);
	let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
	let mut paid = std::collections::HashSet::new();
	while tokio::time::Instant::now() < deadline {
		let sales = store.posd.ok(Method::GET, "/api/v1/owner/sales", Some(&store.owner_token), None).await;
		for sale in sales["sales"].as_array().unwrap() {
			let id = sale["id"].as_str().unwrap().to_string();
			if sale["state"] == "open" && sale["device_name"] != "Front till" && paid.insert(id.clone()) {
				// Give the screen time to show the QR code.
				tokio::time::sleep(Duration::from_secs(4)).await;
				let kind = pay(&payer, sale["payment_request"].as_str().unwrap()).await;
				eprintln!("POS_DEMO paid sale {} by {}", id, kind);
			}
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
}
