use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::{info, trace};

use ark::{ProtocolEncoding, Vtxo, SECP};
use bitcoin_ext::BlockHeight;
use ark::arkoor::ArkoorDestination;
use ark::attestations::ArkoorCosignAttestation;
use ark::vtxo::Full;
use bark::Wallet;
use bark::lightning_invoice::Bolt11Invoice;
use bark_json::primitives::WalletVtxoInfo;
use server_rpc::protos;
use server::database::Db;
use server::vtxopool::VtxoTarget;

use ark_testing::{Captaind, TestContext, btc, lightning_test, require_bark_version, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::context::LightningPaymentSetup;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{FutureExt, ToAltString};
use ark_testing::exit::complete_exit;


/// Asserts that every unspent entry in `vtxo_pool` (`spent_at IS NULL`)
/// references a `vtxo` row with `spend_state = 'pool'`.
async fn assert_vtxopool_consistency_db(db: &Db) {
	let bad = db.read(async |t| {
		let rows = t.query("
			SELECT vtxo.vtxo_id, vtxo.spend_state::text
			FROM vtxo_pool
			JOIN vtxo ON vtxo.vtxo_id = vtxo_pool.vtxo_id
			WHERE vtxo_pool.spent_at IS NULL AND vtxo.spend_state != 'pool'
		", &[]).await?;
		Ok(rows.into_iter()
			.map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
			.collect::<Vec<_>>())
	}).await.unwrap();
	assert!(bad.is_empty(),
		"vtxo_pool entries with spent_at IS NULL must have spend_state = 'pool'; got: {:?}",
		bad);
}

async fn assert_vtxopool_consistency(srv: &Captaind) {
	let pg_cfg = srv.config().postgres.clone();
	let db = Db::connect(&pg_cfg).await.unwrap();
	assert_vtxopool_consistency_db(&db).await;
}


/// Verify that the server extracts preimages from on-chain HTLC spends
/// and uses them to settle invoices.
///
/// The proxy blocks cooperative settlement, so bark explicitly exits the
/// HTLC VTXOs. The exit publishes the HTLC preimage on-chain, which the
/// server's HtlcSettler extracts to settle the hold invoice.
async fn server_settles_invoice_from_on_chain_htlc_preimage(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	require_bark_version!(> "0.1.4");

	// Block cooperative settlement so the only path to settle
	// the hold invoice is via on-chain preimage extraction.
	#[derive(Clone)]
	struct BlockCooperativeSettlement;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for BlockCooperativeSettlement {
		async fn claim_lightning_receive(
			&self,
			_upstream: &mut ArkClient,
			req: server_rpc::protos::ClaimLightningReceiveRequest,
		) -> Result<server_rpc::protos::ArkoorPackageCosignResponse, tonic::Status> {
			info!("payment preimage: {}", req.payment_preimage.as_hex());
			Err(tonic::Status::invalid_argument("Blocked cooperative settlement"))
		}
	}

	let proxy = srv.start_proxy_no_mailbox(BlockCooperativeSettlement).await;

	// bark_recv connects through the proxy so cooperative settlement is blocked,
	// so the claim fails; the test then exits the HTLC VTXOs explicitly.
	let bark_recv = ctx.bark("bark-recv", &proxy.address).funded(btc(3)).create().await;
	bark_recv.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_recv.sync().await;

	let invoice_info = bark_recv.bolt11_invoice(btc(1)).await;

	srv.wait_for_vtxopool(&ctx).await;

	// pay and receive must be concurrent: pay blocks until the server
	// settles the hold invoice (which only happens after the on-chain exit
	// reveals the preimage).
	tokio::join!(
		pay(invoice_info.invoice.clone()),
		async {
			// Proxy blocks cooperative settlement, so this errors
			let _ = bark_recv.try_lightning_receive(&invoice_info.invoice).await;

			// The failed claim no longer starts an exit on its own; explicitly
			// exit the HTLC VTXOs so the preimage is published on-chain.
			let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
			bark_recv.client().await.attempt_lightning_receive_exit(&invoice).await.unwrap();

			bark_recv.sync().await;
			assert!(!bark_recv.list_exits().await.is_empty(), "Expected exit to be started");

			info!("Doing exit...");
			complete_exit(&ctx, &bark_recv).await;

			bark_recv.claim_all_exits(bark_recv.get_onchain_address().await).await;
			ctx.generate_blocks(1).await;
		},
	);

	assert_vtxopool_consistency(srv).await;
}
lightning_test!(server_settles_invoice_from_on_chain_htlc_preimage, |cfg| {
	// Use a long receive_htlc_forward_timeout so hold invoices stay alive
	// while the exit is driven to completion on-chain.
	cfg.receive_htlc_forward_timeout = Duration::from_secs(5 * 60);
	// To make sure we don't sweep the vtxo before user can broadcast preimage
	cfg.vtxopool.vtxo_lifetime = 2048;
});

/// The server must refuse `request_lightning_pay_htlc_revocation` for a
/// payment that has already settled, returning the preimage in the
/// error message so the caller can recover.
///
/// 1. An external invoice is created.
/// 2. bark pays it normally; the payment settles and the preimage is
///    persisted as a paid invoice.
/// 3. We build a fresh revocation request against the (now-spent) HTLC
///    vtxos and call the server's revocation RPC directly. The server
///    must refuse with `InvalidArgument` and surface the preimage in
///    the error message.
#[tokio::test]
async fn reject_revocation_on_successful_lightning_payment() {
	let ctx = TestContext::new("server/reject_revocation_on_successful_lightning_payment").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).create().await;

	let bark_1 = ctx.bark("bark-1", &srv).funded(btc(7)).create().await;
	bark_1.board(btc(5)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// 1. External invoice.
	let invoice = lightning.external.invoice(
		Some(btc(2)), "test_payment", "A test payment",
	).await;
	lightning.sync().await;

	// 2. bark pays it successfully end-to-end.
	bark_1.try_pay_lightning(&invoice, None, true).await.unwrap();
	let payment_hash: ark::lightning::PaymentHash =
		Bolt11Invoice::from_str(&invoice).unwrap().into();
	let client = bark_1.client().await;
	assert!(
		client.is_invoice_paid(payment_hash).await.unwrap(),
		"payment should have settled",
	);

	// 3. Build a fresh revocation request from the (now-spent) HTLC
	// vtxos still in bark's DB and send it directly to the server.
	let htlc_vtxo_ids = client.all_vtxos().await.unwrap()
		.into_iter()
		.filter_map(|wv| {
			let pol = wv.vtxo.policy().as_server_htlc_send()?;
			(pol.payment_hash == payment_hash).then(|| wv.vtxo.id())
		})
		.collect::<Vec<ark::VtxoId>>();
	assert!(
		!htlc_vtxo_ids.is_empty(),
		"expected HTLC vtxos to remain in DB after settlement",
	);

	let mut htlc_vtxos = Vec::with_capacity(htlc_vtxo_ids.len());
	let mut keypairs = Vec::with_capacity(htlc_vtxo_ids.len());
	for id in &htlc_vtxo_ids {
		let vtxo = client.get_full_vtxo(*id).await.unwrap();
		keypairs.push(client.get_vtxo_key(&vtxo).await.unwrap());
		htlc_vtxos.push(vtxo);
	}

	// Any pubkey works for the revocation output; the test never
	// claims it.
	let revocation_pubkey =
		Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key();
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		htlc_vtxos.iter().cloned(),
		ark::VtxoPolicy::new_pubkey(revocation_pubkey),
	).unwrap().generate_user_nonces(&keypairs).unwrap();

	let cosign_request =
		protos::ArkoorPackageCosignRequest::from(builder.cosign_request());

	let mut srv_rpc = srv.get_public_rpc().await;
	let status = srv_rpc
		.request_lightning_pay_htlc_revocation(cosign_request).await
		.expect_err("server should refuse revocation for a completed payment");

	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(
		status.message().contains("invoice has already been paid, preimage"),
		"unexpected server response: {status:?}",
	);
}

#[tokio::test]
async fn server_refuse_claim_invoice_not_settled() {
	let ctx = TestContext::new("server/server_refuse_claim_invoice_not_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.external).funded(btc(10)).create().await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn claim_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::ClaimLightningReceiveRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			req.payment_preimage = vec![1; 32];
			Ok(upstream.claim_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.bark("bark", &proxy.address).funded(btc(3)).create().await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = invoice_info.clone();
	tokio::spawn(async move { lightning.internal.pay_bolt11(cloned.invoice).await; });
	let err = bark.try_lightning_receive(&invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: preimage doesn't match payment hash"), "err: {err}");

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn server_should_release_hold_invoice_when_subscription_is_canceled() {
	let ctx = TestContext::new("server/server_should_release_hold_invoice_when_subscription_is_canceled").await;
	let cfg_htlc_forward_timeout = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.captaind("server").lightningd(&lightning.external).cfg(move |cfg| {
		// Set the receive_htlc_forward_timeout very short so the subscription
		// gets canceled quickly when the receiver doesn't prepare the claim
		cfg.receive_htlc_forward_timeout = cfg_htlc_forward_timeout
	}).create().await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.bark("bark-1", &srv).funded(btc(3)).create().await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	// Spawn the payment - it will be held by the server until claimed or canceled
	let cloned_invoice_info = invoice_info.clone();
	let sender = Arc::new(lightning.internal);
	let cloned_sender = sender.clone();
	let payment_result = tokio::spawn(async move {
		cloned_sender.try_pay_bolt11(cloned_invoice_info.invoice).await
	});

	// Wait for the HTLC forward timeout to elapse plus time for server to process
	tokio::time::sleep(cfg_htlc_forward_timeout + srv.config().invoice_check_interval).await;

	// The payment should fail because the subscription was canceled (receiver didn't claim)
	let err = payment_result.await.unwrap().unwrap_err().to_alt_string();
	assert!(err.contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");

	// Verify the hold invoice was released by trying to pay again - should also fail
	let err = sender.try_pay_bolt11(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"), "err: {err}");

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn server_generated_invoice_has_configured_expiry() {
	let ctx = TestContext::new("server/server_generated_invoice_has_configured_expiry").await;
	let cfg_invoice_expiry = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.captaind("server").lightningd(&lightning.external).cfg(move |cfg| {
		// Set invoice expiry very short so invoice expires quickly
		cfg.invoice_expiry = cfg_invoice_expiry;
	}).create().await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.bark("bark-1", &srv).funded(btc(3)).create().await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let payment_hash = invoice.payment_hash().to_byte_array().to_vec();

	// Wait for the invoice to expire and for the server to process the cancellation
	tokio::time::sleep(cfg_invoice_expiry + srv.config().invoice_check_interval).await;

	// Verify the server has canceled the HTLC subscription due to invoice expiry
	let mut rpc = srv.get_public_rpc().await;
	let resp = rpc.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: payment_hash,
		wait: false,
	}).await.unwrap().into_inner();
	assert_eq!(resp.status, protos::LightningReceiveStatus::Canceled as i32,
		"expected CANCELED status, got {:?}", resp.status);

	// Sender also rejects expired invoice, confirming expiry was set correctly in the invoice
	let err = lightning.internal.try_pay_bolt11(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("Invoice expired"), "err: {err}");

	assert_vtxopool_consistency(&srv).await;
}

async fn server_claim_lightning_receive_is_idempotent(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	// LightningReceiveInfo changes between 0.2.5 and 0.2.6
	require_bark_version!(> "0.3.0");

	srv.wait_for_vtxopool(&ctx).await;

	let bark = Arc::new(ctx.bark("bark-1", srv).funded(btc(3)).create().await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	tokio::join!(
		pay(invoice_info.invoice.clone()),
		bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000),
	);

	// Wait for the onboarding round to be deeply enough confirmed
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark.spendable_balance().await;

	assert_eq!(bark.spendable_balance().await, btc(3));

	let vtxos_before = bark.vtxo_ids_no_sync().await;
	let status_before = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();
	assert_eq!(status_before.state, "settled");
	assert!(status_before.settled_at.is_some());

	// Claiming again should be a no-op.
	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	assert_eq!(bark.spendable_balance().await, btc(3));
	assert_eq!(bark.vtxo_ids_no_sync().await, vtxos_before);
	assert_eq!(
		bark.lightning_receive_status(&invoice_info.invoice).await.unwrap().settled_at,
		status_before.settled_at,
	);

	assert_vtxopool_consistency(srv).await;
}
lightning_test!(server_claim_lightning_receive_is_idempotent);

async fn server_returned_htlc_recv_vtxos_identical(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	// LightningReceiveInfo changes between 0.2.5 and 0.2.6
	require_bark_version!(> "0.3.0");

	srv.wait_for_vtxopool(&ctx).await;

	let bark = ctx.bark("bark-1", srv).funded(btc(3)).create().await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let mut client = srv.get_public_rpc().await;

	// pay runs concurrently with the gRPC assertions. In intra mode
	// pay_lightning_wait blocks forever (no one claims), so we use select!
	// to drop pay once the assertions complete.
	tokio::select! {
		_ = pay(invoice_info.invoice) => {},
		_ = async {
			// Wait for the payment to be received
			client.check_lightning_receive(protos::CheckLightningReceiveRequest {
				hash: receive.payment_hash.to_vec(),
				wait: true,
			}).wait_millis(10_000).await.unwrap().into_inner();

			let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
			let req_1 = protos::PrepareLightningReceiveClaimRequest {
				payment_hash: receive.payment_hash.to_vec(),
				user_pubkey: keypair.public_key().serialize().to_vec(),
				htlc_recv_expiry: 172,
				lightning_receive_anti_dos: None,
			};
			let vtxos_1 = client.prepare_lightning_receive_claim(req_1.clone()).await.unwrap()
				.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
				.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();
			assert!(vtxos_1.iter().all(|v| v.has_all_witnesses()), "first call vtxos should be fully signed");

			// We test once again with the same request
			let vtxos_2 = client.prepare_lightning_receive_claim(req_1).await.unwrap()
				.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
				.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();
			assert!(vtxos_2.iter().all(|v| v.has_all_witnesses()), "retry call vtxos should be fully signed");

			// we change keypair to make sure server don't use it on second request
			let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
			let req_2 = protos::PrepareLightningReceiveClaimRequest {
				payment_hash: receive.payment_hash.to_vec(),
				user_pubkey: keypair.public_key().serialize().to_vec(),
				htlc_recv_expiry: 172,
				lightning_receive_anti_dos: None,
			};

			let vtxos_3 = client.prepare_lightning_receive_claim(req_2).await.unwrap()
				.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
				.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();
			assert!(vtxos_3.iter().all(|v| v.has_all_witnesses()), "third call vtxos should be fully signed");

			assert_eq!(vtxos_1, vtxos_2, "should have the same VTXOs");
			assert_eq!(vtxos_1, vtxos_3, "should have the same VTXOs");
		} => {},
	}

	assert_vtxopool_consistency(srv).await;
}
lightning_test!(server_returned_htlc_recv_vtxos_identical);

/// The server must refuse an HTLC-recv expiry that doesn't leave at
/// least `htlc_expiry_delta` blocks of margin below the inbound
/// Lightning HTLC's expiry. Otherwise a receiver could wait for the
/// inbound HTLC to time out and still claim the Ark VTXO.
async fn refuses_htlc_recv_expiry_past_lowest_incoming_htlc_expiry(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	srv.wait_for_vtxopool(&ctx).await;

	let bark = ctx.bark("bark-1", srv).funded(btc(3)).create().await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let mut client = srv.get_public_rpc().await;
	let htlc_expiry_delta = srv.config().htlc_expiry_delta as BlockHeight;

	tokio::select! {
		_ = pay(invoice_info.invoice) => {},
		_ = async {
			client.check_lightning_receive(protos::CheckLightningReceiveRequest {
				hash: receive.payment_hash.to_vec(),
				wait: true,
			}).wait_millis(10_000).await.unwrap().into_inner();

			let pg_cfg = srv.config().postgres.clone();
			let db = Db::connect(&pg_cfg).await.unwrap();
			let sub = db.read(async |t|
				t.get_htlc_subscription_by_payment_hash(receive.payment_hash).await
			).await.unwrap().expect("subscription should exist");
			let lowest = sub.lowest_incoming_htlc_expiry
				.expect("Accepted subscription must have lowest_incoming_htlc_expiry");

			// Boundary: requested + delta == lowest + 1. Server must refuse.
			let attacker_expiry = lowest - htlc_expiry_delta + 1;
			let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
			let req = protos::PrepareLightningReceiveClaimRequest {
				payment_hash: receive.payment_hash.to_vec(),
				user_pubkey: keypair.public_key().serialize().to_vec(),
				htlc_recv_expiry: attacker_expiry,
				lightning_receive_anti_dos: None,
			};
			let err = client.prepare_lightning_receive_claim(req).await
				.expect_err("server must refuse htlc_recv_expiry + delta >= lowest");
			assert_eq!(err.code(), tonic::Code::InvalidArgument,
				"unexpected error: {err:?}");
			assert!(
				err.message().contains("too close to inbound HTLC expiry"),
				"unexpected error message: {}", err.message(),
			);

			// Just below the boundary: requested + delta == lowest. Must accept.
			let safe_expiry = lowest - htlc_expiry_delta ;
			let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
			let req_safe = protos::PrepareLightningReceiveClaimRequest {
				payment_hash: receive.payment_hash.to_vec(),
				user_pubkey: keypair.public_key().serialize().to_vec(),
				htlc_recv_expiry: safe_expiry,
				lightning_receive_anti_dos: None,
			};
			client.prepare_lightning_receive_claim(req_safe).await
				.expect("server must accept htlc_recv_expiry just below the safety bound");
		} => {},
	}

	assert_vtxopool_consistency(srv).await;
}
lightning_test!(refuses_htlc_recv_expiry_past_lowest_incoming_htlc_expiry);

#[tokio::test]
async fn should_refuse_paying_invoice_not_matching_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_not_matching_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let dummy_invoice = lightning.external.invoice(None, "dummy_invoice", "A dummy invoice").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.external).funded(btc(10)).create().await;

	#[derive(Clone)]
	struct Proxy(String);
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.invoice = self.0.clone();
			let err = upstream.initiate_lightning_payment(req).await.unwrap_err();
			assert!(
				err.message().contains("htlc payment hash doesn't match invoice"),
				"unexpected server error: {}", err.message(),
			);
			Err(err)
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(dummy_invoice)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.bark("bark-1", &proxy.address).funded(btc(3)).create().await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.external.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	bark_1.try_pay_lightning(invoice, None, false).await.unwrap();
}

#[tokio::test]
async fn should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.external).funded(btc(10)).create().await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.htlc_vtxo_ids.pop();
			let err = upstream.initiate_lightning_payment(req).await.unwrap_err();
			assert!(
				err.message().contains("HTLC VTXO sum of")
					&& err.message().contains("is less than the payment amount of"),
				"unexpected server error: {}", err.message(),
			);
			Err(err)
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.bark("bark-1", &proxy.address).funded(btc(3)).create().await;
	bark_1.board(btc(0.5)).await;
	bark_1.board(btc(0.6)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.sync().await;

	let invoice = lightning.external.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	bark_1.try_pay_lightning(invoice, None, false).await.unwrap();
}

#[tokio::test]
async fn should_refuse_ln_pay_input_vtxo_that_is_being_exited() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("server/should_refuse_ln_pay_input_vtxo_that_is_being_exited").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.lightningd("lightningd-1").create().await;

	let srv = ctx.captaind("server").lightningd(&lightningd).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board(sat(400_000)).await;
	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// We created 2 vtxos, exit A so wallet will be able to spend B. But then we tweak the request to try spending A.
	let [vtxo_a, _vtxo_b] = bark.vtxos().await.try_into().unwrap();

	bark.start_exit_vtxos(&[vtxo_a.id]).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(596_429));

	#[derive(Clone)]
	struct Proxy(Wallet, WalletVtxoInfo);
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn request_lightning_pay_htlc_cosign(
			&self, upstream: &mut ArkClient, mut req: protos::LightningPayHtlcCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			let (_, keypair) = self.0.pubkey_keypair(&self.1.user_pubkey).await.unwrap().unwrap();

			let outputs = req.parts[0].outputs.iter()
				.chain(&req.parts[0].isolated_outputs)
				.map(|o| ArkoorDestination::try_from(o.clone()).unwrap())
				.collect::<Vec<_>>();
			let output_refs = outputs.iter().collect::<Vec<_>>();

			let sig = ArkoorCosignAttestation::new(self.1.id, &output_refs, &keypair);

			req.parts[0].input_vtxo_id = self.1.id.to_bytes().to_vec();
			req.parts[0].attestation = sig.serialize().to_vec();
			Ok(upstream.request_lightning_pay_htlc_cosign(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(
		Proxy(bark.client().await, vtxo_a.clone())
	).await;

	bark.set_ark_url(&proxy.address).await;

	let invoice = lightningd.invoice(Some(sat(100_000)), "real invoice", "A real invoice").await;

	let err = bark.try_pay_lightning(&invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains(&format!(
		"bad user input: cannot spend vtxo that is already exited: {}", vtxo_a.id,
	)), "err: {err}");
}

#[tokio::test]
async fn should_allow_dust_lightning_receive_request() {
	let ctx = TestContext::new("server/should_allow_dust_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.lightningd("lightningd-1").create().await;

	let srv = ctx.captaind("server").lightningd(&lightningd).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark.try_bolt11_invoice(sat(300)).await.unwrap();

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn should_refuse_over_max_vtxo_amount_lightning_receive_request() {
	let ctx = TestContext::new("server/should_refuse_over_max_vtxo_amount_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.lightningd("lightningd-1").create().await;

	let srv = ctx.captaind("server").lightningd(&lightningd).cfg(|cfg| {
		cfg.max_vtxo_amount = Some(sat(1_000_000));
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn start_lightning_receive(
			&self, upstream: &mut ArkClient, mut req: protos::StartLightningReceiveRequest,
		) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
			req.amount_sat = 1_000_001;
			Ok(upstream.start_lightning_receive(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	bark.set_ark_url(&proxy.address).await;

	let err = bark.try_bolt11_invoice(sat(30_000)).await.unwrap_err().to_alt_string();
	assert!(err.contains("Requested amount exceeds limit of 0.01000000 BTC"), "err: {err}");

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn server_can_use_multi_input_from_vtxo_pool() {
	let ctx = TestContext::new("server/server_can_use_multi_input_from_vtxo_pool").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.external).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 5, amount: sat(100_000) },
		];
	}).create().await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.bark("bark", &srv).funded(btc(3)).create().await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = sat(200_000);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.internal.pay_bolt11(cloned_invoice_info.invoice).await
	});

	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	// We use that to sync and get onboarded vtxos
	let balance = bark.spendable_balance().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(balance, pay_amount + board_amount);

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn server_can_use_vtxo_pool_change_for_next_receive() {
	let ctx = TestContext::new("server/server_can_use_vtxo_pool_change_for_next_receive").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.external).cfg(|cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 5, amount: sat(100_000) },
		];
	}).create().await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.bark("bark", &srv).funded(btc(3)).create().await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let first_pay_amount = sat(50_000);
	let second_pay_amount = sat(25_000);

	let sender = Arc::new(lightning.internal);

	// First block consumes only vtxo of the pool
	{
		let invoice_info = bark.bolt11_invoice(first_pay_amount).await;

		let cloned_invoice_info = invoice_info.clone();
		let cloned_sender = sender.clone();
		let res1 = tokio::spawn(async move {
			cloned_sender.pay_bolt11(cloned_invoice_info.invoice).await
		});


		bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;
		// HTLC settlement on lightning side
		res1.ready().await.unwrap();
	}

	// Second block consumes change from the first block
	{
		let invoice_info = bark.bolt11_invoice(second_pay_amount).await;

		let cloned_invoice_info = invoice_info.clone();
		let cloned_sender = sender.clone();
		let res1 = tokio::spawn(async move {
			cloned_sender.pay_bolt11(cloned_invoice_info.invoice).await
		});


		bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;
		// HTLC settlement on lightning side
		res1.ready().await.unwrap();
	}

	// We use that to sync and get onboarded vtxos
	let balance = bark.spendable_balance().await;

	assert_eq!(balance, first_pay_amount + second_pay_amount + board_amount);

	assert_vtxopool_consistency(&srv).await;
}

#[tokio::test]
async fn initiate_lightning_payment_fails_without_register_vtxo_transactions() {
	let ctx = TestContext::new("server/initiate_lightning_payment_fails_without_register_vtxo_transactions").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	// Create a proxy that drops register_vtxo_transactions calls (returns success without calling upstream)
	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_vtxo_transactions(
			&self, _upstream: &mut ArkClient, _req: protos::RegisterVtxoTransactionsRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// Drop the call - return success but don't register with upstream
			Ok(protos::Empty {})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.bark("bark-1", &proxy.address).funded(btc(3)).create().await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.external.invoice(Some(btc(1)), "test_payment", "A test payment").await;

	// The payment should fail because register_vtxo_transactions was dropped:
	// the HTLC vtxo stays in `unregistered` state, and check_spendable rejects it.
	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err();
	assert!(err.to_string().contains("not spendable") && err.to_string().contains("unregistered"),
		"Expected error about unregistered vtxo, got: {err}");
}

/// Verify that `check_lightning_receive` returns via the 30-second
/// poll-interval fallback when the broadcast notification is not
/// received.
///
/// Calls `check_lightning_receive_with_rx` with a disconnected
/// broadcast receiver so the notification can never arrive.  The
/// payment is sent concurrently; the server can only detect the
/// status change through the poll fallback.  Asserts the call took
/// at least 28 seconds.
#[tokio::test]
async fn check_lightning_receive_poll_interval_fallback() {
	let ctx = TestContext::new("server/check_lightning_receive_poll_interval_fallback").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_server_with_cfg("server", Some(&lightning.internal), |_| {}).await;

	// Create a preimage and derive the payment hash.
	let preimage = ark::lightning::Preimage::from(rand::random::<[u8; 32]>());
	let payment_hash = preimage.compute_payment_hash();

	// Create a hold invoice on the server.
	let resp = srv.start_lightning_receive(payment_hash, btc(1), 18, None, None).await.unwrap();

	// Create a disconnected receiver: the sender is kept alive so
	// recv() blocks forever instead of returning Closed.
	let (_no_op_tx, mut disconnected_rx) =
		tokio::sync::broadcast::channel::<ark::lightning::PaymentHash>(1);

	let start = std::time::Instant::now();

	// Pay the invoice in the background.  The hold plugin will hold
	// the HTLC so pay_bolt11 blocks until settled or canceled.
	let bolt11 = resp.bolt11;
	tokio::spawn(async move {
		lightning.external.pay_bolt11(bolt11).await;
	});

	// check_lightning_receive_with_rx uses a disconnected receiver so
	// the notification can never arrive.  It can only detect the status
	// change through the 30-second poll fallback.
	let srv_clone = srv.clone();
	let sub = tokio::spawn(async move {
		srv_clone.check_lightning_receive_with_rx(
			payment_hash, true, &mut disconnected_rx,
		).await.unwrap()
	}).await.unwrap();
	let elapsed = start.elapsed();

	assert_eq!(
		sub.status,
		server::database::ln::LightningHtlcSubscriptionStatus::Accepted,
		"expected Accepted status, got {:?}", sub.status,
	);
	assert!(
		elapsed >= Duration::from_secs(28),
		"expected at least ~30s for poll fallback, but took {:?}", elapsed,
	);

	assert_vtxopool_consistency_db(srv.database()).await;
}
