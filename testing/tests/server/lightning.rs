use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Amount;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use futures::future::join_all;
use log::{info, trace};

use ark::{ProtocolEncoding, Vtxo, SECP};
use bitcoin_ext::BlockHeight;
use ark::arkoor::ArkoorDestination;
use ark::attestations::ArkoorCosignAttestation;
use ark::vtxo::Full;
use ark::vtxo::policy::VtxoPolicyKind;
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

/// The number of HTLC-receive VTXOs the server has ever allocated.
async fn count_htlc_recv_vtxos(db: &Db) -> usize {
	db.read(async |t| {
		let row = t.query_one("
			SELECT COUNT(*) FROM vtxo WHERE policy_type = 'server-htlc-receive'
		", &[]).await?;
		Ok(row.get::<_, i64>(0) as usize)
	}).await.unwrap()
}

async fn assert_vtxopool_consistency(srv: &Captaind) {
	let pg_cfg = srv.config().postgres.clone();
	let db = Db::connect(&pg_cfg).await.unwrap();
	assert_vtxopool_consistency_db(&db).await;
}

/// The HTLC-send vtxos `client` holds for `payment_hash`.
async fn htlc_send_vtxo_ids(
	client: &Wallet,
	payment_hash: ark::lightning::PaymentHash,
) -> Vec<ark::VtxoId> {
	let ids = client.all_vtxos().await.unwrap()
		.into_iter()
		.filter_map(|wv| {
			let pol = wv.vtxo.policy().as_server_htlc_send()?;
			(pol.payment_hash == payment_hash).then(|| wv.vtxo.id())
		})
		.collect::<Vec<ark::VtxoId>>();
	assert!(!ids.is_empty(), "the payment should have left HTLC vtxos in the wallet");
	ids
}

/// Build a "claim all" revocation request from the HTLC-send vtxos `client`
/// still holds for `payment_hash`, send it straight to the server, and return
/// the error the server responds with (the caller asserts on it).
async fn request_htlc_revocation(
	srv: &Captaind,
	client: &Wallet,
	payment_hash: ark::lightning::PaymentHash,
) -> tonic::Status {
	let htlc_vtxo_ids = htlc_send_vtxo_ids(client, payment_hash).await;

	let mut htlc_vtxos = Vec::with_capacity(htlc_vtxo_ids.len());
	let mut keypairs = Vec::with_capacity(htlc_vtxo_ids.len());
	for id in &htlc_vtxo_ids {
		let vtxo = client.get_full_vtxo(*id).await.unwrap();
		keypairs.push(client.get_vtxo_key(&vtxo).await.unwrap());
		htlc_vtxos.push(vtxo);
	}

	// Any pubkey works for the revocation output; the tests never claim it.
	let revocation_pubkey =
		Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key();
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		htlc_vtxos.iter().cloned(),
		ark::VtxoPolicy::new_pubkey(revocation_pubkey),
	).unwrap().generate_user_nonces(&keypairs).unwrap();

	let cosign_request =
		protos::ArkoorPackageCosignRequest::from(builder.cosign_request());

	let mut srv_rpc = srv.get_public_rpc().await;
	srv_rpc
		.request_lightning_pay_htlc_revocation(cosign_request).await
		.expect_err("server should refuse revocation for a settled payment")
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

	// 3. Build a fresh revocation request from the (now-spent) HTLC vtxos
	// still in bark's DB and send it directly to the server.
	let status = request_htlc_revocation(&srv, &client, payment_hash).await;

	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(
		status.message().contains("invoice has already been paid, preimage"),
		"unexpected server response: {status:?}",
	);
}

/// Revocation must be refused whenever the invoice is settled, even if the
/// recorded payment-attempt status has diverged from the settlement. The
/// settler (the `htlc_settlement` table) is the source of truth, not the
/// status: the node can settle without the status write committing.
///
/// This locks the fix from commit 1c1613335. With the old code, a status that
/// on its own permits revocation (here, `failed`) would let the server sign the
/// revocation and refund a payment that actually went through: a double-pay.
///
/// Note this exercises the settler gate as a whole (the early `is_settled`
/// bail fires first, since the settlement row is left intact): it pins that the
/// settler, not the attempt status, decides. Isolating the in-write-tx recheck
/// specifically would need a settlement committed between the two checks within
/// a single request, which isn't reproducible without fault injection.
#[tokio::test]
async fn reject_revocation_when_settled_but_status_regressed() {
	let ctx = TestContext::new("server/reject_revocation_when_settled_but_status_regressed").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).create().await;

	let bark_1 = ctx.bark("bark-1", &srv).funded(btc(7)).create().await;
	bark_1.board(btc(5)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice = lightning.external.invoice(
		Some(btc(2)), "test_payment", "A test payment",
	).await;
	lightning.sync().await;

	bark_1.try_pay_lightning(&invoice, None, true).await.unwrap();
	let payment_hash: ark::lightning::PaymentHash =
		Bolt11Invoice::from_str(&invoice).unwrap().into();
	let client = bark_1.client().await;
	assert!(
		client.is_invoice_paid(payment_hash).await.unwrap(),
		"payment should have settled",
	);

	// Force the attempt status to diverge from the settlement: the preimage
	// stays in htlc_settlement, but the status regresses to `failed`, which on
	// its own would make the attempt eligible for revocation.
	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	db.write(async |t| {
		t.query(
			"UPDATE lightning_payment_attempt SET status = 'failed', updated_at = NOW() WHERE payment_hash = $1",
			&[&payment_hash.to_string()],
		).await?;
		Ok(())
	}).await.unwrap();

	// Build a fresh revocation request from the (now-spent) HTLC vtxos still in
	// bark's DB and send it directly to the server.
	let status = request_htlc_revocation(&srv, &client, payment_hash).await;

	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(
		status.message().contains("invoice has already been paid, preimage"),
		"unexpected server response: {status:?}",
	);
}

/// Requests the server to sign a HTLC while using a HTCL VTXO as an input
async fn request_second_htlc_cosign(
	ctx: &TestContext,
	srv: &Captaind,
	client: &Wallet,
	htlc_vtxo_ids: &[ark::VtxoId],
) -> tonic::Status {
	let mut htlc_vtxos = Vec::with_capacity(htlc_vtxo_ids.len());
	let mut keypairs = Vec::with_capacity(htlc_vtxo_ids.len());
	for id in htlc_vtxo_ids {
		let vtxo = client.get_full_vtxo(*id).await.unwrap();
		keypairs.push(client.get_vtxo_key(&vtxo).await.unwrap());
		htlc_vtxos.push(vtxo);
	}

	// A payment hash the server has never seen, so the request gets past the
	// already-paid and already-in-progress gates and reaches the input checks.
	let second_hash = ark::lightning::PaymentHash::from(
		sha256::Hash::hash(b"a second invoice").to_byte_array(),
	);
	let tip = ctx.bitcoind().get_block_count().await as BlockHeight;
	let htlc_expiry = tip + srv.config().htlc_send_expiry_delta as BlockHeight + 2;
	let htlc_key = Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key();
	let outputs = vec![ArkoorDestination {
		total_amount: htlc_vtxos.iter().map(|v| v.amount()).sum(),
		policy: ark::VtxoPolicy::new_server_htlc_send(htlc_key, second_hash, htlc_expiry),
	}];

	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_with_checkpoints(
		htlc_vtxos.clone(), outputs,
	).unwrap().generate_user_nonces(&keypairs).unwrap();

	let mut srv_rpc = srv.get_public_rpc().await;
	srv_rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: protos::ArkoorPackageCosignRequest::from(builder.cosign_request()).parts,
	}).await.expect_err("server should refuse an HTLC vtxo as a lightning-send cosign input")
}

/// HTLC VTXOs should not be accepted as inputs for spends (arkoor, rounds or offboards).
#[tokio::test]
async fn refuse_generic_spends_of_htlc_send_vtxo_while_payment_in_flight() {
	let ctx = TestContext::new(
		"server/refuse_generic_spends_of_htlc_send_vtxo_while_payment_in_flight",
	).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	// The receiver invoices through the server and never claims, so the
	// payment it funds never settles.
	let bark_recv = ctx.bark("bark-recv", &srv).funded(btc(3)).create().await;
	bark_recv.board_and_confirm_and_register(&ctx, btc(2)).await;
	srv.wait_for_vtxopool(&ctx).await;
	let invoice_info = bark_recv.bolt11_invoice(btc(1)).await;

	let bark_atk = ctx.bark("bark-atk", &srv).funded(btc(3)).create().await;
	bark_atk.board_and_confirm_and_register(&ctx, btc(2)).await;

	// Without `--wait` this returns as soon as the server has been told to pay.
	bark_atk.try_pay_lightning(&invoice_info.invoice, None, false).await.unwrap();

	let payment_hash: ark::lightning::PaymentHash =
		Bolt11Invoice::from_str(&invoice_info.invoice).unwrap().into();
	let client = bark_atk.client().await;
	let htlc_vtxo_ids = htlc_send_vtxo_ids(&client, payment_hash).await;

	// The premise: the server is on the hook for this payment.
	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let open_attempts = db.read(async |t| Ok(t.query("
		SELECT id FROM lightning_payment_attempt
		WHERE payment_hash = $1 AND status NOT IN ('failed', 'succeeded')
	", &[&payment_hash.to_string()]).await?)).await.unwrap();
	assert_eq!(open_attempts.len(), 1, "the payment should still be in flight");

	// 1. Offboard: the server would co-sign a forfeit and pay out on-chain.
	client.unlock_vtxos(&htlc_vtxo_ids).await.expect("it should be able to unlock vtxos on the db");
	let address = ctx.bitcoind().get_new_address();
	let err = client.offboard_vtxos(htlc_vtxo_ids.clone(), address.clone()).await
		.expect_err("server must refuse to offboard an HTLC vtxo");
	let err = format!("{err:#}");
	assert!(err.contains("not spendable as a"), "unexpected error: {err}");

	// Nothing was paid out. Without the fix the server co-signs and broadcasts
	// the offboard, funding this address while it also pays the payee.
	ctx.generate_blocks(1).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO,
		"server paid out an HTLC vtxo whose lightning payment is still in flight");

	// 2. Round: forfeits the vtxo instead of offboarding it. Rounds only run on
	// a long interval here, so kick one off alongside.
	client.unlock_vtxos(&htlc_vtxo_ids).await.expect("it should be able to unlock vtxos on the db");
	let (res, _) = tokio::join!(
		client.refresh_vtxos(htlc_vtxo_ids.clone()),
		srv.trigger_round(),
	);
	let err = res.expect_err("server must refuse an HTLC vtxo as a round input");
	let err = format!("{err:#}");
	assert!(err.contains("not spendable"), "unexpected error: {err}");

	// 3. Arkoor, through the one path that accepted HTLC inputs: fund a second
	// invoice with the vtxos already funding this one. Straight to the server,
	// so no client-side state stands in the way.
	let status = request_second_htlc_cosign(&ctx, &srv, &client, &htlc_vtxo_ids).await;
	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(status.message().contains("not spendable as a"),
		"unexpected server response: {status:?}");
}

/// HTLC VTXOs should not be used outside of the lightning payment/receive flow.
/// This test asserts the server does not accept any HTLC VTXO as an input even
/// outside of an ongoing lightning payment.
#[tokio::test]
async fn refuse_generic_spends_of_htlc_send_vtxo_with_no_payment_in_flight() {
	let ctx = TestContext::new(
		"server/refuse_generic_spends_of_htlc_send_vtxo_with_no_payment_in_flight",
	).await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	/// Accepts the payment request and then does nothing with it.
	#[derive(Clone)]
	struct SwallowInitiate;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for SwallowInitiate {
		async fn initiate_lightning_payment(
			&self,
			_upstream: &mut ArkClient,
			_req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Ok(protos::Empty {})
		}

		async fn check_lightning_payment(
			&self,
			_upstream: &mut ArkClient,
			_req: protos::CheckLightningPaymentRequest,
		) -> Result<protos::LightningPaymentStatus, tonic::Status> {
			Ok(protos::LightningPaymentStatus {
				payment_status: Some(
					protos::lightning_payment_status::PaymentStatus::Pending(protos::Empty {}),
				),
			})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(SwallowInitiate).await;

	let bark_atk = ctx.bark("bark-atk", &proxy.address).funded(btc(3)).create().await;
	bark_atk.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.external.invoice(
		Some(btc(1)), "test_payment", "A test payment",
	).await;
	lightning.sync().await;
	bark_atk.try_pay_lightning(&invoice, None, false).await.unwrap();

	let payment_hash: ark::lightning::PaymentHash =
		Bolt11Invoice::from_str(&invoice).unwrap().into();
	let client = bark_atk.client().await;
	let htlc_vtxo_ids = htlc_send_vtxo_ids(&client, payment_hash).await;

	// The premise: the HTLC vtxos exist and the server never started paying.
	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let attempts = db.read(async |t| Ok(t.query("
		SELECT id FROM lightning_payment_attempt WHERE payment_hash = $1
	", &[&payment_hash.to_string()]).await?)).await.unwrap();
	assert!(attempts.is_empty(), "the proxy should have swallowed the payment request");

	client.unlock_vtxos(&htlc_vtxo_ids).await.expect("it should be able to unlock vtxos on the db");
	let address = ctx.bitcoind().get_new_address();
	let err = client.offboard_vtxos(htlc_vtxo_ids.clone(), address.clone()).await
		.expect_err("server must refuse to offboard an HTLC vtxo");
	assert!(format!("{err:#}").contains("not spendable as a"), "unexpected error: {err:#}");

	ctx.generate_blocks(1).await;
	assert_eq!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO,
		"server paid out an HTLC vtxo");

	client.unlock_vtxos(&htlc_vtxo_ids).await.expect("it should be able to unlock vtxos on the db");
	let (res, _) = tokio::join!(
		client.refresh_vtxos(htlc_vtxo_ids.clone()),
		srv.trigger_round(),
	);
	let err = res.expect_err("server must refuse an HTLC vtxo as a round input");
	assert!(format!("{err:#}").contains("not spendable"), "unexpected error: {err:#}");

	let status = request_second_htlc_cosign(&ctx, &srv, &client, &htlc_vtxo_ids).await;
	assert_eq!(status.code(), tonic::Code::InvalidArgument);
	assert!(status.message().contains("not spendable as a"),
		"unexpected server response: {status:?}");
}

/// HTLC VTXOs need to be revoked and cannot be used as offboard input. The client must
/// provide a Pubkey VTXO.
#[tokio::test]
async fn revoked_htlc_send_vtxo_can_be_offboarded() {
	let ctx = TestContext::new("server/revoked_htlc_send_vtxo_can_be_offboarded").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let bark_1 = ctx.bark("bark-1", &srv).funded(btc(3)).create().await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.external.invoice(
		Some(btc(1)), "test_payment", "A test payment",
	).await;
	bark_1.pay_lightning_wait(invoice, None).await;

	// The revocation gave the funds back as a plain pubkey vtxo.
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.is_empty(), "the revocation should have left spendable vtxos");
	assert!(vtxos.iter().all(|v| v.vtxo.policy_type == VtxoPolicyKind::Pubkey),
		"no HTLC vtxo should be left after revocation: {vtxos:#?}");

	// After revocation, client should be able to offboard a regular VTXO using
	// Pubkey policy.
	let address = ctx.bitcoind().get_new_address();
	srv.wait_for_vtxopool(&ctx).await;
	bark_1.offboard_all(&address).await;
	ctx.generate_blocks(1).await;
	assert_ne!(ctx.bitcoind().get_received_by_address(&address), Amount::ZERO,
		"revoked funds should still be offboardable");
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

/// Hammer `prepare_lightning_receive_claim` with 100 concurrent calls for the
/// same invoice. A single invoice must only ever pay out one set of HTLC
/// VTXOs, no matter how many requests race.
async fn server_concurrent_prepare_lightning_claim(
	ctx: &TestContext,
	_lightning: &LightningPaymentSetup,
	srv: &Captaind,
	pay: impl AsyncFn(String),
) {
	const NB_REQUESTS: usize = 100;

	srv.wait_for_vtxopool(&ctx).await;

	let bark = ctx.bark("bark-1", srv).funded(btc(3)).create().await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(invoice_amount).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let pg_cfg = srv.config().postgres.clone();
	let db = Db::connect(&pg_cfg).await.unwrap();

	// pay blocks until the payment is claimed, which never happens here, so
	// we race it against the wait for its HTLC to arrive and then drop it.
	tokio::select! {
		_ = pay(invoice_info.invoice) => panic!("pay returned before any claim"),
		_ = async {
			srv.get_public_rpc().await.check_lightning_receive(
				protos::CheckLightningReceiveRequest {
					hash: receive.payment_hash.to_vec(),
					wait: true,
				},
			).wait_millis(10_000).await.unwrap();
		} => {},
	}

	// Fire all requests at once, each over its own connection. Every call
	// uses a fresh user pubkey, so nothing but the server's own bookkeeping
	// ties the requests together.
	let results = join_all((0..NB_REQUESTS).map(|_| async {
		let mut client = srv.get_public_rpc().await;
		client.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			payment_hash: receive.payment_hash.to_vec(),
			user_pubkey: Keypair::new(&SECP, &mut bip39::rand::thread_rng())
				.public_key().serialize().to_vec(),
			htlc_recv_expiry: 172,
			lightning_receive_anti_dos: None,
		}).await
	})).await;

	// Collect every distinct HTLC vtxo the calls handed out.
	let mut nb_success = 0;
	let mut returned_ids = HashSet::new();
	let mut returned_amount = Amount::ZERO;
	for result in results {
		if let Ok(response) = result {
			nb_success += 1;
			for bytes in response.into_inner().htlc_vtxos {
				let vtxo: Vtxo<Full> = Vtxo::deserialize(&bytes)
					.expect("server returned invalid vtxo");
				if returned_ids.insert(vtxo.id()) {
					returned_amount += vtxo.amount();
				}
			}
		}
	}
	let created = count_htlc_recv_vtxos(&db).await;
	info!("{} of {} concurrent calls succeeded, handing out {} distinct htlc-recv vtxos worth {}, {} created",
		nb_success, NB_REQUESTS, returned_ids.len(), returned_amount, created,
	);

	// However many calls succeed, the invoice must only pay out once:
	// the vtxos handed out must never be worth more than the invoice.
	assert!(nb_success > 0, "not a single request succeeded");
	assert!(returned_amount <= invoice_amount,
		"a {} invoice handed out {} worth of htlc vtxos",
		invoice_amount, returned_amount,
	);
	assert_eq!(created, returned_ids.len(),
		"server allocated {} htlc-recv vtxos but handed out {}",
		created, returned_ids.len(),
	);

	// The losers are told to retry, so a retry after the storm must
	// return the winner's vtxos instead of allocating a new set.
	let retry = srv.get_public_rpc().await
		.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			payment_hash: receive.payment_hash.to_vec(),
			user_pubkey: Keypair::new(&SECP, &mut bip39::rand::thread_rng())
				.public_key().serialize().to_vec(),
			htlc_recv_expiry: 172,
			lightning_receive_anti_dos: None,
		}).await
		.expect("retry after the storm must succeed").into_inner();
	let retry_ids = retry.htlc_vtxos.iter()
		.map(|b| Vtxo::<Full>::deserialize(b).unwrap().id())
		.collect::<HashSet<_>>();
	assert_eq!(retry_ids, returned_ids, "retry allocated a new htlc set");
	assert_eq!(count_htlc_recv_vtxos(&db).await, created,
		"retry allocated extra htlc-recv vtxos",
	);

	assert_vtxopool_consistency(srv).await;
}
lightning_test!(server_concurrent_prepare_lightning_claim);

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

/// Reproduces a theft vector in the lightning receive flow.
///
/// The granted HTLC-recv VTXOs are an outgoing HTLC for the server, covered by
/// the inbound Lightning HTLC the payer locked into the server's hold invoice.
/// The server may only release the granted value (cosign the claim) while it
/// can still settle the hold invoice, i.e. while the inbound HTLC is live.
///
/// A malicious receiver requests an invoice with a small `min_cltv_delta`
/// (the server only enforces a maximum), pays it from their own node, prepares
/// the claim and then simply waits for the inbound HTLC to expire: their own
/// node gets refunded, while the subscription stays `HtlcsReady`. The server
/// must refuse the cooperative claim at that point. Otherwise the receiver
/// walks away with the granted VTXO value *and* the refunded payment, and the
/// server's hold settler keeps retrying a settle that can never succeed.
#[tokio::test]
async fn refuse_receive_claim_after_incoming_htlc_expiry() {
	let ctx = TestContext::new("server/refuse_receive_claim_after_incoming_htlc_expiry").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx
		.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create()
		.await;

	let bark = ctx.bark("bark-1", &srv).funded(btc(3)).create().await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// The attacker drives the receive flow directly at the RPC layer so they
	// can pick a small min_cltv_delta and control the timing of the claim.
	let preimage = ark::lightning::Preimage::from([7u8; 32]);
	let payment_hash = preimage.compute_payment_hash();
	let min_cltv_delta = 2u32;
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc
		.start_lightning_receive(protos::StartLightningReceiveRequest {
			payment_hash: payment_hash.as_ref().to_vec(),
			amount_sat: btc(1).to_sat(),
			min_cltv_delta,
			mailbox_id: None,
			description: None,
		})
		.await
		.expect("start receive failed")
		.into_inner()
		.bolt11;

	// The attacker's own node pays the hold invoice. The payment blocks until
	// it settles or fails, so it runs in the background.
	let payer = lightning.external;
	let pay_task = {
		let invoice = invoice.clone();
		tokio::spawn(async move { payer.try_pay_bolt11(invoice).await })
	};

	// Wait until the server holds the inbound HTLC.
	rpc.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: payment_hash.as_ref().to_vec(),
		wait: true,
	})
	.wait_millis(10_000)
	.await
	.expect("inbound HTLC never arrived");

	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let sub = db
		.read(async |t| t.get_htlc_subscription_by_payment_hash(payment_hash).await)
		.await
		.unwrap()
		.expect("subscription should exist");
	let lowest = sub
		.lowest_incoming_htlc_expiry
		.expect("Accepted subscription must record lowest incoming HTLC expiry");

	// Prepare the claim while the inbound HTLC is still live. The granted
	// HTLC-recv VTXOs are now outstanding value of the server.
	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let granted = rpc
		.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			payment_hash: payment_hash.as_ref().to_vec(),
			user_pubkey: keypair.public_key().serialize().to_vec(),
			htlc_recv_expiry: lowest - srv.config().htlc_expiry_delta as BlockHeight,
			lightning_receive_anti_dos: None,
		})
		.await
		.expect("prepare should succeed while the inbound HTLC is live")
		.into_inner()
		.htlc_vtxos
		.into_iter()
		.map(|b| Vtxo::deserialize(&b).expect("server returned invalid vtxo"))
		.collect::<Vec<Vtxo<Full>>>();

	// Wait until the inbound HTLC expired: the attacker's node gets refunded.
	let tip = ctx.bitcoind().get_block_count().await as BlockHeight;
	assert!(
		tip < lowest,
		"test premise broken: tip {tip} already past lowest {lowest}"
	);
	ctx.generate_blocks(lowest - tip + 1).await;

	// The attack: claim the granted VTXOs cooperatively. The inbound HTLC is
	// expired, so the server can never settle its hold invoice: cosigning here
	// pays the attacker twice (granted VTXOs plus the refunded payment).
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		granted.iter().cloned(),
		ark::VtxoPolicy::new_pubkey(
			Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key(),
		),
	)
	.unwrap()
	.generate_user_nonces(&[keypair])
	.unwrap();

	let err = rpc
		.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
			payment_hash: payment_hash.as_ref().to_vec(),
			payment_preimage: preimage.as_ref().to_vec(),
			cosign_request: Some(protos::ArkoorPackageCosignRequest::from(
				builder.cosign_request(),
			)),
		})
		.await
		.expect_err("server must refuse a claim it can no longer settle the inbound HTLC for");
	assert_eq!(
		err.code(),
		tonic::Code::InvalidArgument,
		"unexpected error: {err:?}"
	);

	pay_task.abort();
	assert_vtxopool_consistency(&srv).await;
}

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
async fn should_refuse_over_max_ln_receive_amount_invoice_request() {
	let ctx = TestContext::new("server/should_refuse_over_max_ln_receive_amount_invoice_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.lightningd("lightningd-1").create().await;

	let srv = ctx.captaind("server").lightningd(&lightningd).cfg(|cfg| {
		cfg.max_ln_receive_amount = Some(sat(100_000));
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let err = bark.try_bolt11_invoice(sat(100_001)).await.unwrap_err().to_alt_string();
	assert!(err.contains("Requested amount exceeds lightning receive limit of 0.00100000 BTC"), "err: {err}");

	// At the limit is still allowed.
	bark.try_bolt11_invoice(sat(100_000)).await.unwrap();

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
	let resp = srv.start_lightning_receive(
		payment_hash, btc(1), 18, None, None, server_rpc::MAX_PROTOCOL_VERSION,
	).await.unwrap();

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

/// Plant an hArk unlock hash in `round_participation`, returning its preimage.
async fn plant_unlock_preimage(db: &Db, preimage: ark::lightning::Preimage) {
	db.write(async |t| {
		t.execute(
			"INSERT INTO round_participation (unlock_hash, unlock_preimage, round_id, created_at) \
			VALUES ($1, $2, REPEAT('0', 64), NOW())",
			&[
				&preimage.compute_payment_hash().to_string(),
				&preimage.to_string(),
			],
		).await?;
		Ok(())
	}).await.unwrap();
}

/// A receive whose payment hash is an existing hArk unlock hash must be
/// refused: it would put the same secret in two domains at once.
#[tokio::test]
async fn refuse_receive_with_unlock_hash_as_payment_hash() {
	let ctx = TestContext::new("server/refuse_receive_with_unlock_hash_as_payment_hash").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let preimage = ark::lightning::Preimage::from([7u8; 32]);
	plant_unlock_preimage(&db, preimage).await;
	let payment_hash = preimage.compute_payment_hash();

	let mut rpc = srv.get_public_rpc().await;
	let err = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: payment_hash.as_ref().to_vec(),
		amount_sat: 10_000,
		min_cltv_delta: 8,
		mailbox_id: None,
		description: None,
	}).await.expect_err("must refuse a payment hash that is an existing unlock hash");
	assert_eq!(err.code(), tonic::Code::InvalidArgument);
	assert!(err.message().contains("unlock hash"), "unexpected error: {err:?}");
}

/// A lightning send whose payment hash is an existing hArk unlock hash must
/// be refused at the HTLC cosign: it would put the same secret in two
/// domains at once.
#[tokio::test]
async fn refuse_send_with_unlock_hash_as_payment_hash() {
	let ctx = TestContext::new("server/refuse_send_with_unlock_hash_as_payment_hash").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	let bark = ctx.bark("bark-1", &srv).funded(sat(500_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(200_000)).await;

	let db = Db::connect(&srv.config().postgres.clone()).await.unwrap();
	let unlock_preimage = ark::lightning::Preimage::from([7u8; 32]);
	plant_unlock_preimage(&db, unlock_preimage).await;

	// The attacker's own invoice with payment_hash == their unlock hash.
	let mut preimage = [0u8; 32];
	preimage.copy_from_slice(unlock_preimage.as_ref());
	let invoice = lightning.external.invoice_with_preimage(
		Some(sat(10_000)), "cross-domain", "x", preimage,
	).await;

	let err = bark.try_pay_lightning(invoice, None, false)
		.await.expect_err("send with an unlock hash as payment hash must be refused");
	let msg = format!("{:#}", err);
	assert!(msg.contains("unlock hash"), "unexpected error: {msg}");
}
