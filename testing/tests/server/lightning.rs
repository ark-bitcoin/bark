use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;
use log::{info, trace};

use ark::{ProtocolEncoding, Vtxo, SECP};
use ark::arkoor::ArkoorDestination;
use ark::attestations::ArkoorCosignAttestation;
use ark::vtxo::Full;
use bark::Wallet;
use bark::lightning_invoice::Bolt11Invoice;
use bark_json::primitives::WalletVtxoInfo;
use server_rpc::protos::{self, lightning_payment_status};
use server::vtxopool::VtxoTarget;

use ark_testing::{TestContext, btc, sat};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{FutureExt, ToAltString};
use ark_testing::exit::complete_exit;


/// Verify that the server extracts preimages from on-chain HTLC spends
/// and uses them to settle invoices — both inter-ark (external CLN sender)
/// and intra-ark (same-server bark sender).
///
/// The proxy blocks cooperative settlement, forcing bark into an emergency
/// exit. The exit publishes the HTLC preimage on-chain, which the server's
/// HtlcSettler extracts to settle the hold invoice.
#[tokio::test]
async fn server_settles_invoice_from_on_chain_htlc_preimage() {
	let ctx = TestContext::new("server/server_settles_invoice_from_on_chain_htlc_preimage").await;
	let ctx = Arc::new(ctx);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg(
		"srv", Some(&lightning.receiver), |cfg| {
			// Use a long receive_htlc_forward_timeout so hold invoices stay alive
			// while the exit is driven to completion on-chain.
			cfg.receive_htlc_forward_timeout = Duration::from_secs(5 * 60);
			// To make sure we don't sweep the vtxo before user can broadcast preimage
			cfg.vtxopool.vtxo_lifetime = 2048;
		},
	).await;
	ctx.fund_captaind(&srv, btc(10)).await;

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
			Err(tonic::Status::internal("Blocked cooperative settlement"))
		}
	}

	let proxy = srv.start_proxy_no_mailbox(BlockCooperativeSettlement).await;

	// bark_sender connects to the real server (for intra-ark test below)
	let bark_sender = ctx.new_bark_with_funds("bark-sender", &srv, btc(3)).await;
	// bark_recv connects through the proxy so cooperative settlement is blocked
	let bark_recv = ctx.new_bark_with_funds("bark-recv", &proxy.address, btc(3)).await;

	bark_sender.board(btc(2)).await;
	bark_recv.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_sender.sync().await;
	bark_recv.sync().await;

	// ── Inter-ark: external CLN sender ──────────────────────────────

	let invoice_info = bark_recv.bolt11_invoice(btc(1)).await;

	let cloned_invoice = invoice_info.invoice.clone();
	let pay_handle = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice).await;
	});

	// Proxy blocks cooperative settlement, so this errors
	let _ = bark_recv.try_lightning_receive(&invoice_info.invoice).await;

	bark_recv.sync().await;
	assert!(!bark_recv.list_exits().await.is_empty(), "Expected exit to be started");

	info!("Doing first exit...");
	complete_exit(&ctx, &bark_recv).await;

	bark_recv.claim_all_exits(bark_recv.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// The external CLN sender's payment completes — the server extracted
	// the preimage from the on-chain spend and settled the hold invoice.
	info!("Waiting for pay_handle...");
	pay_handle.await.unwrap();

	// ── Intra-ark: same-server bark sender ──────────────────────────

	// Re-board bark_recv (its VTXOs were spent during the exit above).
	ctx.fund_bark(&bark_recv, btc(3)).await;
	bark_recv.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_recv.sync().await;

	let invoice_info = bark_recv.bolt11_invoice(btc(1)).await;

	info!("Waiting for vtxopool...");
	srv.wait_for_vtxopool(&ctx).await;

	// Spawn receiver: proxy blocks cooperative settlement, so this will error
	let recv_invoice = invoice_info.invoice.clone();
	let recv_handle = tokio::spawn(async move {
		let _ = bark_recv.try_lightning_receive(&recv_invoice).await;
		bark_recv
	});

	// Spawn sender: pay_lightning_wait blocks until the server settles
	// the invoice (via payment_update_tx notification from HtlcSettler).
	let send_invoice = invoice_info.invoice.clone();
	let send_handle = tokio::spawn(async move {
		bark_sender.pay_lightning_wait(send_invoice, None).wait_millis(300_000).await;
		bark_sender
	});

	info!("Waiting for recv_handle (2)...");
	let bark_recv = recv_handle.await.unwrap();

	bark_recv.sync().await;
	assert!(!bark_recv.list_exits().await.is_empty(), "Expected exit to be started");

	info!("Doing second exit...");
	complete_exit(&ctx, &bark_recv).await;

	bark_recv.claim_all_exits(bark_recv.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Sender's payment completes — pay_lightning_wait blocks until the
	// server's HtlcSettler settles the invoice via payment_update_tx.
	info!("Waiting for send_handle (2)...");
	let bark_sender = send_handle.await.unwrap();

	assert_eq!(
		bark_sender.offchain_balance().await.pending_lightning_send, btc(0),
		"pending lightning send should be zero after settlement",
	);
}

#[tokio::test]
async fn reject_revocation_on_successful_lightning_payment() {
	let ctx = TestContext::new("server/reject_revocation_on_successful_lightning_payment").await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn check_lightning_payment(
			&self, upstream: &mut ArkClient,
			req: protos::CheckLightningPaymentRequest,
		) -> Result<protos::LightningPaymentStatus, tonic::Status> {
			let res = upstream.check_lightning_payment(req).await?.into_inner();
			let status = res.payment_status.unwrap();

			match status {
				lightning_payment_status::PaymentStatus::Pending(_) => {
					Ok(protos::LightningPaymentStatus {
						payment_status: Some(lightning_payment_status::PaymentStatus::Pending(protos::Empty {})),
					})
				},
				_ => {
					Ok(protos::LightningPaymentStatus {
						payment_status: Some(lightning_payment_status::PaymentStatus::Failed(protos::Empty {})),
					})
				},
			}
		}
	}

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(7);
	let board_amount = btc(5);

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	lightning.sync().await;

	assert_eq!(bark_1.spendable_balance().await, board_amount);
	let err = bark_1.try_pay_lightning(invoice, None, true).await.unwrap_err().to_alt_string();
	assert!(err.contains("This lightning payment has completed. preimage: "), "err: {err}");
}

#[tokio::test]
async fn server_refuse_claim_invoice_not_settled() {
	let ctx = TestContext::new("server/server_refuse_claim_invoice_not_settled").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

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
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &proxy.address, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned = invoice_info.clone();
	tokio::spawn(async move { lightning.sender.pay_bolt11(cloned.invoice).await; });
	let err = bark.try_lightning_receive(&invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("bad user input: preimage doesn't match payment hash"), "err: {err}");
}

#[tokio::test]
async fn server_should_release_hold_invoice_when_subscription_is_canceled() {
	let ctx = TestContext::new("server/server_should_release_hold_invoice_when_subscription_is_canceled").await;
	let cfg_htlc_forward_timeout = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// Set the receive_htlc_forward_timeout very short so the subscription
		// gets canceled quickly when the receiver doesn't prepare the claim
		cfg.receive_htlc_forward_timeout = cfg_htlc_forward_timeout
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	// Spawn the payment - it will be held by the server until claimed or canceled
	let cloned_invoice_info = invoice_info.clone();
	let sender = Arc::new(lightning.sender);
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
}

#[tokio::test]
async fn server_generated_invoice_has_configured_expiry() {
	let ctx = TestContext::new("server/server_generated_invoice_has_configured_expiry").await;
	let cfg_invoice_expiry = Duration::from_secs(5);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// Set invoice expiry very short so invoice expires quickly
		cfg.invoice_expiry = cfg_invoice_expiry;
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
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
	let err = lightning.sender.try_pay_bolt11(invoice_info.invoice).await.unwrap_err().to_alt_string();
	assert!(err.contains("Invoice expired"), "err: {err}");
}

#[tokio::test]
async fn server_claim_lightning_receive_is_idempotent() {
	let ctx = TestContext::new("server/server_claim_lightning_receive_is_idempotent").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	// Wait for the onboarding round to be deeply enough confirmed
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	// We use that to sync and get onboarded vtxos
	bark.spendable_balance().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(bark.spendable_balance().await, btc(3));

	let vtxos_before = bark.vtxo_ids_no_sync().await;
	let status_before = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();
	assert!(status_before.finished_at.is_some());

	// Claiming again should be a no-op.
	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	assert_eq!(bark.spendable_balance().await, btc(3));
	assert_eq!(bark.vtxo_ids_no_sync().await, vtxos_before);
	assert_eq!(
		bark.lightning_receive_status(&invoice_info.invoice).await.unwrap().finished_at,
		status_before.finished_at,
	);
}

#[tokio::test]
async fn server_returned_htlc_recv_vtxos_should_be_identical_cln() {
	let ctx = TestContext::new("server/server_returned_htlc_recv_vtxos_should_be_identical_cln").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();

	let mut client = srv.get_public_rpc().await;

	// Need to initiate payment for server to return htlc vtxos
	tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	// Wait for the payment to be received
	client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: receive.payment_hash.to_vec(),
		wait: true,
	}).wait_millis(10_000).await.unwrap().into_inner();

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_1 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};
	let vtxos_1 = client.prepare_lightning_receive_claim(req_1.clone()).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	// We test once again with the same request
	let vtxos_2 = client.prepare_lightning_receive_claim(req_1).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	// we change keypair to make sure server don't use it on second request
	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_2 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};

	let vtxos_3 = client.prepare_lightning_receive_claim(req_2).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	assert_eq!(vtxos_1, vtxos_2, "should have the same VTXOs");
	assert_eq!(vtxos_1, vtxos_3, "should have the same VTXOs");
}

#[tokio::test]
async fn server_returned_htlc_recv_vtxos_should_be_identical_intra_ark() {
	let ctx = TestContext::new("server/server_returned_htlc_recv_vtxos_should_be_identical_intra_ark").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and create a VTXO to be able to board
	let bark = ctx.new_bark_with_funds("bark-1", &srv, btc(3)).await;
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark-2", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;
	bark2.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice_info = bark.bolt11_invoice(btc(1)).await;
	let receive = bark.lightning_receive_status(&invoice_info.invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();

	let mut client = srv.get_public_rpc().await;

	// Need to initiate payment for server to return htlc vtxos
	tokio::spawn(async move {
		bark2.pay_lightning(cloned_invoice_info.invoice, None).wait_millis(10_000).await;
	});

	// Wait for the payment to be received
	client.check_lightning_receive(protos::CheckLightningReceiveRequest {
		hash: receive.payment_hash.to_vec(),
		wait: true,
	}).wait_millis(10_000).await.unwrap().into_inner();

	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_1 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};
	let vtxos_1 = client.prepare_lightning_receive_claim(req_1.clone()).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	// We test once again with the same request
	let vtxos_2 = client.prepare_lightning_receive_claim(req_1).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	// we change keypair to make sure server don't use it on second request
	let keypair = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let req_2 = protos::PrepareLightningReceiveClaimRequest {
		payment_hash: receive.payment_hash.to_vec(),
		user_pubkey: keypair.public_key().serialize().to_vec(),
		htlc_recv_expiry: 180,
		lightning_receive_anti_dos: None,
	};

	let vtxos_3 = client.prepare_lightning_receive_claim(req_2).await.unwrap()
		.into_inner().htlc_vtxos.into_iter().map(|b| Vtxo::deserialize(&b))
		.collect::<Result<Vec<Vtxo<Full>>, _>>().unwrap();

	assert_eq!(vtxos_1, vtxos_2, "should have the same VTXOs");
	assert_eq!(vtxos_1, vtxos_3, "should have the same VTXOs");
}

#[tokio::test]
async fn server_claim_lightning_receive_is_idempotent_intra_ark() {
	let ctx = TestContext::new("server/server_claim_lightning_receive_is_idempotent_intra_ark").await;

	trace!("Start lightningd-1");
	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board_and_confirm_and_register(&ctx, sat(400_000)).await;
	bark2.board_and_confirm_and_register(&ctx, sat(400_000)).await;

	let invoice_info = bark1.bolt11_invoice(sat(30_000)).await;

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		bark2.pay_lightning(cloned_invoice_info.invoice, None).wait_millis(10_000).await;
	});

	bark1.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	let vtxos_before = bark1.vtxo_ids_no_sync().await;
	let status_before = bark1.lightning_receive_status(&invoice_info.invoice).await.unwrap();
	assert!(status_before.finished_at.is_some());

	// Claiming again should be a no-op.
	bark1.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	assert_eq!(bark1.vtxo_ids_no_sync().await, vtxos_before);
	assert_eq!(
		bark1.lightning_receive_status(&invoice_info.invoice).await.unwrap().finished_at,
		status_before.finished_at,
	);
}

#[tokio::test]
async fn should_refuse_paying_invoice_not_matching_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_not_matching_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let dummy_invoice = lightning.receiver.invoice(None, "dummy_invoice", "A dummy invoice").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy(String);
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.invoice = self.0.clone();
			Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy(dummy_invoice)).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains("htlc payment hash doesn't match invoice"), "err: {err}");
}

#[tokio::test]
async fn should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs() {
	let ctx = TestContext::new("server/should_refuse_paying_invoice_whose_amount_is_higher_than_htlcs").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, upstream: &mut ArkClient, mut req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			req.htlc_vtxo_ids.pop();
			Ok(upstream.initiate_lightning_payment(req).await?.into_inner())
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board(btc(0.5)).await;
	bark_1.board(btc(0.6)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_1.sync().await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "real invoice", "A real invoice").await;

	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err().to_alt_string();
	assert!(err.contains("HTLC VTXO sum of") && err.contains("is less than the payment amount of"), "err: {err}");
}

#[tokio::test]
async fn should_refuse_ln_pay_input_vtxo_that_is_being_exited() {
	let ctx = TestContext::new("server/should_refuse_ln_pay_input_vtxo_that_is_being_exited").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

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
	struct Proxy(Arc<Wallet>, WalletVtxoInfo);
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
		Proxy(Arc::new(bark.client().await), vtxo_a.clone())
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
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind("server", Some(&lightningd)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark.try_bolt11_invoice(sat(300)).await.unwrap();
}

#[tokio::test]
async fn should_refuse_over_max_vtxo_amount_lightning_receive_request() {
	let ctx = TestContext::new("server/should_refuse_over_max_vtxo_amount_lightning_receive_request").await;

	trace!("Start lightningd-1");
	let lightningd = ctx.new_lightningd("lightningd-1").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightningd), |cfg| {
		cfg.max_vtxo_amount = Some(sat(1_000_000));
	}).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

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
}

#[tokio::test]
async fn server_can_use_multi_input_from_vtxo_pool() {
	let ctx = TestContext::new("server/server_can_use_multi_input_from_vtxo_pool").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 5, amount: sat(100_000) },
		];
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let pay_amount = sat(200_000);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;
	let invoice = Bolt11Invoice::from_str(&invoice_info.invoice).unwrap();
	let _ = bark.lightning_receive_status(&invoice).await.unwrap();

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	// We use that to sync and get onboarded vtxos
	let balance = bark.spendable_balance().await;

	// HTLC settlement on lightning side
	res1.ready().await.unwrap();

	assert_eq!(balance, pay_amount + board_amount);
}

#[tokio::test]
async fn server_can_use_vtxo_pool_change_for_next_receive() {
	let ctx = TestContext::new("server/server_can_use_vtxo_pool_change_for_next_receive").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.vtxopool.vtxo_targets = vec![
			VtxoTarget { count: 5, amount: sat(100_000) },
		];
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Start a bark and create a VTXO to be able to board
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	let first_pay_amount = sat(50_000);
	let second_pay_amount = sat(25_000);

	let sender = Arc::new(lightning.sender);

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
}

#[tokio::test]
async fn initiate_lightning_payment_fails_without_register_vtxos() {
	let ctx = TestContext::new("server/initiate_lightning_payment_fails_without_register_vtxos").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;

	// Create a proxy that drops register_vtxos calls (returns success without calling upstream)
	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_vtxos(
			&self, _upstream: &mut ArkClient, _req: protos::RegisterVtxosRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// Drop the call - return success but don't register with upstream
			Ok(protos::Empty {})
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, btc(3)).await;
	bark_1.board_and_confirm_and_register(&ctx, btc(2)).await;

	let invoice = lightning.receiver.invoice(Some(btc(1)), "test_payment", "A test payment").await;

	// The payment should fail because register_vtxos was dropped,
	// so initiate_lightning_payment will fail when trying to mark server_may_own_descendants
	let err = bark_1.try_pay_lightning(invoice, None, false).await.unwrap_err();
	assert!(err.to_string().contains("does not exist") || err.to_string().contains("NULL signed_tx"),
		"Expected error about missing or unsigned transaction, got: {err}");
}
