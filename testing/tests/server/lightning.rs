use std::sync::Arc;
use std::time::Duration;

use ark_testing::{TestContext, btc};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::FutureExt;

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
	let ctx = TestContext::new(
		"server/server_settles_invoice_from_on_chain_htlc_preimage",
	).await;
	let ctx = Arc::new(ctx);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Use a long receive_htlc_forward_timeout so hold invoices stay alive
	// while the exit is driven to completion on-chain.
	let srv = ctx.new_captaind_with_cfg(
		"srv", Some(&lightning.receiver), |cfg| {
			cfg.receive_htlc_forward_timeout = Duration::from_secs(300);
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
			_req: server_rpc::protos::ClaimLightningReceiveRequest,
		) -> Result<server_rpc::protos::ArkoorPackageCosignResponse, tonic::Status> {
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

	complete_exit(&ctx, &bark_recv).await;

	bark_recv.claim_all_exits(bark_recv.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// The external CLN sender's payment completes — the server extracted
	// the preimage from the on-chain spend and settled the hold invoice.
	pay_handle.await.unwrap();

	// ── Intra-ark: same-server bark sender ──────────────────────────

	// Re-board bark_recv (its VTXOs were spent during the exit above).
	ctx.fund_bark(&bark_recv, btc(3)).await;
	bark_recv.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark_recv.sync().await;

	let invoice_info = bark_recv.bolt11_invoice(btc(1)).await;

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

	let bark_recv = recv_handle.await.unwrap();

	bark_recv.sync().await;
	assert!(!bark_recv.list_exits().await.is_empty(), "Expected exit to be started");

	complete_exit(&ctx, &bark_recv).await;

	bark_recv.claim_all_exits(bark_recv.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Sender's payment completes — pay_lightning_wait blocks until the
	// server's HtlcSettler settles the invoice via payment_update_tx.
	let bark_sender = send_handle.await.unwrap();

	assert_eq!(
		bark_sender.offchain_balance().await.pending_lightning_send, btc(0),
		"pending lightning send should be zero after settlement",
	);
}
