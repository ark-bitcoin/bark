use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};
use std::time::Duration;

use bitcoin::Amount;
use server_log::ArkFeeRecorded;
use server_rpc::protos;

use ark::fees::{BoardFees, PpmFeeRate};
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};

use ark_testing::barkd_helpers::{wait_for_boards_synced, wait_for_onchain_balance};

/// Server without fees
#[tokio::test]
async fn board_barkd() {
	let ctx = TestContext::new("barkd/board_barkd").await;
	// The minimum board amount is 20_000 sat.
	let srv = ctx.captaind("server").create().await;

	// Board an amount
	Box::pin(async {
		let barkd = ctx.barkd("amount", &srv).funded(sat(200_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(200_000)).await;

		let board = barkd.board_amount(sat(100_000)).await;
		assert_eq!(board.amount, sat(100_000));
		let [vtxo_id] = board.vtxos.clone().try_into().expect("one board vtxo");

		let pending = barkd.get_pending_boards().await;
		assert_eq!(pending.len(), 1, "should have one pending board before confirmation");
		assert_eq!(pending[0].amount, board.amount);
		assert_eq!(barkd.bark_balance().await.pending_board, board.amount);
		let vtxo = barkd.get_vtxo(&vtxo_id.to_string()).await;
		assert_eq!(vtxo.amount, board.amount);

		// The daemon registers the board without a manual sync.
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wait_for_boards_synced(&barkd).await;

		let balance = barkd.bark_balance().await;
		assert_eq!(balance.spendable, board.amount);
		assert_eq!(balance.pending_board, Amount::ZERO);
	}).await;

	// Refuse a board below the server minimum
	Box::pin(async {
		let barkd = ctx.barkd("below-minimum", &srv).funded(sat(100_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(100_000)).await;

		let err = barkd.try_board_amount(sat(19_999)).await.unwrap_err().to_string();
		assert!(err.contains(
			"board amount of 0.00019999 BTC is less than minimum board amount required by server (0.00020000 BTC)",
		), "unexpected error: {err}");
		assert!(barkd.get_pending_boards().await.is_empty());
	}).await;

	// Board registration is robust against a server refusing it
	Box::pin(async {
		/// Refuses the first `n` register_board_vtxo calls.
		#[derive(Clone)]
		struct Proxy(Arc<AtomicUsize>);

		#[async_trait::async_trait]
		impl captaind::proxy::ArkRpcProxy for Proxy {
			async fn register_board_vtxo(
				&self, upstream: &mut ArkClient, req: protos::BoardVtxoRequest,
			) -> Result<protos::Empty, tonic::Status> {
				let refuse = self.0.fetch_update(
					atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |n| n.checked_sub(1),
				).is_ok();
				if refuse {
					Err(tonic::Status::unavailable("refused by the test proxy"))
				} else {
					Ok(upstream.register_board_vtxo(req).await?.into_inner())
				}
			}
		}

		let refusals = Arc::new(AtomicUsize::new(2));
		let proxy = srv.start_proxy_no_mailbox(Proxy(refusals.clone())).await;
		let barkd = ctx.barkd("refused", &srv)
			.cfg({
				let addr = proxy.address.clone();
				move |c| c.server_address = addr
			})
			.funded(sat(100_000))
			.create().await;
		wait_for_onchain_balance(&barkd, sat(100_000)).await;

		let board = barkd.board_all().await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		// Syncs until the board registers.
		barkd.wait_for_boards_synced().await;

		assert_eq!(refusals.load(atomic::Ordering::Relaxed), 0, "the proxy never refused");
		assert_eq!(barkd.bark_balance().await.spendable, board.amount);
	}).await;
}

/// Server with fees
#[tokio::test]
async fn board_barkd_fees() {
	let ctx = TestContext::new("barkd/board_barkd_fees").await;
	// Fee = max(30_000, 100 + 1% of the amount)
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.fees.board = BoardFees {
			min_fee: sat(30_000),
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).create().await;

	// Pay the base and ppm fee
	Box::pin(async {
		let barkd = ctx.barkd("base-and-ppm", &srv).funded(sat(6_000_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(6_000_000)).await;

		// Fee = 100 + 1% of 5_000_000 = 50_100
		let estimate = barkd.board_fee(sat(5_000_000)).await;
		assert_eq!(estimate.gross_amount, sat(5_000_000));
		assert_eq!(estimate.fee, sat(50_100));
		assert_eq!(estimate.net_amount, sat(4_949_900));

		let mut fee_logs = srv.subscribe_log::<ArkFeeRecorded>();
		let board = barkd.board_amount(sat(5_000_000)).await;
		assert_eq!(board.amount, estimate.net_amount, "board amount should match fee estimate");

		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wait_for_boards_synced(&barkd).await;
		assert_eq!(barkd.bark_balance().await.spendable, estimate.net_amount);

		// The server records the fee when it registers the board.
		let fee_log = tokio::time::timeout(Duration::from_secs(15), async {
			loop {
				let log = fee_logs.recv().await.expect("fee log channel closed");
				if log.op_type == "board" {
					return log;
				}
			}
		}).await.expect("no board fee was recorded");
		assert_eq!(fee_log.net_fee_sat, 50_100);
		assert_eq!(fee_log.user_fee_sat, 50_100);
		assert_eq!(fee_log.routing_fee_sat, None);
		assert_eq!(fee_log.round_seq, None);

		let [movement] = barkd.history(None, None).await.try_into().expect("one movement");
		assert_eq!(movement.offchain_fee, estimate.fee);
		assert_eq!(movement.intended_balance, estimate.gross_amount.to_signed().unwrap());
		assert_eq!(movement.effective_balance, estimate.net_amount.to_signed().unwrap());
	}).await;

	// Pay the minimum fee
	Box::pin(async {
		let barkd = ctx.barkd("minimum-fee", &srv).funded(sat(200_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(200_000)).await;

		let estimate = barkd.board_fee(sat(100_000)).await;
		assert_eq!(estimate.fee, sat(30_000));
		assert_eq!(estimate.net_amount, sat(70_000));

		let board = barkd.board_amount(sat(100_000)).await;
		assert_eq!(board.amount, estimate.net_amount);

		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wait_for_boards_synced(&barkd).await;

		let [movement] = barkd.history(None, None).await.try_into().expect("one movement");
		assert_eq!(movement.offchain_fee, estimate.fee);
		assert_eq!(movement.effective_balance, estimate.net_amount.to_signed().unwrap());
		assert_eq!(barkd.bark_balance().await.spendable, estimate.net_amount);
	}).await;

	// Refuse a board when the fee exceeds the amount
	Box::pin(async {
		let barkd = ctx.barkd("fee-exceeds", &srv).funded(sat(100_000)).create().await;
		wait_for_onchain_balance(&barkd, sat(100_000)).await;

		// The estimate still answers.
		let estimate = barkd.board_fee(sat(25_000)).await;
		assert_eq!(estimate.fee, sat(30_000));
		assert_eq!(estimate.net_amount, Amount::ZERO);

		let err = barkd.try_board_amount(sat(25_000)).await.unwrap_err().to_string();
		assert!(err.contains("exceeds amount"), "unexpected error: {err}");
		assert!(barkd.get_pending_boards().await.is_empty());
		assert!(barkd.vtxos(None).await.is_empty());
	}).await;
}
