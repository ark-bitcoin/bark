use bitcoin::Amount;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::ToAltString;

#[tokio::test]
async fn bark_board_refused_over_max_board_amount() {
	let ctx = TestContext::new("bark/bark_board_refused_over_max_board_amount").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.max_board_amount = Some(sat(500_000));
	}).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_500_000)).create().await;

	// at the limit is allowed
	bark1.board_and_confirm_and_register(&ctx, sat(500_000)).await;

	// exceeds limit, should fail
	//
	// NB a wallet can't board again after a refused board: the cosign is
	// requested before the funding tx is broadcast, so the refusal leaves that
	// tx in bark's wallet unbroadcast, and a later board would spend its change
	// and be refused for an input tx the server doesn't know. So this comes
	// after the board above, and the disabled case below uses a fresh wallet.
	let err = bark1.try_board(sat(600_000)).await.unwrap_err().to_alt_string();
	assert!(err.contains("board amount exceeds limit of 0.00500000 BTC"), "err: {err}");

	// zero disables boards entirely
	srv.stop().await.unwrap();
	srv.config_mut().max_board_amount = Some(Amount::ZERO);
	srv.start().await.unwrap();

	let bark2 = ctx.bark("bark2", &srv).funded(sat(500_000)).create().await;
	let err = bark2.try_board(sat(100_000)).await.unwrap_err().to_alt_string();
	assert!(err.contains("board is temporarily disabled"), "err: {err}");
}

#[tokio::test]
async fn bark_refresh_fails_for_unregistered_board() {
	let ctx = TestContext::new("bark/bark_refresh_fails_for_unregistered_board").await;

	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, _upstream: &mut ArkClient, _req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			// drop the request
			Ok(protos::Empty{})
		}
	}

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	let bark = ctx.bark("bark".to_string(), &proxy.address).funded(sat(1_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let (err, _) = tokio::join!(
		async { bark.try_refresh_all_no_retry().await.unwrap_err().to_alt_string() },
		srv.trigger_round(),
	);
	assert!(err.contains("failed to register vtxo transactions"), "err: {err}");
}

/// Verify that broadcasting the board vtxo's exit tx (outside of bark) causes
/// board registration to fail when bark tries to register via sync().
///
/// The exit tx spends the board funding output, so the server sees it as already
/// spent and rejects the register_board_vtxo call.
#[tokio::test]
async fn bark_keeps_board_locked_after_refused_registration() {
	let ctx = TestContext::new("bark/bark_keeps_board_locked_after_refused_registration").await;
	let srv = ctx.captaind("server").funded(btc(1)).create().await;
	let bark = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	// Board some funds.
	let board = bark.board(sat(90_000)).await;
	let vtxo_id = board.vtxos[0];

	// Confirm the board transaction so it meets the required confirmations.
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Get the full vtxo (including genesis with exit tx) before calling sync(),
	// so the board is still pending in the DB.
	// vtxos_no_sync() returns vtxos in Locked state (pending boards are locked),
	// and with --hex flag includes the raw vtxo bytes.
	let vtxo = bark.raw_vtxo(vtxo_id).await;

	// A board vtxo has exactly one genesis item; its tx is the exit tx
	// that spends the board funding output.
	let exit_tx = vtxo.transactions().next().expect("board vtxo should have one exit tx").tx;
	// Broadcast the exit tx from the test framework – bark is not aware of this.
	// The exit tx has 0 fee (default test config), so we use CPFP via its P2A anchor.
	let child_txid = ctx.broadcast_cpfp(&exit_tx).await;
	srv.bitcoind().await_transaction(child_txid).await;

	// Now bark tries to register the board via sync().
	// The server calls gettxout on the board funding output; because the exit tx is
	// now in the mempool the output is already spent, so it rejects the registration
	// with "VTXO funding output is already spent".  sync_pending_boards handles the
	// error gracefully (logs a warning) so sync() itself does not panic.
	bark.sync().await;

	// Board registration failed – the vtxo should still be in Locked (pending) state,
	// not Spendable. Spendable balance must be zero.
	let vtxos = bark.vtxos_no_sync().await;
	let vtxo_info = vtxos.iter()
		.find(|v| v.vtxo.id == vtxo_id)
		.expect("vtxo should still be in the wallet (locked, pending registration)");
	assert!(
		matches!(vtxo_info.state, bark_json::primitives::VtxoStateInfo::Locked { .. }),
		"board vtxo should be Locked (not Spendable) after failed registration",
	);

	let balance = bark.spendable_balance_no_sync().await;
	assert_eq!(balance, Amount::ZERO, "spendable balance should be zero since board was not registered");
}
