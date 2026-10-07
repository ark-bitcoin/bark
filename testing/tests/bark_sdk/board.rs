//! Tests for the board flow through the SDK.

use bitcoin::Amount;
use bitcoin_ext::rpc::RpcApi;

use ark_testing::{sat, TestContext};

const MIN_BOARD_AMOUNT: Amount = Amount::from_sat(20_000);

/// A board that fails before its checkpoint exists must leave the onchain
/// wallet untouched: the funding proposal is signed before the server is
/// asked to cosign, and a proposal the server never cosigned must not spend
/// any coins, not even after a sync (which rebroadcasts the wallet's
/// unconfirmed transactions).
///
/// The board is made to fail by boarding half the server's minimum amount.
#[tokio::test]
#[ignore = "fails until board signing stops storing the funding tx in the wallet"]
async fn failed_board_leaves_the_onchain_wallet_untouched() {
	let ctx = TestContext::new("bark_sdk/failed_board_leaves_the_onchain_wallet_untouched").await;
	let srv = ctx.captaind("server")
		.cfg(|cfg| cfg.min_board_amount = MIN_BOARD_AMOUNT)
		.create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(MIN_BOARD_AMOUNT)
		.create().await;

	let err = wallet.board_amount(MIN_BOARD_AMOUNT / 2).await
		.expect_err("boarding below the minimum must be refused");
	assert!(format!("{:#}", err).contains("less than minimum board amount"),
		"unexpected board error: {err:#}",
	);

	// The failed board left a signed funding proposal behind; syncing must
	// neither count it as a spend nor hand it to the network.
	wallet.sync_onchain().await.expect("onchain sync");

	let balance = wallet.onchain().expect("onchain wallet").read().await.balance().await;
	assert_eq!(balance, MIN_BOARD_AMOUNT, "no onchain coins may move on a failed board");
	assert!(ctx.bitcoind().sync_client().get_raw_mempool().expect("mempool").is_empty(),
		"a failed board must not broadcast its funding tx",
	);
	assert!(wallet.pending_boards().await.expect("pending boards").is_empty(),
		"a failed board must not linger as pending",
	);

	// The coins are still the wallet's to spend: with enough funds on top,
	// the same wallet boards fine.
	let address = {
		let onchain = wallet.onchain().expect("onchain wallet");
		let mut guard = onchain.write().await;
		guard.address().await.expect("onchain address")
	};
	ctx.bitcoind().fund_addr(address, sat(80_000)).await;
	ctx.generate_blocks(1).await;
	wallet.sync_onchain().await.expect("onchain sync");

	let board = wallet.board_all().await.expect("board with funds above the minimum");
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	wallet.sync_onchain().await.expect("onchain sync");
	let balance = wallet.onchain().expect("onchain wallet").read().await.balance().await;
	assert_eq!(balance, Amount::ZERO, "the successful board drains the onchain wallet");
}
