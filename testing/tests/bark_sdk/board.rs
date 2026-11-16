//! Tests for the board flow through the SDK.

use bitcoin::{Amount, Psbt};
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;

use bark::{BoardFundingAddress, Wallet};

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

const MIN_BOARD_AMOUNT: Amount = Amount::from_sat(20_000);

/// A board that fails before its checkpoint exists must leave the onchain
/// wallet untouched: the funding proposal is signed before the server is
/// asked to cosign, and a proposal the server never cosigned must not spend
/// any coins, not even after a sync (which rebroadcasts the wallet's
/// unconfirmed transactions).
///
/// The board is made to fail by boarding half the server's minimum amount.
#[tokio::test]
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

/// Builds a finalised PSBT paying `funding` from the wallet's own on-chain
/// wallet, standing in for another party such as a payjoin sender.
async fn funding_psbt(wallet: &Wallet, funding: &BoardFundingAddress, amount: Amount) -> Psbt {
	let onchain = wallet.onchain().expect("onchain wallet");
	let mut onchain = onchain.write().await;
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(funding.address().clone(), amount)], fee_rate).await.unwrap();
	onchain.finish_psbt(psbt).await.unwrap()
}

/// A funding address handed out before `BoardFundingAddress` existed can still be
/// boarded from the keypair and expiry height stored alongside it.
#[tokio::test]
#[allow(deprecated)]
async fn board_psbt_legacy_funding_address() {
	let ctx = TestContext::new("bark_sdk/board_psbt_legacy_funding_address").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(100_000))
		.create().await;

	// What a caller of the removed `board_funding_address` stored.
	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let expiry_height = wallet.chain().tip().await.unwrap() + BlockDelta::new(100);

	let funding = wallet.legacy_board_funding_address(keypair.public_key(), expiry_height)
		.await.unwrap();
	assert_eq!(funding.expiry_height(), expiry_height);

	let psbt = funding_psbt(&wallet, &funding, sat(90_000)).await;
	wallet.board_psbt(psbt, &funding).await.expect("board a legacy funding address");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(90_000));
}
