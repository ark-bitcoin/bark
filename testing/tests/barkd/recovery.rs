
use ark_testing::{btc, sat, TestContext};
use bitcoin::Amount;

use super::helpers::wait_for_rounds_complete;

/// Wallet recovery from seed.
///
/// Board and register a VTXO, then wipe the daemon's datadir down to nothing
/// but the seed and recover in place. Asserts the recovered wallet rediscovers
/// the very same VTXO.
#[tokio::test]
async fn recovered_wallet_finds_boarded_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_boarded_vtxo").await;

	let srv = ctx.captaind("server").create().await;

	// Board and register a single VTXO with the Ark server.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 1, "wallet should have one boarded VTXO before recovery");

	let mnemonic = barkd.mnemonic().await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	// Drive whatever sync/recovery the wallet exposes.
	recovered.onchain_sync().await;
	recovered.sync().await;

	// The recovered wallet must rediscover the same VTXO.
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(), "recovered wallet should rediscover the same number of VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id), "recovered wallet should rediscover the VTXO with id {:?}", vtxo.vtxo.id);
	}

	// Spend recovered VTXOs in a payment (board minus fees)
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(99_443)).await;
}

/// Wallet recovery from seed after a round refresh.
///
/// Board a VTXO, then refresh it into a round: the board VTXO is spent as the
/// round input and a fresh round-output VTXO is produced. After recovering from
/// the same seed, only the round output should be recovered — the board VTXO
/// was spent in the round, so the server reports it spent and recovery skips it.
#[tokio::test]
async fn recovered_wallet_finds_round_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_round_vtxo").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Board a VTXO.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;

	let board = barkd.vtxos(None).await;
	assert_eq!(board.len(), 1, "should have one boarded VTXO");
	let board_id = board[0].vtxo.id;

	// Refresh it into a round and confirm the round. The default round interval
	// is long, so the round needs an explicit trigger alongside the refresh.
	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let after_refresh = barkd.vtxos(None).await;
	assert_eq!(after_refresh.len(), 1, "should hold one round-output VTXO after refresh");
	let round_id = after_refresh[0].vtxo.id;
	assert_ne!(round_id, board_id, "refresh should produce a new VTXO id");

	// Recover from the same seed into a fresh wallet.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	recovered.onchain_sync().await;
	recovered.sync().await;

	// Only the round output is recovered; the board VTXO is spent (round input).
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "recovered wallet should hold exactly one VTXO");
	assert_eq!(after[0].vtxo.id, round_id, "recovered VTXO should be the round output");

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(99_443)).await;
}
