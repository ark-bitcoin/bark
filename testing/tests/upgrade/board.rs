//! Board cut off mid-flight across an upgrade.

use ark_testing::{btc, constants, TestContext};
use ark_testing::util::upgrade_from_exec;

use crate::common::{assert_action_completed, assert_parked_at, assert_upgrade_spans_builds};

/// Broadcast under the old release, registered under the new one. Boards are the
/// action most exposed to migrations: `m0038` already rewrote legacy rows once.
#[tokio::test]
async fn board_started_before_upgrade_registers_after_upgrade() {
	let ctx = TestContext::new("upgrade/board_started_before_upgrade").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	srv.wait_for_vtxopool(&ctx).await;

	let board_amount = btc(2);
	let old = ctx.bark("bark", &srv)
		.exec(upgrade_from_exec())
		.funded(btc(3))
		.create().await;

	// Leaving the funding tx unconfirmed parks the board at `Confirming`,
	// so this one needs no proxy.
	let board = old.board(board_amount).await;
	ctx.await_transaction(board.funding_tx.txid).await;

	assert_parked_at(&old, "board.Confirming").await;

	let new = old.upgraded().await;
	assert_upgrade_spans_builds(&old, &new).await;

	// Confirm and let the upgraded build finish the registration.
	ctx.generate_blocks(constants::BOARD_CONFIRMATIONS).await;
	new.maintain().await;
	new.sync().await;

	assert_eq!(
		new.spendable_balance().await, board_amount,
		"the upgraded build should have registered the board the old one broadcast",
	);
	assert_action_completed(&new).await;
}
