use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

/// Ban a vtxo, verify OOR/refresh/offboard all fail, then unban and
/// verify they succeed again.
#[tokio::test]
async fn banned_vtxo_cannot_be_spent() {
	let ctx = TestContext::new("ban/spend").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.sync().await;

	let vtxos = bark1.vtxo_ids().await;
	assert_eq!(vtxos.len(), 1);

	// Ban the vtxo for 100 blocks
	srv.ban_vtxo(vtxos[0], 100).await;
	assert_eq!(srv.list_banned_vtxos().await.len(), 1);

	// OOR send should fail
	let bark2_addr = bark2.address().await;
	let err = bark1.try_send_oor(&bark2_addr, sat(50_000), true).await;
	assert!(err.is_err(), "OOR send should fail with banned vtxo");

	// Refresh should fail (needs a round to be triggered concurrently)
	let (err, _) = tokio::join!(
		bark1.try_refresh_all_no_retry(),
		srv.trigger_round(),
	);
	assert!(err.is_err(), "refresh should fail with banned vtxo");

	// Offboard should fail
	let addr = bark1.get_onchain_address().await;
	let err = bark1.try_offboard_all(&addr).await;
	assert!(err.is_err(), "offboard should fail with banned vtxo");

	// Unban the vtxo
	srv.unban_vtxo(vtxos[0]).await;
	assert!(srv.list_banned_vtxos().await.is_empty());

	// OOR send should now succeed
	bark1.send_oor(&bark2_addr, sat(50_000)).await;
}
