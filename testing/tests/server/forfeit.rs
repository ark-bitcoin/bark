use std::sync::Arc;

use parking_lot::Mutex;

use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::exit::complete_exit;

/// Forwards the hArk forfeit calls and records how the server answered them.
#[derive(Clone, Default)]
struct RecordForfeit {
	nonces: Arc<Mutex<Option<Result<(), String>>>>,
	forfeit: Arc<Mutex<Option<Result<(), String>>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RecordForfeit {
	async fn request_forfeit_nonces(
		&self, upstream: &mut ArkClient, req: protos::ForfeitNoncesRequest,
	) -> Result<protos::ForfeitNoncesResponse, tonic::Status> {
		let res = upstream.request_forfeit_nonces(req).await;
		*self.nonces.lock() = Some(res.as_ref().map(|_| ()).map_err(|e| e.message().to_owned()));
		Ok(res?.into_inner())
	}

	async fn forfeit_vtxos(
		&self, upstream: &mut ArkClient, req: protos::ForfeitVtxosRequest,
	) -> Result<protos::ForfeitVtxosResponse, tonic::Status> {
		let res = upstream.forfeit_vtxos(req).await;
		*self.forfeit.lock() = Some(res.as_ref().map(|_| ()).map_err(|e| e.message().to_owned()));
		Ok(res?.into_inner())
	}
}

/// A round input passes every check when it joins the round and the round
/// finishes. Before the owner forfeits it, a stale copy of the wallet exits
/// the input and claims it through its exit clause. The forfeit that follows
/// could never confirm, so the server must refuse it instead of releasing
/// the unlock preimage.
#[tokio::test]
async fn forfeit_refuses_exited_input() {
	let ctx = TestContext::new("server/forfeit_refuses_exited_input").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().watchmand().create().await;
	let wm = srv.watchmand();

	// bark1 refreshes a board into a round vtxo; the clone keeps a copy of it
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	assert_eq!(bark1.vtxo_ids().await.len(), 1);
	let bark1_old = bark1.full_clone("bark1_old").await;

	let record = RecordForfeit::default();
	let proxy = srv.start_proxy_no_mailbox(record.clone()).await;
	bark1.set_ark_url(&proxy.address).await;

	// the round vtxo joins a second round; bark1 only forfeits it once the
	// round tx confirmed and it syncs again
	ctx.refresh_all(&srv, &[&bark1]).await;
	assert!(record.nonces.lock().is_none(), "forfeit started before the round confirmed");

	// meanwhile the stale clone exits the input and claims it after the exit delta
	bark1_old.start_exit_all().await;
	complete_exit(&ctx, &bark1_old).await;
	bark1_old.claim_all_exits(bark1_old.get_onchain_address().await).await;
	let tip = ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wm.wait_for_sync_height(tip).await;

	// bark1 now tries to finish the hArk swap
	bark1.sync().await;
	let nonces = record.nonces.lock().clone().expect("bark did not request forfeit nonces");
	let forfeit = record.forfeit.lock().clone();
	assert!(!matches!(forfeit, Some(Ok(()))), "server signed the forfeit of an exited input");
	let err = nonces.err().or_else(|| forfeit.and_then(|r| r.err()))
		.expect("server accepted the forfeit calls for an exited input");
	assert!(err.contains("exited onchain"), "unexpected error: {err}");

	// the participation was not forfeited, so the preimage was not released
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let forfeited = db.read(async |t| {
		let row = t.query_one(
			"SELECT forfeited_at IS NOT NULL FROM round_participation \
			WHERE round_id IS NOT NULL ORDER BY id DESC LIMIT 1",
			&[],
		).await?;
		Ok(row.get::<_, bool>(0))
	}).await.unwrap();
	assert!(!forfeited, "server released the unlock preimage for an exited input");
}
