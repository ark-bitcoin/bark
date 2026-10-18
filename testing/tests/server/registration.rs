use ark::{vtxo::Bare, vtxo::Full, ProtocolEncoding, Vtxo, VtxoPolicy};
use bitcoin::OutPoint;
use bitcoin_ext::BlockHeight;
use bitcoin_ext::rpc::RpcApi;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::exit::complete_exit;

/// The same vtxo twice in one registration request must be accepted as an
/// idempotent no-op. Without the handler-level dedupe the duplicate ids reach
/// the tree-update validation, which panics in debug builds via `debug_assert!`.
#[tokio::test]
async fn register_vtxo_transactions_accepts_duplicate_ids() {
	let ctx = TestContext::new("server/register_vtxo_transactions_accepts_duplicate_ids").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(90_000)).create().await;
	let vtxo_ids = bark.board_and_confirm_and_register(&ctx, sat(80_000)).await;
	assert_eq!(vtxo_ids.len(), 1);

	// Board registration stored the fully-signed vtxo; replay it twice in
	// one request through the real RPC.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let blob = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo FROM vtxo WHERE vtxo_id = $1", &[&vtxo_ids[0].to_string()],
		).await?;
		Ok(row.get::<_, Vec<u8>>(0))
	}).await.unwrap();

	let mut client = srv.get_public_rpc().await;
	client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
		vtxos: vec![blob.clone(), blob],
	}).await.expect("duplicate ids in one request should be accepted");
}

/// Acknowledges vtxo transaction registrations without forwarding them, so
/// the server keeps the resulting vtxos `unregistered` and holds their
/// transactions unsigned.
#[derive(Clone)]
struct DropRegistration;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for DropRegistration {
	async fn register_vtxo_transactions(
		&self, _upstream: &mut ArkClient, _req: protos::RegisterVtxoTransactionsRequest,
	) -> Result<protos::Empty, tonic::Status> {
		Ok(protos::Empty {})
	}
}

/// The sender cosigns an arkoor but never registers the signed chain, so the
/// server holds the checkpoint tx unsigned and the watchman can only wait when
/// the input's exit confirms. Once the owner took the input through its exit
/// clause, the checkpoint can never confirm, so registering the child must be
/// refused.
#[tokio::test]
async fn register_vtxo_transactions_refuses_child_of_exited_input() {
	let ctx = TestContext::new("server/register_vtxo_transactions_refuses_child_of_exited_input").await;
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

	// both wallets reach the server through the proxy, so neither of them
	// registers the arkoor output
	let proxy = srv.start_proxy_no_mailbox(DropRegistration).await;
	bark1.set_ark_url(&proxy.address).await;
	let bark2 = ctx.bark("bark2", &proxy.address).create().await;
	bark1.send_oor(bark2.address().await, sat(50_000)).await;
	let child_ids = bark2.vtxo_ids().await;
	assert_eq!(child_ids.len(), 1);
	let child = bark2.raw_vtxo(child_ids[0]).await;

	// the stale clone exits the input and claims it after the exit delta
	bark1_old.start_exit_all().await;
	complete_exit(&ctx, &bark1_old).await;
	bark1_old.claim_all_exits(bark1_old.get_onchain_address().await).await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	let mut client = srv.get_public_rpc().await;
	let err = client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
		vtxos: vec![child.serialize()],
	}).await.expect_err("registering the child of an exited input must be refused");
	assert!(err.message().contains("exited onchain"), "unexpected error: {}", err.message());

	// the child stays unregistered
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::TEXT FROM vtxo WHERE vtxo_id = $1",
			&[&child_ids[0].to_string()],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "unregistered");
}

/// Builds a bare-vtxo encoding that decodes back to a full vtxo with the same
/// id, the same point and policy, an empty history anchored to its own
/// terminal outpoint, and the given (forged) expiry. This works because the
/// Pubkey policy output does not commit to the outer expiry.
fn reanchored_vtxo(vtxo: &Vtxo<Full>, expiry: BlockHeight) -> Vtxo<Full> {
	let fake = Vtxo::<Bare, VtxoPolicy>::new(
		vtxo.point(),
		vtxo.policy().clone(),
		vtxo.amount(),
		expiry,
		vtxo.server_pubkey(),
		vtxo.exit_delta(),
		vtxo.point(),
	);
	<Vtxo<Full>>::deserialize(&fake.serialize())
		.expect("a bare encoding re-anchors as an empty-genesis full vtxo")
}


/// A registration may only add witnesses to a stored vtxo. Re-anchoring a
/// pubkey vtxo at its own point with an empty chain and a forged expiry
/// passes validation against the anchor, so the server has to compare it
/// with the stored vtxo and refuse it. Otherwise offboarding the forged vtxo
/// builds a connector that the watchman sweeps before the genuine expiry,
/// and the owner exits the original vtxo after being paid out.
#[tokio::test]
async fn register_vtxo_transactions_refuses_reanchoring_with_forged_expiry() {
	let ctx = TestContext::new(
		"server/register_vtxo_transactions_refuses_reanchoring_with_forged_expiry",
	).await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	// board, then send to self so the vtxo has a signed arkoor chain
	bark.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	bark.send_oor(&bark.address().await, sat(700_000)).await;
	let target_id = bark.vtxos().await.into_iter()
		.find(|v| v.vtxo.amount == sat(700_000))
		.expect("oor destination vtxo")
		.vtxo.id;

	// anyone can fetch the vtxo by id
	let mut client = srv.get_public_rpc().await;
	let blob = client.get_vtxo(protos::GetVtxoRequest {
		vtxo_id: target_id.to_bytes().to_vec(),
	}).await.unwrap().into_inner().vtxo;
	let vtxo = <Vtxo<Full>>::deserialize(&blob).unwrap();

	let forged = reanchored_vtxo(&vtxo, BlockHeight::new(0));
	assert_eq!(forged.id(), target_id);
	let err = client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
		vtxos: vec![forged.serialize()],
	}).await.expect_err("re-anchoring a registered vtxo must be refused");
	assert!(err.message().contains("does not match the stored vtxo"),
		"unexpected error: {}", err.message());

	// the server still holds the genuine vtxo
	let blob = client.get_vtxo(protos::GetVtxoRequest {
		vtxo_id: target_id.to_bytes().to_vec(),
	}).await.unwrap().into_inner().vtxo;
	let stored = <Vtxo<Full>>::deserialize(&blob).unwrap();
	assert_eq!(stored.chain_anchor(), vtxo.chain_anchor());
	assert_eq!(stored.expiry_height(), vtxo.expiry_height());
	assert_eq!(stored.exit_depth(), vtxo.exit_depth());
}

/// Offboarding builds its connector from the stored input vtxos, and the
/// watchman sweeps the connector once the tip passes the connector expiry.
/// If a registration could forge the inputs' expiry to 0, the connector
/// would be swept long before the inputs expire, and the owner could then
/// exit the original vtxos after already being paid by the offboard.
#[tokio::test]
async fn reanchoring_cannot_make_watchman_sweep_offboard_connector_early() {
	let ctx = TestContext::new(
		"server/reanchoring_cannot_make_watchman_sweep_offboard_connector_early",
	).await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().watchmand().create().await;
	let wm = srv.watchmand();

	// four inputs make the connector root large enough to pay for its own sweep
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	for _ in 0..4 {
		bark.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	}
	let ids = bark.vtxo_ids().await;
	assert_eq!(ids.len(), 4);

	let mut client = srv.get_public_rpc().await;
	let mut expiries = Vec::new();
	let mut forged = Vec::new();
	for id in &ids {
		let blob = client.get_vtxo(protos::GetVtxoRequest {
			vtxo_id: id.to_bytes().to_vec(),
		}).await.unwrap().into_inner().vtxo;
		let vtxo = <Vtxo<Full>>::deserialize(&blob).unwrap();
		expiries.push(vtxo.expiry_height());
		forged.push(reanchored_vtxo(&vtxo, BlockHeight::new(0)).serialize());
	}
	let min_expiry = *expiries.iter().min().unwrap();
	let max_expiry = *expiries.iter().max().unwrap();

	// Whether the server refuses this is checked above; this test checks
	// what an accepted forgery leads to.
	let _ = client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
		vtxos: forged,
	}).await;

	let offboard_txid = bark.offboard_all(ctx.bitcoind().get_new_address()).await.offboard_txid;
	ctx.generate_blocks(1).await;
	// the connector root is the second output of the offboard tx
	let connector_point = OutPoint::new(offboard_txid, 1);

	// Mine past what a forged connector expiry would be (0 + 144), but stay
	// before any of the inputs expire.
	let tip = ctx.generate_blocks(170).await;
	assert!(tip < min_expiry, "inputs must not have expired yet");
	wm.wait_for_sync_height(tip).await;
	wm.trigger_sweep().await;
	let tip = ctx.generate_blocks(1).await;
	wm.wait_for_sync_height(tip).await;

	let unspent = ctx.bitcoind().sync_client()
		.get_tx_out(&connector_point.txid, connector_point.vout, Some(true)).unwrap();
	assert!(unspent.is_some(),
		"watchman swept offboard connector {} at tip {} while the inputs only expire \
		at {}: the owner can exit the original vtxos and be paid twice",
		connector_point, tip, min_expiry,
	);

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let connector_expiry = db.read(async |t| {
		let row = t.query_one(
			"SELECT expiry FROM vtxo WHERE vtxo_id = $1", &[&connector_point.to_string()],
		).await?;
		Ok(row.get::<_, i32>(0))
	}).await.unwrap();
	assert_eq!(connector_expiry as u32, max_expiry.to_u32() + 144);
}
