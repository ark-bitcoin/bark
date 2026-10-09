use ark::ProtocolEncoding;
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
