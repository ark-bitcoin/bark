use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};

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
