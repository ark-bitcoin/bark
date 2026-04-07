use ark::encode::ProtocolEncoding;
use ark::ServerVtxo;
use ark::test_util::VTXO_VECTORS;
use server::database::Db;

use ark_testing::TestContext;

#[tokio::test]
async fn get_bare_vtxo_by_id() {
	let mut ctx = TestContext::new_minimal("postgresd/get_bare_vtxo_by_id").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos([vtxo.clone()]).await.unwrap();

	let bare = db.get_bare_vtxo_by_id(vtxo.id()).await.unwrap();

	assert_eq!(bare.vtxo_id, vtxo.id());
	assert_eq!(bare.vtxo.amount(), vtxo.amount());
	assert_eq!(bare.vtxo.exit_delta(), vtxo.exit_delta());
	assert_eq!(bare.vtxo.server_pubkey(), vtxo.server_pubkey());
	assert_eq!(bare.vtxo.chain_anchor(), vtxo.chain_anchor());
	assert_eq!(bare.vtxo.expiry_height(), vtxo.expiry_height());
	assert_eq!(bare.vtxo.policy().serialize(), vtxo.policy().serialize());
}
