use ark::encode::ProtocolEncoding;
use ark::ServerVtxo;
use ark::test_util::VTXO_VECTORS;

use server::database::Db;

use ark_testing::TestContext;

#[tokio::test]
async fn fill_vtxo_data() {
	let mut ctx = TestContext::new_minimal("postgresd/fill_vtxo_data").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Insert vtxos (these will already have the new columns filled)
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos([vtxo.clone()]).await.unwrap();

	// NULL out the new columns to simulate pre-migration data
	let client = ctx.postgres_manager().database_client(Some(&ctx.test_name)).await;
	client.execute(
		"UPDATE vtxo SET exit_delta = NULL, policy_type = NULL, policy = NULL,
		 server_pubkey = NULL, amount = NULL, anchor_point = NULL, updated_at = NOW()",
		&[],
	).await.unwrap();

	// Run the data migration
	let count = server::database::data_migrations::fill_vtxo_data::run(&db).await.unwrap();
	assert_eq!(count, 1);

	// Verify the columns are filled correctly
	let row = client.query_one(
		"SELECT exit_delta, policy_type, policy, amount, server_pubkey, anchor_point
		 FROM vtxo WHERE vtxo_id = $1",
		&[&vtxo.id().to_string()],
	).await.unwrap();

	assert_eq!(row.get::<_, i32>("exit_delta"), vtxo.exit_delta() as i32);
	assert_eq!(row.get::<_, String>("policy_type"), vtxo.policy_type().to_string());
	assert_eq!(row.get::<_, Vec<u8>>("policy"), vtxo.policy().serialize());
	assert_eq!(row.get::<_, i64>("amount"), vtxo.amount().to_sat() as i64);
	assert_eq!(row.get::<_, String>("server_pubkey"), vtxo.server_pubkey().to_string());
	assert_eq!(row.get::<_, String>("anchor_point"), vtxo.chain_anchor().to_string());

	// Running again should be a no-op
	let count = server::database::data_migrations::fill_vtxo_data::run(&db).await.unwrap();
	assert_eq!(count, 0);
}
