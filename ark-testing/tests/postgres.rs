use ark_testing::TestContext;
use aspd::database::Db;

use ark::test::dummy;

#[tokio::test]
async fn upsert_vtxo() {
	let mut ctx = TestContext::new_minimal("postgresd/upsert_vtxo").await;
	let postgres_cfg = ctx.init_central_postgres().await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create a few dummy vtxo's
	let board_1 = dummy::DummyVtxoBuilder::new(1).build();
	let board_2 = dummy::DummyVtxoBuilder::new(2).build();
	let board_3 = dummy::DummyVtxoBuilder::new(3).build();

	db.upsert_vtxos(&[board_1.clone(), board_2.clone()]).await.expect("Query succeeded");
	db.get_vtxos_by_id(&[board_1.id(), board_2.id()]).await.expect("Query succeeded");
	db.get_vtxos_by_id(&[board_3.id()]).await.expect_err("Query Failed because 3 isn't in the db yet");

	// It shouldn't complain if board_2 is already present
	db.upsert_vtxos(&[board_2, board_3]).await.expect("Query succeeded");
}

