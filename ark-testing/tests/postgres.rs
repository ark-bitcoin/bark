use std::str::FromStr;
use bitcoin::secp256k1::PublicKey;
use ark_testing::TestContext;
use aspd::database::Db;

use ark::test::dummy;
use cln_rpc::listsendpays_request::ListsendpaysIndex;

#[tokio::test]
async fn upsert_vtxo() {
	let mut ctx = TestContext::new_minimal("postgresd/upsert_vtxo").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.name).await;

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


#[tokio::test]
async fn lightning_invoice() {
	let mut ctx = TestContext::new_minimal("postgresd/lightning_node").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let dummy_public_key = PublicKey::from_str("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354")
		.expect("Failed to create dummy pubkey");

	let (lightning_node_id, _dt) = db.register_lightning_node(&dummy_public_key).await.unwrap();
	assert_ne!(lightning_node_id, 0);
	let (lightning_invoice_id2, _dt) = db.register_lightning_node(&dummy_public_key).await.unwrap();
	assert_eq!(lightning_node_id, lightning_invoice_id2);

	db.store_lightning_payment_index(lightning_node_id, ListsendpaysIndex::Created, 1).await.unwrap();
	db.store_lightning_payment_index(lightning_node_id, ListsendpaysIndex::Updated, 2).await.unwrap();

	let payment_indexes = db.get_lightning_payment_indexes(lightning_node_id).await.unwrap().unwrap();
	assert_eq!(payment_indexes.created_index, 1);
	assert_eq!(payment_indexes.updated_index, 2);
}

