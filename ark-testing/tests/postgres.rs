use std::str::FromStr;
use ark::{lightning::Invoice, vtxo::test::VTXO_VECTORS};
use bark::lightning_invoice::Bolt11Invoice;
use bitcoin::secp256k1::PublicKey;
use ark_testing::TestContext;
use server::database::Db;

use cln_rpc::listsendpays_request::ListsendpaysIndex;

#[tokio::test]
async fn upsert_vtxo() {
	let mut ctx = TestContext::new_minimal("postgresd/upsert_vtxo").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create a few dummy vtxo's
	let vtxo1 = &VTXO_VECTORS.board_vtxo;
	let vtxo2 = &VTXO_VECTORS.round1_vtxo;
	let vtxo3 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;

	db.upsert_vtxos(&[vtxo1.clone(), vtxo2.clone()]).await.expect("Query succeeded");
	db.get_vtxos_by_id(&[vtxo1.id(), vtxo2.id()]).await.expect("Query succeeded");
	db.get_vtxos_by_id(&[vtxo3.id()]).await.expect_err("Query Failed because 3 isn't in the db yet");

	// It shouldn't complain if vtxo2 is already present
	db.upsert_vtxos(&[vtxo2.clone(), vtxo3.clone()]).await.expect("Query succeeded");
}


#[tokio::test]
async fn lightning_invoice() {
	let mut ctx = TestContext::new_minimal("postgresd/lightning_node").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

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

#[tokio::test]
async fn duplicated_lightning_invoice() {
	let mut ctx = TestContext::new_minimal("postgresd/duplicated_lightning_invoice").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let dummy_public_key = PublicKey::from_str("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354")
		.expect("Failed to create dummy pubkey");

	let invoice = Bolt11Invoice::from_str("lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8").unwrap();
	let invoice = Invoice::Bolt11(invoice);

	let (lightning_node_id, _dt) = db.register_lightning_node(&dummy_public_key).await.unwrap();
	assert_ne!(lightning_node_id, 0);

	db.store_lightning_payment_start(lightning_node_id, &invoice, 1000).await.unwrap();

	// We create a test db client because Db check lightning invoice uniqueness
	let db_client = ctx.postgres_manager().database_client(Some(&ctx.test_name)).await;

	let stmt = db_client.prepare("
		INSERT INTO lightning_invoice (
			invoice,
			payment_hash,
			created_at,
			updated_at
		) VALUES ($1, $2, NOW(), NOW())
		RETURNING lightning_invoice_id;
	").await.unwrap();

	let err = db_client.query_one(
		&stmt, &[&invoice.to_string(), &&invoice.payment_hash().to_vec()[..]],
	).await.unwrap_err();
	assert!(err.to_string().contains("duplicate key value violates unique constraint \"lightning_invoice_payment_hash_key\""), "err: {}", err);
}
