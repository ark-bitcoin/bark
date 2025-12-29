use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use chrono::Local;

use ark::{lightning::Invoice, vtxo::test::VTXO_VECTORS};
use ark::integration::{TokenStatus, TokenType};

use bark::lightning_invoice::Bolt11Invoice;
use bitcoin_ext::BlockRef;
use cln_rpc::listsendpays_request::ListsendpaysIndex;

use server::database::Db;
use server::filters;
use server::filters::Filters;


use ark_testing::TestContext;

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
	let (lightning_node_id2, _dt) = db.register_lightning_node(&dummy_public_key).await.unwrap();
	assert_eq!(lightning_node_id, lightning_node_id2);

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
		RETURNING id;
	").await.unwrap();

	let err = db_client.query_one(
		&stmt, &[&invoice.to_string(), &&invoice.payment_hash().to_vec()[..]],
	).await.unwrap_err();
	assert!(err.as_db_error()
		.expect("db error expected").to_string()
		.contains("duplicate key value violates unique constraint \"lightning_invoice_payment_hash_key\""), "err: {}", err);
}

#[tokio::test]
async fn integration() {
	let mut ctx = TestContext::new_minimal("postgresd/integration").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let integration_second = db.store_integration("second").await.unwrap();
	assert_ne!(integration_second.id, 0);

	let integration_second = db.get_integration_by_name("second").await.unwrap()
		.expect("Second's integration not found in database");
	assert_ne!(integration_second.id, 0);

	let integration_second = db.get_integration_by_id(integration_second.id).await.unwrap()
		.expect("Second's integration not found in database");
	assert_ne!(integration_second.id, 0);
	assert_eq!(integration_second.deleted_at, None);

	let integration_second = db.delete_integration(integration_second.id).await.unwrap();
	assert_ne!(integration_second.deleted_at, None);

	let integration_third = db.store_integration("third").await.unwrap();
	assert_ne!(integration_third.id, 0);

	let api_key = uuid::Uuid::new_v4();
	let integration_api_key_second = db.store_integration_api_key(
		"second_api_key",
		api_key.clone(),
		&filters::Filters::new(),
		integration_second.id,
		Local::now(),
	).await.unwrap();
	assert_ne!(integration_api_key_second.id, 0);

	let integration_api_key_second = db.get_integration_api_key_by_api_key(api_key).await.unwrap()
		.expect("Second's integration API key not found in database");
	assert_ne!(integration_api_key_second.id, 0);
	assert_eq!(integration_api_key_second.deleted_at, None);
	assert!(integration_api_key_second.filters.is_empty());

	let integration_api_key_second = db.get_integration_api_key_by_name(
		integration_second.name.as_str(), integration_api_key_second.name.as_str(),
	).await.unwrap()
		.expect("Second's integration API key not found in database");
	assert_ne!(integration_api_key_second.id, 0);
	assert_eq!(integration_api_key_second.deleted_at, None);
	assert!(integration_api_key_second.filters.is_empty());

	let integration_api_key_second = db.update_integration_api_key(
		integration_api_key_second,
		&Filters::init(vec!["127.0.0.1".to_string()], vec!["localhost".to_string()]),
	).await.unwrap();
	assert!(!integration_api_key_second.filters.is_empty());

	let integration_api_key_second = db.delete_integration_api_key(
		integration_api_key_second.id,
		integration_api_key_second.updated_at,
	).await.unwrap();
	assert_ne!(integration_api_key_second.deleted_at, None);

	let integration_api_key_third = db.store_integration_api_key(
		"third_api_key", uuid::Uuid::new_v4(), &filters::Filters::new(), integration_third.id, Local::now()
	).await.unwrap();
	assert_ne!(integration_api_key_third.integration_id, 0);

	let integration_token_config_second = db.store_integration_token_config(
		TokenType::SingleUseBoard,
		1,
		2,
		integration_second.id,
	)
		.await.unwrap();
	assert_ne!(integration_token_config_second.id, 0);
	assert_eq!(integration_token_config_second.maximum_open_tokens, 1);
	assert_eq!(integration_token_config_second.active_seconds, 2);
	assert_eq!(integration_token_config_second.integration_id, integration_second.id);
	let integration_token_config_second = db.update_integration_token_config(
		integration_token_config_second,
		10,
		11,
	).await.unwrap();
	assert_eq!(integration_token_config_second.maximum_open_tokens, 10);
	assert_eq!(integration_token_config_second.active_seconds, 11);

	let integration_token_config_second = db.delete_integration_token_config(
		integration_token_config_second.id,
		integration_token_config_second.updated_at,
	).await.unwrap();
	assert_ne!(integration_token_config_second.deleted_at, None);

	let token = uuid::Uuid::new_v4().to_string();
	let tomorrow = Local::now() + chrono::Duration::days(1);
	let integration_token_third = db.store_integration_token(
		token.as_str(), TokenType::SingleUseBoard, TokenStatus::Unused, tomorrow,
		&filters::Filters::new(),
		integration_third.id, integration_api_key_third.id,
	).await.unwrap();
	assert_ne!(integration_token_third.id, 0);

	let integration_token_third = db.get_integration_token(token.as_str()).await.unwrap()
		.expect("Token is not found in database");
	assert_eq!(integration_token_third.integration_id, integration_third.id);

	let count = db.count_open_integration_tokens(integration_third.id, TokenType::SingleUseBoard).await.unwrap();
	assert_eq!(count, 1);

	let integration_token_third = db.update_integration_token(
		integration_token_third,
		integration_api_key_second.id,
		TokenStatus::Used,
		&Filters::init(
			Vec::from(&["127.0.0.1".to_string()]),
			Vec::from(&["localhost".to_string()]),
		),
	).await.unwrap();
	assert_eq!(integration_token_third.integration_id, integration_third.id);
	assert_ne!(integration_token_third.status, TokenStatus::Unused);
	assert!(!integration_token_third.filters.is_empty());

	let count = db.count_open_integration_tokens(integration_third.id, TokenType::SingleUseBoard).await.unwrap();
	assert_eq!(count, 0);
}

#[tokio::test]
async fn block_database_crud() {
	let mut ctx = TestContext::new_minimal("postgresd/block_db_crud").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Construct some mock block refs
	let hash1 = bitcoin::BlockHash::from_str("0000000000000000000670ab57e8c1a4637b22d1d56e4c2837d08ec9a61e7777").unwrap();
	let block1 = BlockRef {
		height: 1,
		hash: hash1,
	};

	let hash2 = bitcoin::BlockHash::from_str("00000000000000000003acbe2c55c3b2ee3421fd4b726e2f8ef6e7ef1ecc4777").unwrap();
	let block2 = BlockRef {
		height: 2,
		hash: hash2,
	};

	// Initially no blocks
	assert!(db.get_block_by_height(1).await.unwrap().is_none());
	assert!(db.get_block_by_height(2).await.unwrap().is_none());

	// Initially no tip
	assert!(db.get_highest_block().await.unwrap().is_none());

	// Store first block
	db.store_block(&block1).await.expect("Store block1");
	{
		let stored = db.get_block_by_height(1).await.unwrap().expect("block1 present");
		assert_eq!(stored.height, block1.height);
		assert_eq!(stored.hash, block1.hash);
		assert_eq!(db.get_highest_block
().await.unwrap(), Some(block1.clone()));
	}

	// Store second block
	db.store_block(&block2).await.expect("Store block2");
	{
		let stored = db.get_block_by_height(2).await.unwrap().expect("block2 present");
		assert_eq!(stored.height, block2.height);
		assert_eq!(stored.hash, block2.hash);
		assert_eq!(db.get_highest_block
().await.unwrap(), Some(block2.clone()));
	}

	// Try to add a conflicting block at block-height 2
	let hash2_conflict = bitcoin::BlockHash::from_str("11111111111111111111acbe2c55c3b2ee3421fd4b726e2f8ef6e7ef1ecc4777").unwrap();
	let block2_conflict = BlockRef {
		height: 2,
		hash: hash2_conflict,
	};

	let result = db.store_block(&block2_conflict).await;
	assert!(result.is_err(), "Storing a conflicting block at the same height should error");

	// Remove blocks above height2 (block2 should still be there)
	db.remove_blocks_above(2).await.expect("Remove above height2");
	assert!(db.get_block_by_height(2).await.unwrap().is_some()); // block2 still there
	assert!(db.get_block_by_height(1).await.unwrap().is_some()); // block1 still there
	assert_eq!(db.get_highest_block().await.unwrap(), Some(block2.clone())); // Tip should be at block2

	// Remove blocks above height1 (block1 should still be there)
	db.remove_blocks_above(1).await.expect("Remove above height1");
	assert!(db.get_block_by_height(1).await.unwrap().is_some()); // block1 still there
	assert_eq!(db.get_highest_block().await.unwrap(), Some(block1.clone())); // Tip should be at block1
}
