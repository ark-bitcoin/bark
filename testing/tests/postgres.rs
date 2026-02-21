use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Transaction;
use chrono::Local;

use ark::ServerVtxo;
use ark::integration::{TokenStatus, TokenType};
use ark::lightning::Invoice;
use ark::test_util::VTXO_VECTORS;

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
	let vtxo1 = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let vtxo2 = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	let vtxo3 = ServerVtxo::from(VTXO_VECTORS.arkoor_htlc_out_vtxo.clone());

	db.upsert_vtxos(&[vtxo1.clone(), vtxo2.clone()]).await.expect("Query succeeded");
	db.get_user_vtxos_by_id(&[vtxo1.id(), vtxo2.id()]).await.expect("Query succeeded");
	db.get_user_vtxos_by_id(&[vtxo3.id()]).await.expect_err("Query Failed because 3 isn't in the db yet");

	// It shouldn't complain if vtxo2 is already present
	db.upsert_vtxos(&[vtxo2.into(), vtxo3.clone()]).await.expect("Query succeeded");
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

#[tokio::test]
async fn upsert_virtual_transaction() {
	let mut ctx = TestContext::new_minimal("postgresd/virtual_transaction").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create a dummy transaction
	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Step 1: Insert an unsigned vtx
	let returned_txid = db.upsert_virtual_transaction(txid, None, false, None).await
		.expect("Failed to insert vtx");
	assert_eq!(returned_txid, txid);

	// Step 2: Verify retrieval returns correct fields with signed_tx = None
	let vtx = db.get_virtual_transaction_by_txid(txid).await
		.expect("Failed to get vtx").unwrap();
	assert_eq!(vtx.txid, txid);
	assert_eq!(vtx.signed_tx, None);
	assert_eq!(vtx.is_funding, false);

	// Step 3: Upsert same txid with signed_tx = Some(tx) (fill in signature)
	let returned_txid2 = db.upsert_virtual_transaction(txid, Some(&tx), false, None).await
		.expect("Failed to upsert signed vtx");
	assert_eq!(returned_txid2, txid);

	// Step 4: Verify signed_tx is now populated
	let vtx_signed = db.get_virtual_transaction_by_txid(txid).await
		.expect("Failed to get signed vtx").unwrap();
	assert_eq!(vtx_signed.txid, txid);
	assert_eq!(vtx_signed.signed_tx().unwrap(), &tx);

	// Step 5: Upsert same txid with signed_tx = None again
	let returned_txid3 = db.upsert_virtual_transaction(txid, None, false, None).await
		.expect("Failed to upsert unsigned vtx again");
	assert_eq!(returned_txid3, txid);

	// Step 6: Verify signed_tx is STILL populated (COALESCE preserves existing)
	let vtx_after_unsigned = db.get_virtual_transaction_by_txid(txid).await
		.expect("Failed to get vtx after unsigned upsert").unwrap();
	assert_eq!(vtx_after_unsigned.signed_tx().unwrap(), &tx);

	// Step 7: Upsert multiple times (idempotency - no errors)
	db.upsert_virtual_transaction(txid, Some(&tx), false, None).await
		.expect("Idempotent upsert 1");
	db.upsert_virtual_transaction(txid, Some(&tx), false, None).await
		.expect("Idempotent upsert 2");
}

#[tokio::test]
async fn upsert_virtual_transaction_server_may_own_descendant() {
	let mut ctx = TestContext::new_minimal("postgresd/vtx_server_may_own_descendant").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Step 1: Insert vtx with server_may_own_descendant_since = None
	db.upsert_virtual_transaction(txid, None, false, None).await
		.expect("Failed to insert vtx");
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	assert!(vtx.server_may_own_descendant_since.is_none());

	// Step 2: Upsert with server_may_own_descendant_since = Some(timestamp)
	let timestamp = Local::now();
	db.upsert_virtual_transaction(txid, None, false, Some(timestamp)).await
		.expect("Failed to upsert with timestamp");

	// Step 3: Verify timestamp is now set
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	assert!(vtx.server_may_own_descendant_since.is_some());

	// Step 4: Upsert with server_may_own_descendant_since = None
	db.upsert_virtual_transaction(txid, None, false, None).await
		.expect("Failed to upsert with None");

	// Step 5: Verify timestamp is STILL set (COALESCE preserves existing)
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	assert!(vtx.server_may_own_descendant_since.is_some(),
		"COALESCE should preserve existing timestamp");
}

#[tokio::test]
async fn upsert_virtual_transaction_is_funding_preserved() {
	let mut ctx = TestContext::new_minimal("postgresd/vtx_is_funding_preserved").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Step 1: Insert vtx with is_funding = true
	db.upsert_virtual_transaction(txid, None, true, None).await
		.expect("Failed to insert vtx");
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	assert_eq!(vtx.is_funding, true);

	// Step 2: Upsert same txid with is_funding = false
	db.upsert_virtual_transaction(txid, None, false, None).await
		.expect("Failed to upsert");

	// Step 3: Verify is_funding is still true (not updated on conflict)
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	assert_eq!(vtx.is_funding, true,
		"is_funding should be preserved from original INSERT");
}

#[tokio::test]
async fn get_virtual_transaction_not_found() {
	let mut ctx = TestContext::new_minimal("postgresd/vtx_not_found").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create a txid without inserting it
	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(99),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Verify returns Ok(None) for non-existent txid
	let result = db.get_virtual_transaction_by_txid(txid).await
		.expect("Query should not error");
	assert!(result.is_none(), "Non-existent txid should return None");
}

#[tokio::test]
async fn get_first_unsigned_virtual_transaction() {
	let mut ctx = TestContext::new_minimal("postgresd/get_first_unsigned_vtx").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create 3 transactions with different txids
	let tx1 = Transaction {
		version: bitcoin::transaction::Version::non_standard(1),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let tx2 = Transaction {
		version: bitcoin::transaction::Version::non_standard(2),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let tx3 = Transaction {
		version: bitcoin::transaction::Version::non_standard(3),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let tx_nonexistent = Transaction {
		version: bitcoin::transaction::Version::non_standard(99),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};

	let txid1 = tx1.compute_txid();
	let txid2 = tx2.compute_txid();
	let txid3 = tx3.compute_txid();
	let txid_nonexistent = tx_nonexistent.compute_txid();

	// tx1: signed, tx2: unsigned, tx3: signed
	db.upsert_virtual_transaction(txid1, Some(&tx1), false, None).await.unwrap();
	db.upsert_virtual_transaction(txid2, None, false, None).await.unwrap();
	db.upsert_virtual_transaction(txid3, Some(&tx3), false, None).await.unwrap();

	// Test case 1: [tx1, tx2, tx3] -> Some(tx2)
	let result = db.get_first_unsigned_virtual_transaction(&[txid1, txid2, txid3]).await.unwrap();
	assert_eq!(result, Some(txid2), "Should find unsigned tx2");

	// Test case 2: [tx1, tx3] -> None (all signed)
	let result = db.get_first_unsigned_virtual_transaction(&[txid1, txid3]).await.unwrap();
	assert_eq!(result, None, "All signed should return None");

	// Test case 3: [tx_nonexistent] -> None (doesn't exist)
	let result = db.get_first_unsigned_virtual_transaction(&[txid_nonexistent]).await.unwrap();
	assert_eq!(result, None, "Non-existent should return None");

	// Test case 4: [] (empty) -> None
	let result = db.get_first_unsigned_virtual_transaction(&[]).await.unwrap();
	assert_eq!(result, None, "Empty input should return None");

	// Test case 5: [tx_nonexistent, tx2] -> Some(tx2)
	let result = db.get_first_unsigned_virtual_transaction(&[txid_nonexistent, txid2]).await.unwrap();
	assert_eq!(result, Some(txid2), "Should find unsigned tx2, ignoring non-existent");
}

#[tokio::test]
async fn upsert_vtxos_with_txid() {
	let mut ctx = TestContext::new_minimal("postgresd/vtxos_with_txid").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create vtxos using VTXO_VECTORS
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	// Upsert vtxos
	db.upsert_vtxos(&[vtxo.clone()]).await.expect("Failed to upsert vtxo");

	// Retrieve vtxos and verify they exist
	let vtxos = db.get_user_vtxos_by_id(&[vtxo.id()]).await.expect("Failed to get vtxo");
	assert_eq!(vtxos.len(), 1);

	// Query raw DB to check vtxo_txid column
	let db_client = ctx.postgres_manager().database_client(Some(&ctx.test_name)).await;
	let row = db_client.query_one(
		"SELECT vtxo_txid FROM vtxo WHERE vtxo_id = $1",
		&[&vtxo.id().to_string()]
	).await.expect("Failed to query raw DB");

	let vtxo_txid: String = row.get("vtxo_txid");

	// Verify value matches vtxo.point().txid
	assert_eq!(vtxo_txid, vtxo.point().txid.to_string(),
		"vtxo_txid should match vtxo.point().txid");
}

#[tokio::test]
async fn update_virtual_transaction_tree_atomic() {
	use std::borrow::Cow;
	use server::database::VirtualTransaction;

	let mut ctx = TestContext::new_minimal("postgresd/vtx_tree_atomic").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create virtual transaction
	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(42),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();
	let vtx = VirtualTransaction {
		txid,
		signed_tx: Some(Cow::Borrowed(&tx)),
		is_funding: true,
		server_may_own_descendant_since: None,
	};

	// Create vtxo
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	// Call update_virtual_transaction_tree
	db.update_virtual_transaction_tree(
		[vtx],
		[vtxo.clone()],
		std::iter::empty::<(ark::VtxoId, bitcoin::Txid)>(),
	).await.expect("Failed to update tree");

	// Verify virtual tx was inserted
	let retrieved_vtx = db.get_virtual_transaction_by_txid(txid).await
		.expect("Query failed").expect("Virtual tx not found");
	assert_eq!(retrieved_vtx.txid, txid);
	assert_eq!(retrieved_vtx.is_funding, true);

	// Verify vtxo was inserted
	let vtxos = db.get_user_vtxos_by_id(&[vtxo.id()]).await.expect("Query failed");
	assert_eq!(vtxos.len(), 1);
}

#[tokio::test]
async fn update_virtual_transaction_tree_empty_inputs() {
	use std::borrow::Cow;
	use server::database::VirtualTransaction;

	let mut ctx = TestContext::new_minimal("postgresd/vtx_tree_empty").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Test 1: All empty - should succeed
	db.update_virtual_transaction_tree(
		std::iter::empty::<VirtualTransaction>(),
		std::iter::empty::<ark::ServerVtxo>(),
		std::iter::empty::<(ark::VtxoId, bitcoin::Txid)>(),
	).await.expect("Empty inputs should succeed");

	// Test 2: Only virtual_txs populated
	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(100),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();
	let vtx = VirtualTransaction {
		txid,
		signed_tx: Some(Cow::Borrowed(&tx)),
		is_funding: false,
		server_may_own_descendant_since: None,
	};

	db.update_virtual_transaction_tree(
		[vtx],
		std::iter::empty::<ark::ServerVtxo>(),
		std::iter::empty::<(ark::VtxoId, bitcoin::Txid)>(),
	).await.expect("Only virtual_txs should succeed");

	// Verify it was inserted
	let retrieved = db.get_virtual_transaction_by_txid(txid).await.unwrap();
	assert!(retrieved.is_some());

	// Test 3: Only vtxos populated
	let vtxo = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	db.update_virtual_transaction_tree(
		std::iter::empty::<VirtualTransaction>(),
		[vtxo.clone()],
		std::iter::empty::<(ark::VtxoId, bitcoin::Txid)>(),
	).await.expect("Only vtxos should succeed");

	// Verify it was inserted
	let vtxos = db.get_user_vtxos_by_id(&[vtxo.id()]).await.unwrap();
	assert_eq!(vtxos.len(), 1);
}

#[tokio::test]
async fn mark_server_may_own_descendants_empty_input() {
	let mut ctx = TestContext::new_minimal("postgresd/mark_descendants_empty").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Empty input should succeed
	db.mark_server_may_own_descendants(&[]).await
		.expect("Empty input should succeed");
}

#[tokio::test]
async fn mark_server_may_own_descendants_all_signed() {
	let mut ctx = TestContext::new_minimal("postgresd/mark_descendants_signed").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create signed transactions
	let tx1 = Transaction {
		version: bitcoin::transaction::Version::non_standard(1),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let tx2 = Transaction {
		version: bitcoin::transaction::Version::non_standard(2),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid1 = tx1.compute_txid();
	let txid2 = tx2.compute_txid();

	// Insert both as signed
	db.upsert_virtual_transaction(txid1, Some(&tx1), false, None).await.unwrap();
	db.upsert_virtual_transaction(txid2, Some(&tx2), false, None).await.unwrap();

	// Verify they don't have server_may_own_descendant_since set
	let vtx1 = db.get_virtual_transaction_by_txid(txid1).await.unwrap().unwrap();
	let vtx2 = db.get_virtual_transaction_by_txid(txid2).await.unwrap().unwrap();
	assert!(vtx1.server_may_own_descendant_since.is_none());
	assert!(vtx2.server_may_own_descendant_since.is_none());

	// Mark them as server may own descendants
	db.mark_server_may_own_descendants(&[txid1, txid2]).await
		.expect("Should succeed for signed transactions");

	// Verify server_may_own_descendant_since is now set
	let vtx1 = db.get_virtual_transaction_by_txid(txid1).await.unwrap().unwrap();
	let vtx2 = db.get_virtual_transaction_by_txid(txid2).await.unwrap().unwrap();
	assert!(vtx1.server_may_own_descendant_since.is_some(),
		"server_may_own_descendant_since should be set for tx1");
	assert!(vtx2.server_may_own_descendant_since.is_some(),
		"server_may_own_descendant_since should be set for tx2");
}

#[tokio::test]
async fn mark_server_may_own_descendants_fails_for_unsigned() {
	let mut ctx = TestContext::new_minimal("postgresd/mark_descendants_unsigned").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create one signed and one unsigned transaction
	let tx_signed = Transaction {
		version: bitcoin::transaction::Version::non_standard(1),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let tx_unsigned = Transaction {
		version: bitcoin::transaction::Version::non_standard(2),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid_signed = tx_signed.compute_txid();
	let txid_unsigned = tx_unsigned.compute_txid();

	// Insert one signed and one unsigned
	db.upsert_virtual_transaction(txid_signed, Some(&tx_signed), false, None).await.unwrap();
	db.upsert_virtual_transaction(txid_unsigned, None, false, None).await.unwrap();

	// Should fail because one is unsigned
	let result = db.mark_server_may_own_descendants(&[txid_signed, txid_unsigned]).await;
	assert!(result.is_err(), "Should fail when one transaction is unsigned");
	let err_msg = result.unwrap_err().to_string();
	assert!(err_msg.contains("NULL signed_tx"), "Error should mention NULL signed_tx: {}", err_msg);
	assert!(err_msg.contains(&txid_unsigned.to_string()),
		"Error should mention the unsigned txid: {}", err_msg);

	// Verify neither transaction was updated (atomic failure)
	let vtx_signed = db.get_virtual_transaction_by_txid(txid_signed).await.unwrap().unwrap();
	assert!(vtx_signed.server_may_own_descendant_since.is_none(),
		"signed tx should not be updated when operation fails");
}

#[tokio::test]
async fn mark_server_may_own_descendants_does_not_overwrite() {
	let mut ctx = TestContext::new_minimal("postgresd/mark_descendants_no_overwrite").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(1),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Insert with server_may_own_descendant_since already set
	let original_timestamp = Local::now() - chrono::Duration::days(1);
	db.upsert_virtual_transaction(txid, Some(&tx), false, Some(original_timestamp)).await.unwrap();

	// Verify it's set
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	let original_stored = vtx.server_may_own_descendant_since.unwrap();

	// Call mark_server_may_own_descendants again
	db.mark_server_may_own_descendants(&[txid]).await
		.expect("Should succeed");

	// Verify the timestamp was NOT overwritten
	let vtx = db.get_virtual_transaction_by_txid(txid).await.unwrap().unwrap();
	let after_mark = vtx.server_may_own_descendant_since.unwrap();
	assert_eq!(original_stored, after_mark,
		"server_may_own_descendant_since should not be overwritten");
}

#[tokio::test]
async fn mark_server_may_own_descendants_fails_for_nonexistent() {
	let mut ctx = TestContext::new_minimal("postgresd/mark_descendants_nonexistent").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create txid that doesn't exist in database
	let tx_nonexistent = Transaction {
		version: bitcoin::transaction::Version::non_standard(99),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid_nonexistent = tx_nonexistent.compute_txid();

	// Should fail for non-existent txids
	let result = db.mark_server_may_own_descendants(&[txid_nonexistent]).await;
	assert!(result.is_err(), "Should fail when transaction doesn't exist");
	let err_msg = result.unwrap_err().to_string();
	assert!(err_msg.contains("does not exist"), "Error should mention 'does not exist': {}", err_msg);
	assert!(err_msg.contains(&txid_nonexistent.to_string()),
		"Error should mention the non-existent txid: {}", err_msg);
}
