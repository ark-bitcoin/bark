use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Transaction;
use chrono::Local;

use ark::{ServerVtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::offboard::OffboardForfeitResult;
use ark::integration::{TokenStatus, TokenType};
use ark::lightning::{Invoice, Preimage};
use ark::mailbox::{MailboxIdentifier, MailboxType};
use ark::rounds::RoundId;
use ark::test_util::VTXO_VECTORS;
use ark::vtxo::Full;
use ark::tree::signed::{UnlockHash, UnlockPreimage};

use bitcoin::hashes::Hash as _;
use bark::lightning_invoice::Bolt11Invoice;
use bitcoin_ext::BlockRef;
use cln_rpc::listsendpays_request::ListsendpaysIndex;

use server::database::{BlockTable, Db, MailboxPayload};
use server::database::ln::LightningHtlcSubscriptionStatus;
use server::database::vtxopool::PoolVtxo;
use server::filters;
use server::filters::Filters;
use server::wallet::WalletKind;

use ark_testing::TestContext;
use server::database::rounds::StoredRoundOutput;

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

	db.upsert_vtxos([vtxo1.clone(), vtxo2.clone()]).await.expect("Query succeeded");
	db.get_user_vtxos_by_id(&[vtxo1.id(), vtxo2.id()]).await.expect("Query succeeded");
	db.get_user_vtxos_by_id(&[vtxo3.id()]).await.expect_err("Query Failed because 3 isn't in the db yet");

	// It shouldn't complain if vtxo2 is already present
	db.upsert_vtxos([vtxo2.into(), vtxo3.clone()]).await.expect("Query succeeded");
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
		&stmt, &[&invoice.to_string(), &invoice.payment_hash().to_string()],
	).await.unwrap_err();
	let db_err = err.as_db_error().expect("db error expected").to_string();
	assert!(
		db_err.contains("duplicate key value violates unique constraint"),
		"unexpected error: {}", db_err
	);
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
	assert!(db.get_block_by_height(BlockTable::Captaind, 1).await.unwrap().is_none());
	assert!(db.get_block_by_height(BlockTable::Captaind, 2).await.unwrap().is_none());

	// Initially no tip
	assert!(db.get_highest_block(BlockTable::Captaind).await.unwrap().is_none());

	// Store first block
	db.store_block(BlockTable::Captaind, &block1).await.expect("Store block1");
	{
		let stored = db.get_block_by_height(BlockTable::Captaind, 1).await.unwrap().expect("block1 present");
		assert_eq!(stored.height, block1.height);
		assert_eq!(stored.hash, block1.hash);
		assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap(), Some(block1.clone()));
	}

	// Store second block
	db.store_block(BlockTable::Captaind, &block2).await.expect("Store block2");
	{
		let stored = db.get_block_by_height(BlockTable::Captaind, 2).await.unwrap().expect("block2 present");
		assert_eq!(stored.height, block2.height);
		assert_eq!(stored.hash, block2.hash);
		assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap(), Some(block2.clone()));
	}

	// Try to add a conflicting block at block-height 2
	let hash2_conflict = bitcoin::BlockHash::from_str("11111111111111111111acbe2c55c3b2ee3421fd4b726e2f8ef6e7ef1ecc4777").unwrap();
	let block2_conflict = BlockRef {
		height: 2,
		hash: hash2_conflict,
	};

	let result = db.store_block(BlockTable::Captaind, &block2_conflict).await;
	assert!(result.is_err(), "Storing a conflicting block at the same height should error");

	// Remove blocks above height2 (block2 should still be there)
	db.remove_blocks_above(BlockTable::Captaind, 2).await.expect("Remove above height2");
	assert!(db.get_block_by_height(BlockTable::Captaind, 2).await.unwrap().is_some()); // block2 still there
	assert!(db.get_block_by_height(BlockTable::Captaind, 1).await.unwrap().is_some()); // block1 still there
	assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap(), Some(block2.clone())); // Tip should be at block2

	// Remove blocks above height1 (block1 should still be there)
	db.remove_blocks_above(BlockTable::Captaind, 1).await.expect("Remove above height1");
	assert!(db.get_block_by_height(BlockTable::Captaind, 1).await.unwrap().is_some()); // block1 still there
	assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap(), Some(block1.clone())); // Tip should be at block1
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
	db.upsert_vtxos([vtxo.clone()]).await.expect("Failed to upsert vtxo");

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
		std::iter::empty::<(VtxoId, bitcoin::Txid)>(),
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
		std::iter::empty::<ServerVtxo<Full>>(),
		std::iter::empty::<(VtxoId, bitcoin::Txid)>(),
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
		std::iter::empty::<ServerVtxo<Full>>(),
		std::iter::empty::<(VtxoId, bitcoin::Txid)>(),
	).await.expect("Only virtual_txs should succeed");

	// Verify it was inserted
	let retrieved = db.get_virtual_transaction_by_txid(txid).await.unwrap();
	assert!(retrieved.is_some());

	// Test 3: Only vtxos populated
	let vtxo = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	db.update_virtual_transaction_tree(
		std::iter::empty::<VirtualTransaction>(),
		[vtxo.clone()],
		std::iter::empty::<(VtxoId, bitcoin::Txid)>(),
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

#[tokio::test]
async fn block_table_independence() {
	let mut ctx = TestContext::new_minimal("postgresd/block_table_independence").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Create test blocks with different hashes at the same height
	let hash_captaind = bitcoin::BlockHash::from_str("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
	let hash_watchmand = bitcoin::BlockHash::from_str("0000000000000000000065bda8f8a88f2e1e00d9a6887a43d640e52a4c3b3a81").unwrap();

	let captaind_block_100 = BlockRef { height: 100, hash: hash_captaind };
	let watchmand_block_100 = BlockRef { height: 100, hash: hash_watchmand };

	// Initially both tables are empty
	assert!(db.get_highest_block(BlockTable::Captaind).await.unwrap().is_none());
	assert!(db.get_highest_block(BlockTable::Watchmand).await.unwrap().is_none());

	// Insert block 100 into captaind table
	db.store_block(BlockTable::Captaind, &captaind_block_100).await.expect("Store to captaind");

	// Verify isolation: captaind has it, watchmand doesn't
	assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap(), Some(captaind_block_100));
	assert_eq!(db.get_block_by_height(BlockTable::Captaind, 100).await.unwrap(), Some(captaind_block_100));
	assert_eq!(db.get_highest_block(BlockTable::Watchmand).await.unwrap(), None);
	assert_eq!(db.get_block_by_height(BlockTable::Watchmand, 100).await.unwrap(), None);

	// Insert block 100 into watchmand table (different hash!)
	db.store_block(BlockTable::Watchmand, &watchmand_block_100).await.expect("Store to watchmand");

	// Verify both tables have independent data at the same height
	let captaind_retrieved = db.get_block_by_height(BlockTable::Captaind, 100).await.unwrap().unwrap();
	let watchmand_retrieved = db.get_block_by_height(BlockTable::Watchmand, 100).await.unwrap().unwrap();

	assert_eq!(captaind_retrieved.hash, hash_captaind);
	assert_eq!(watchmand_retrieved.hash, hash_watchmand);
	assert_ne!(captaind_retrieved.hash, watchmand_retrieved.hash, "Tables should have different hashes at same height");

	// Add more blocks to test independent highest block tracking
	let captaind_block_101 = BlockRef { height: 101, hash: hash_captaind };
	let watchmand_block_102 = BlockRef { height: 102, hash: hash_watchmand };

	db.store_block(BlockTable::Captaind, &captaind_block_101).await.unwrap();
	db.store_block(BlockTable::Watchmand, &watchmand_block_102).await.unwrap();

	assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap().unwrap().height, 101);
	assert_eq!(db.get_highest_block(BlockTable::Watchmand).await.unwrap().unwrap().height, 102);

	// Test independent removal
	db.remove_blocks_above(BlockTable::Captaind, 100).await.unwrap();

	// Captaind should only have block 100 now
	assert_eq!(db.get_highest_block(BlockTable::Captaind).await.unwrap().unwrap().height, 100);
	assert_eq!(db.get_block_by_height(BlockTable::Captaind, 101).await.unwrap(), None);

	// Watchmand should still have both blocks
	assert_eq!(db.get_highest_block(BlockTable::Watchmand).await.unwrap().unwrap().height, 102);
	assert!(db.get_block_by_height(BlockTable::Watchmand, 100).await.unwrap().is_some());
	assert!(db.get_block_by_height(BlockTable::Watchmand, 102).await.unwrap().is_some());

	// Test independent lowest block tracking
	assert_eq!(db.get_lowest_block(BlockTable::Captaind).await.unwrap().unwrap().height, 100);
	assert_eq!(db.get_lowest_block(BlockTable::Watchmand).await.unwrap().unwrap().height, 100);
}

#[tokio::test]
async fn ban_vtxo() {
	let mut ctx = TestContext::new_minimal("postgresd/ban_vtxo").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Insert a vtxo
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let vtxo_id = vtxo.id();
	db.upsert_vtxos(&[vtxo]).await.expect("upsert succeeded");

	// Initially no vtxos are banned
	let banned = db.list_banned_vtxos(100).await.expect("list succeeded");
	assert!(banned.is_empty(), "no vtxos should be banned initially");

	// The vtxo should not have a ban set
	let state = db.get_user_vtxos_by_id(&[vtxo_id]).await.expect("get succeeded")
		.into_iter().next().expect("vtxo found");
	assert!(state.banned_until_height.is_none());
	assert!(state.is_spendable(100));

	// Ban the vtxo until block 200
	db.ban_vtxo(vtxo_id, 200).await.expect("ban succeeded");

	// The vtxo should now be banned
	let state = db.get_user_vtxos_by_id(&[vtxo_id]).await.expect("get succeeded")
		.into_iter().next().expect("vtxo found");
	assert_eq!(state.banned_until_height, Some(200));
	assert!(!state.is_spendable(100)); // tip 100 < ban 200
	assert!(state.is_spendable(200)); // tip 200 >= ban 200

	// Should appear in the banned list
	let banned = db.list_banned_vtxos(100).await.expect("list succeeded");
	assert_eq!(banned.len(), 1);
	assert_eq!(banned[0].vtxo_id, vtxo_id);
	assert_eq!(banned[0].banned_until_height, Some(200));

	// Unban the vtxo
	db.unban_vtxo(vtxo_id).await.expect("unban succeeded");

	// The vtxo should no longer be banned
	let state = db.get_user_vtxos_by_id(&[vtxo_id]).await.expect("get succeeded")
		.into_iter().next().expect("vtxo found");
	assert!(state.banned_until_height.is_none());
	assert!(state.is_spendable(100));

	// Banned list should be empty again
	let banned = db.list_banned_vtxos(100).await.expect("list succeeded");
	assert!(banned.is_empty());
}

#[tokio::test]
async fn pending_sweeps() {
	let mut ctx = TestContext::new_minimal("postgresd/pending_sweeps").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Initially empty
	let sweeps = db.fetch_pending_sweeps().await.unwrap();
	assert!(sweeps.is_empty(), "should start with no pending sweeps");

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

	// Store two sweeps
	db.store_pending_sweep(&txid1, &tx1).await.unwrap();
	db.store_pending_sweep(&txid2, &tx2).await.unwrap();

	// Inserting the same txid twice must fail due to the unique index on sweep.txid
	let err = db.store_pending_sweep(&txid1, &tx1).await.unwrap_err();
	let err_chain = format!("{:#}", err);
	assert!(
		err_chain.contains("duplicate key value violates unique constraint"),
		"expected unique constraint violation, got: {}", err_chain,
	);

	let sweeps = db.fetch_pending_sweeps().await.unwrap();
	assert_eq!(sweeps.len(), 2, "both sweeps should be pending");

	// Confirm one
	db.confirm_pending_sweep(&txid1).await.unwrap();
	let sweeps = db.fetch_pending_sweeps().await.unwrap();
	assert_eq!(sweeps.len(), 1, "one sweep confirmed, one still pending");
	assert!(!sweeps.contains_key(&txid1), "confirmed sweep should not appear");
	assert!(sweeps.contains_key(&txid2), "unconfirmed sweep should appear");

	// Abandon the remaining one
	db.abandon_pending_sweep(&txid2).await.unwrap();
	let sweeps = db.fetch_pending_sweeps().await.unwrap();
	assert!(sweeps.is_empty(), "all sweeps resolved");
}

fn dummy_tx(num: u32) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::from_height(num).unwrap(),
		input: vec![],
		output: vec![],
	}
}

#[tokio::test]
async fn postgres_offboards() {
	let mut ctx = TestContext::new_minimal("postgresd/offboards").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	// Register the vtxo's transactions in the virtual transaction tree
	for tx_item in vtxo.transactions() {
		db.upsert_virtual_transaction(tx_item.tx.compute_txid(), Some(&tx_item.tx), false, None)
			.await
			.unwrap();
	}

	// Initially no uncommitted offboards
	let uncommitted = db.get_uncommitted_offboards().await.unwrap();
	assert!(uncommitted.is_empty());

	let offboard_tx = dummy_tx(1);
	let offboard_txid = offboard_tx.compute_txid();

	// Register the offboard
	let forfeit_result = OffboardForfeitResult {
		forfeit_txs: vec![dummy_tx(2)],
		forfeit_vtxos: vec![],
		connector_tx: None,
		connector_vtxos: vec![],
	};
	db.register_offboard(&[&vtxo], &offboard_tx, &forfeit_result).await.unwrap();

	let uncommitted = db.get_uncommitted_offboards().await.unwrap();
	assert_eq!(uncommitted.len(), 1, "one uncommitted offboard");
	assert_eq!(uncommitted[0].txid, offboard_txid);

	// Mark the vtxo is spent (offboarded_in set), trying to offboard again should fail
	let offboard_tx2 = dummy_tx(3);
	let forfeit_result2 = OffboardForfeitResult {
		forfeit_txs: vec![dummy_tx(4)],
		forfeit_vtxos: vec![],
		connector_tx: None,
		connector_vtxos: vec![],
	};
	let result = db.register_offboard(&[&vtxo], &offboard_tx2, &forfeit_result2).await;
	assert!(result.is_err(), "double-offboard should fail");

	// Commit the offboard
	db.mark_offboard_committed(offboard_txid).await.unwrap();

	let uncommitted = db.get_uncommitted_offboards().await.unwrap();
	assert!(uncommitted.is_empty(), "no uncommitted offboards after commit");
}

#[tokio::test]
async fn bitcoin_transaction_index() {
	let mut ctx = TestContext::new_minimal("postgresd/bitcoin_tx_index").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(42),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let txid = tx.compute_txid();

	// Not found initially
	assert!(db.get_bitcoin_transaction_by_id(txid).await.unwrap().is_none());

	// Upsert the transaction
	db.upsert_bitcoin_transaction(txid, &tx).await.unwrap();

	// Now found
	let stored = db.get_bitcoin_transaction_by_id(txid).await.unwrap().unwrap();
	assert_eq!(stored.compute_txid(), txid);

	// Upsert same txid again (idempotent)
	db.upsert_bitcoin_transaction(txid, &tx).await.unwrap();
	let stored2 = db.get_bitcoin_transaction_by_id(txid).await.unwrap().unwrap();
	assert_eq!(stored2.compute_txid(), txid);
}

#[tokio::test]
async fn ephemeral_tweaks() {
	let mut ctx = TestContext::new_minimal("postgresd/ephemeral_tweaks").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let pubkey = PublicKey::from_str(
		"038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"
	).unwrap();
	let tweak_bytes = [1u8; 32];
	let tweak = bitcoin::secp256k1::Scalar::from_be_bytes(tweak_bytes).unwrap();

	// Not found initially
	assert!(db.fetch_ephemeral_tweak(pubkey).await.unwrap().is_none());

	// Store tweak with long lifetime
	db.store_ephemeral_tweak(pubkey, tweak, std::time::Duration::from_secs(3600)).await.unwrap();

	// Now found
	let fetched = db.fetch_ephemeral_tweak(pubkey).await.unwrap().unwrap();
	assert_eq!(fetched.to_be_bytes(), tweak_bytes);

	// Drop it
	let dropped = db.drop_ephemeral_tweak(pubkey).await.unwrap().unwrap();
	assert_eq!(dropped.to_be_bytes(), tweak_bytes);

	// Gone after drop
	assert!(db.fetch_ephemeral_tweak(pubkey).await.unwrap().is_none());

	// clean_expired removes nothing when table is empty
	db.clean_expired_ephemeral_tweaks().await.unwrap();
}

#[tokio::test]
async fn vtxo_mailbox() {
	let mut ctx = TestContext::new_minimal("postgresd/vtxo_mailbox").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let mailbox_id = MailboxIdentifier::from_str(
		"038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"
	).unwrap();

	// Upsert the vtxo first (vtxo_mailbox has a FK on vtxo)
	let vtxo1 = VTXO_VECTORS.board_vtxo.clone();
	let vtxo2 = VTXO_VECTORS.round1_vtxo.clone();
	db.upsert_vtxos(&[
		ServerVtxo::from(vtxo1.clone()),
		ServerVtxo::from(vtxo2.clone()),
	]).await.unwrap();

	// Empty mailbox returns nothing
	let result = db.get_mailbox_entries(mailbox_id.clone(), 0, 10).await.unwrap();
	assert!(result.is_empty());

	// Store vtxo1 in mailbox (gets checkpoint 1)
	let cp1 = db.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox_id.clone(), &[vtxo1.clone()]).await.unwrap()
		.expect("should return a checkpoint");

	// Fetch from checkpoint 0 – should return vtxo1
	let batches = db.get_mailbox_entries(mailbox_id.clone(), 0, 10).await.unwrap();
	assert_eq!(batches.len(), 1);
	assert_eq!(batches[0].checkpoint, cp1);
	let vtxos = match &batches[0].payload {
		MailboxPayload::Arkoor { vtxos } => vtxos,
		other => panic!("expected Arkoor payload, got {:?}", other),
	};
	assert_eq!(vtxos.len(), 1);
	assert_eq!(vtxos[0].id(), vtxo1.id());

	// Store vtxo2 in mailbox (gets checkpoint 2, ≥ cp1)
	let cp2 = db.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox_id.clone(), &[vtxo2.clone()]).await.unwrap()
		.expect("should return a checkpoint");
	assert!(cp2 > cp1, "checkpoints should be monotonically increasing");

	// Fetch from checkpoint cp1 – should only return vtxo2 (beyond cp1)
	let batches = db.get_mailbox_entries(mailbox_id.clone(), cp1, 10).await.unwrap();
	assert_eq!(batches.len(), 1);
	assert_eq!(batches[0].checkpoint, cp2);
	let vtxos2 = match &batches[0].payload {
		MailboxPayload::Arkoor { vtxos } => vtxos,
		other => panic!("expected Arkoor payload, got {:?}", other),
	};
	assert_eq!(vtxos2[0].id(), vtxo2.id());
}

#[tokio::test]
async fn store_vtxos_in_mailbox_empty() {
	let mut ctx = TestContext::new_minimal("postgresd/vtxo_mailbox_empty").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let mailbox_id = MailboxIdentifier::from_str(
		"038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"
	).unwrap();

	// Storing an empty slice returns None (no checkpoint allocated)
	let result = db.store_vtxos_in_mailbox(MailboxType::ArkoorReceive, mailbox_id, &[]).await.unwrap();
	assert!(result.is_none(), "empty vtxo list should return None");
}

#[tokio::test]
async fn vtxo_pool() {
	use futures::TryStreamExt;

	let mut ctx = TestContext::new_minimal("postgresd/vtxo_pool").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo1 = PoolVtxo::new(VTXO_VECTORS.board_vtxo.clone());
	let vtxo2 = PoolVtxo::new(VTXO_VECTORS.round1_vtxo.clone());

	// vtxo_pool has a FK on vtxo_id → insert into vtxo table first
	db.upsert_vtxos(&[
		ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone()),
		ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone()),
	]).await.unwrap();

	// Load from empty pool
	let pool: Vec<_> = db.load_vtxopool().await.unwrap().try_collect().await.unwrap();
	assert!(pool.is_empty());

	// Store vtxo1 individually, vtxo2 in bulk
	db.store_vtxopool_vtxo(&vtxo1).await.unwrap();
	db.store_vtxopool_vtxos(&[vtxo2.clone()]).await.unwrap();

	// Get by ids
	let got = db.get_pool_vtxos_by_ids(&[vtxo1.id(), vtxo2.id()]).await.unwrap();
	assert_eq!(got.len(), 2);

	// Load pool: 2 unspent vtxos
	let pool: Vec<_> = db.load_vtxopool().await.unwrap().try_collect().await.unwrap();
	assert_eq!(pool.len(), 2);

	// Mark vtxo1 as spent
	db.mark_vtxopool_vtxos_spent([vtxo1.id()]).await.unwrap();

	// Load pool: only vtxo2 remains unspent
	let pool: Vec<_> = db.load_vtxopool().await.unwrap().try_collect().await.unwrap();
	assert_eq!(pool.len(), 1);
	assert_eq!(pool[0].id(), vtxo2.id());
}

#[tokio::test]
async fn watchman_frontier() {
	let mut ctx = TestContext::new_minimal("postgresd/watchman_frontier").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// First, store the vtxo object itself (watchman_vtxo_frontier JOINs vtxo)
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	// Also store the funding virtual transaction that watchman queries for
	let funding_txid = vtxo.point().txid;
	db.upsert_virtual_transaction(funding_txid, None, true, None).await.unwrap();

	// Frontier starts empty
	let frontier = db.get_frontier().await.unwrap();
	assert!(frontier.is_empty());

	// Add vtxo to frontier
	db.add_vtxo_to_frontier(vtxo.id()).await.unwrap();

	// Frontier has one unconfirmed entry
	let frontier = db.get_frontier().await.unwrap();
	assert_eq!(frontier.len(), 1);
	let (confirmed_height, _) = frontier[&vtxo.id()];
	assert!(confirmed_height.is_none(), "not yet confirmed");

	// get_unfrontiered_funding_txids returns empty (vtxo is now frontiered)
	let unfrontiered = db.get_unfrontiered_funding_txids().await.unwrap();
	assert!(unfrontiered.is_empty(), "all vtxos should be frontiered now");

	// Register confirmation at height 100
	db.register_vtxo_confirmation(vtxo.id(), 100).await.unwrap();

	let frontier = db.get_frontier().await.unwrap();
	let (confirmed_height, _) = frontier[&vtxo.id()];
	assert_eq!(confirmed_height, Some(100));

	// Register a spend at height 101
	let spend_tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(77),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let spend_txid = spend_tx.compute_txid();
	db.register_vtxo_spend(vtxo.id(), 101, spend_txid).await.unwrap();

	// Spent vtxos do not appear in frontier
	let frontier = db.get_frontier().await.unwrap();
	assert!(frontier.is_empty(), "spent vtxo should not appear in frontier");
}

#[tokio::test]
async fn watchman_reorg() {
	let mut ctx = TestContext::new_minimal("postgresd/watchman_reorg").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();
	db.add_vtxo_to_frontier(vtxo.id()).await.unwrap();
	db.register_vtxo_confirmation(vtxo.id(), 100).await.unwrap();

	// Verify confirmed
	let frontier = db.get_frontier().await.unwrap();
	assert_eq!(frontier[&vtxo.id()].0, Some(100));

	// Reorg at height 99 – confirmation at 100 should be cleared
	db.reorg_frontier(99).await.unwrap();

	let frontier = db.get_frontier().await.unwrap();
	assert!(frontier[&vtxo.id()].0.is_none(), "confirmation cleared after reorg");
}

#[tokio::test]
async fn watchman_get_vtxos_by_txid() {
	let mut ctx = TestContext::new_minimal("postgresd/watchman_vtxos_by_txid").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	let vtxo_txid = vtxo.point().txid;
	let vtxos = db.get_vtxos_by_txid(vtxo_txid).await.unwrap();
	assert_eq!(vtxos.len(), 1);
	assert_eq!(vtxos[0].id(), vtxo.id());

	// Non-existent txid returns empty
	let other_tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(99),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let other_txid = other_tx.compute_txid();
	let vtxos = db.get_vtxos_by_txid(other_txid).await.unwrap();
	assert!(vtxos.is_empty());
}

#[tokio::test]
async fn watchman_unfrontiered_funding_txids() {
	let mut ctx = TestContext::new_minimal("postgresd/watchman_unfrontiered").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// No vtxos → no unfrontiered txids
	let unfrontiered = db.get_unfrontiered_funding_txids().await.unwrap();
	assert!(unfrontiered.is_empty());

	// Insert vtxo + its funding virtual_transaction (is_funding = true)
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();
	let funding_txid = vtxo.point().txid;
	db.upsert_virtual_transaction(funding_txid, None, true, None).await.unwrap();

	// Now funding_txid is unfrontiered
	let unfrontiered = db.get_unfrontiered_funding_txids().await.unwrap();
	assert!(unfrontiered.contains(&funding_txid));

	// After adding to frontier it disappears from unfrontiered
	db.add_vtxo_to_frontier(vtxo.id()).await.unwrap();
	let unfrontiered = db.get_unfrontiered_funding_txids().await.unwrap();
	assert!(unfrontiered.is_empty());
}

#[tokio::test]
async fn oor_mark_package_spent() {
	let mut ctx = TestContext::new_minimal("postgresd/oor_mark_spent").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	// Verify vtxo is spendable
	let state = db.get_server_vtxo_by_id(vtxo.id()).await.unwrap();
	assert!(state.is_spendable(0));

	// Mark it as spent via OOR
	let spend_tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(55),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let spend_txid = spend_tx.compute_txid();

	// Use a transaction to call the query::mark_package_spent helper
	let mut conn = db.get_conn().await.unwrap();
	let pg_tx = conn.transaction().await.unwrap();
	server::database::oor::mark_package_spent(&pg_tx, &[vtxo.id()], &[spend_txid])
		.await.unwrap();
	pg_tx.commit().await.unwrap();

	// Check it is now marked as spent
	let state = db.get_server_vtxo_by_id(vtxo.id()).await.unwrap();
	assert_eq!(state.oor_spent_txid, Some(spend_txid));
	assert!(!state.is_spendable(0));
}

#[tokio::test]
async fn oor_mark_package_spent_idempotent() {
	let mut ctx = TestContext::new_minimal("postgresd/oor_mark_spent_idem").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	let spend_tx = Transaction {
		version: bitcoin::transaction::Version::non_standard(56),
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	};
	let spend_txid = spend_tx.compute_txid();

	let mut conn = db.get_conn().await.unwrap();
	let pg_tx = conn.transaction().await.unwrap();
	server::database::oor::mark_package_spent(&pg_tx, &[vtxo.id()], &[spend_txid])
		.await.unwrap();
	pg_tx.commit().await.unwrap();

	// Calling again with the same txid should be idempotent (no error)
	let mut conn = db.get_conn().await.unwrap();
	let pg_tx = conn.transaction().await.unwrap();
	server::database::oor::mark_package_spent(&pg_tx, &[vtxo.id()], &[spend_txid])
		.await.unwrap();
	pg_tx.commit().await.unwrap();
}

#[tokio::test]
async fn round_queries_empty() {
	let mut ctx = TestContext::new_minimal("postgresd/round_queries_empty").await;
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
	let round_id = RoundId::from(txid);

	// No rounds yet
	assert!(!db.is_round_tx(txid).await.unwrap(), "no rounds yet");
	assert!(db.get_round(round_id).await.unwrap().is_none());
	assert!(db.get_last_round_id().await.unwrap().is_none());
	assert!(db.get_expired_round_ids(u32::MAX).await.unwrap().is_empty());
}

#[tokio::test]
async fn round_participation() {
	let mut ctx = TestContext::new_minimal("postgresd/round_participation").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Insert a vtxo to use as an input
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	let unlock_preimage: UnlockPreimage = [1u8; 32];

	let output = StoredRoundOutput {
		vtxo_request: VtxoRequest {
			policy: VtxoPolicy::new_pubkey(VTXO_VECTORS.board_vtxo.user_pubkey()),
			amount: bitcoin::Amount::from_sat(1000),
		},
		unblinded_mailbox_id: None,
	};

	// No participations yet
	let pending = db.get_all_pending_round_participations().await.unwrap();
	assert!(pending.is_empty());

	// Store a participation
	db.try_store_round_participation(0, unlock_preimage, &[vtxo.id()], std::iter::once(&output))
		.await.unwrap();

	// One pending participation
	let pending = db.get_all_pending_round_participations().await.unwrap();
	assert_eq!(pending.len(), 1);

	let unlock_hash = UnlockHash::hash(&unlock_preimage);
	let part = db.get_round_participation_by_unlock_hash(unlock_hash).await.unwrap()
		.expect("participation should exist");
	assert_eq!(part.inputs.len(), 1);
	assert_eq!(part.inputs[0].vtxo_id, vtxo.id());
	assert_eq!(part.outputs.len(), 1);

	// Remove it
	let removed = db.remove_round_participation(unlock_hash).await.unwrap();
	assert!(removed, "should have removed one participation");

	let pending = db.get_all_pending_round_participations().await.unwrap();
	assert!(pending.is_empty(), "participation removed");

	// Removing again returns false
	let removed_again = db.remove_round_participation(unlock_hash).await.unwrap();
	assert!(!removed_again, "nothing to remove the second time");
}

#[tokio::test]
async fn round_participation_same_vtxo_multiple_pending() {
	let mut ctx = TestContext::new_minimal("postgresd/round_part_double_spend").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	let preimage1: UnlockPreimage = [1u8; 32];
	let preimage2: UnlockPreimage = [2u8; 32];

	let output = StoredRoundOutput {
		vtxo_request: VtxoRequest {
			policy: VtxoPolicy::new_pubkey(VTXO_VECTORS.board_vtxo.user_pubkey()),
			amount: bitcoin::Amount::from_sat(1000),
		},
		unblinded_mailbox_id: None,
	};

	// First participation succeeds
	db.try_store_round_participation(0, preimage1, &[vtxo.id()], std::iter::once(&output)).await.unwrap();

	// Second participation with same vtxo as input is allowed at the DB level;
	// deduplication happens when a round is finalized (no unique constraint on vtxo_id).
	db.try_store_round_participation(0, preimage2, &[vtxo.id()], std::iter::once(&output)).await.unwrap();

	// Both are stored as pending participations
	let pending = db.get_all_pending_round_participations().await.unwrap();
	assert_eq!(pending.len(), 2, "both participations are pending");
}

const DUMMY_PUBKEY: &str = "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354";
const BOLT11_INVOICE: &str = "lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8";

#[tokio::test]
async fn lightning_payment_attempt_lifecycle() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/lightning_payment_attempt").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.register_lightning_node(&pubkey).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();
	let invoice = Invoice::Bolt11(bolt11.clone());

	// No open attempts yet
	let attempts = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert!(attempts.is_empty());

	assert!(db.get_open_lightning_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await.unwrap().is_none());

	// Start a payment
	db.store_lightning_payment_start(node_id, &invoice, 2000).await.unwrap();

	// One open attempt
	let attempts = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert_eq!(attempts.len(), 1);
	assert_eq!(attempts[0].amount_msat, 2000);

	let attempt = db.get_open_lightning_payment_attempt_by_payment_hash(
		(&bolt11).into()
	).await.unwrap().expect("should find attempt");

	// Verify invoice retrieval
	let li = db.get_lightning_invoice_by_id(attempt.lightning_invoice_id).await.unwrap();
	assert_eq!(li.payment_hash.to_vec(), bolt11.payment_hash().to_byte_array().to_vec());
	assert_eq!(li.final_amount_msat, None);

	let li2 = db.get_lightning_invoice_by_payment_hash(
		(&bolt11).into()
	).await.unwrap().expect("should find invoice");
	assert_eq!(li.id, li2.id);

	// Update attempt status to Submitted
	db.update_lightning_payment_attempt_status(&attempt, LightningPaymentStatus::Submitted, None).await.unwrap();

	// Update attempt status to Succeeded with an error message (tests the error branch)
	let refreshed = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert_eq!(refreshed.len(), 1); // Submitted is still "open"

	db.update_lightning_payment_attempt_status(&refreshed[0], LightningPaymentStatus::Succeeded, None).await.unwrap();

	// Succeeded attempt is no longer "open"
	let open = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert!(open.is_empty(), "succeeded attempt is closed");
}

#[tokio::test]
async fn lightning_payment_attempt_with_error() {
	use server::database::ln::LightningPaymentStatus;

	let mut ctx = TestContext::new_minimal("postgresd/lightning_payment_error").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.register_lightning_node(&pubkey).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();
	let invoice = Invoice::Bolt11(bolt11);

	db.store_lightning_payment_start(node_id, &invoice, 1000).await.unwrap();

	let attempts = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert_eq!(attempts.len(), 1);

	// Fail with an error message
	db.update_lightning_payment_attempt_status(
		&attempts[0],
		LightningPaymentStatus::Failed,
		Some("route not found"),
	).await.unwrap();

	// No more open attempts
	let open = db.get_open_lightning_payment_attempts(node_id).await.unwrap();
	assert!(open.is_empty());
}

#[tokio::test]
async fn lightning_invoice_update() {
	let mut ctx = TestContext::new_minimal("postgresd/lightning_invoice_update").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.register_lightning_node(&pubkey).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();
	let invoice = Invoice::Bolt11(bolt11.clone());

	db.store_lightning_payment_start(node_id, &invoice, 1500).await.unwrap();

	let li = db.get_lightning_invoice_by_payment_hash(
		(&bolt11).into()
	).await.unwrap().expect("invoice present");
	assert!(li.final_amount_msat.is_none());
	assert!(li.preimage.is_none());

	let preimage = Preimage::random();
	let updated_at = db.update_lightning_invoice(li, Some(9999), Some(preimage)).await.unwrap();
	assert!(updated_at.is_some(), "update should return new updated_at");

	// Verify changes persisted
	let li2 = db.get_lightning_invoice_by_payment_hash(
		(&bolt11).into()
	).await.unwrap().expect("invoice still present");
	assert_eq!(li2.final_amount_msat, Some(9999));
	assert!(li2.preimage.is_some());
}

#[tokio::test]
async fn lightning_generated_invoice_and_htlc_subscription() {
	let mut ctx = TestContext::new_minimal("postgresd/lightning_generated_invoice").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let pubkey = PublicKey::from_str(DUMMY_PUBKEY).unwrap();
	let (node_id, _) = db.register_lightning_node(&pubkey).await.unwrap();

	let bolt11 = Bolt11Invoice::from_str(BOLT11_INVOICE).unwrap();

	// Store as generated (receive-side) invoice
	db.store_generated_lightning_invoice(node_id, &bolt11, 3000).await.unwrap();

	// Find the htlc subscription (should be in Created state)
	let payment_hash: ark::lightning::PaymentHash = (&bolt11).into();
	let subs = db.get_htlc_subscriptions_by_payment_hash(payment_hash).await.unwrap();
	assert_eq!(subs.len(), 1);
	assert_eq!(subs[0].status, LightningHtlcSubscriptionStatus::Created);

	let sub_id = subs[0].id;

	// Update status to Accepted
	db.store_lightning_htlc_subscription_status(
		sub_id, LightningHtlcSubscriptionStatus::Accepted, Some(200),
	).await.unwrap();

	let latest = db.get_htlc_subscription_by_payment_hash(payment_hash).await.unwrap().unwrap();
	assert_eq!(latest.status, LightningHtlcSubscriptionStatus::Accepted);
	assert!(latest.accepted_at.is_some());

	// Calling Accepted again should NOT change accepted_at (idempotency)
	db.store_lightning_htlc_subscription_status(
		sub_id, LightningHtlcSubscriptionStatus::Accepted, None,
	).await.unwrap();
	let latest2 = db.get_htlc_subscription_by_payment_hash(payment_hash).await.unwrap().unwrap();
	assert_eq!(latest.accepted_at, latest2.accepted_at, "accepted_at must not change on duplicate");

	// Insert a vtxo and attach it to the subscription (htlcs-ready transition)
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.upsert_vtxos(&[vtxo.clone()]).await.unwrap();

	db.update_lightning_htlc_subscription_with_htlcs(sub_id, [vtxo.id()]).await.unwrap();

	let latest3 = db.get_htlc_subscription_by_payment_hash(payment_hash).await.unwrap().unwrap();
	assert_eq!(latest3.status, LightningHtlcSubscriptionStatus::HtlcsReady);

	// get_open_lightning_htlc_subscriptions should return this subscription
	// (HtlcsReady is not Settled/Canceled)
	let open = db.get_open_lightning_htlc_subscriptions(node_id).await.unwrap();
	assert_eq!(open.len(), 1);

	// get_htlc_subscription_by_id
	let by_id = db.get_htlc_subscription_by_id(sub_id).await.unwrap().unwrap();
	assert_eq!(by_id.id, sub_id);
}

#[tokio::test]
async fn get_integration_token_config() {
	let mut ctx = TestContext::new_minimal("postgresd/get_integ_token_cfg").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	let integration = db.store_integration("test_integration").await.unwrap();

	// Not found before storing
	let cfg = db.get_integration_token_config(TokenType::SingleUseBoard, integration.id).await.unwrap();
	assert!(cfg.is_none(), "not yet created");

	db.store_integration_token_config(
		TokenType::SingleUseBoard,
		5,
		3600,
		integration.id,
	).await.unwrap();

	let cfg = db.get_integration_token_config(TokenType::SingleUseBoard, integration.id)
		.await.unwrap().expect("config should exist");
	assert_eq!(cfg.maximum_open_tokens, 5);
	assert_eq!(cfg.active_seconds, 3600);
	assert_eq!(cfg.integration_id, integration.id);
}

#[tokio::test]
async fn wallet_changeset() {
	let mut ctx = TestContext::new_minimal("postgresd/wallet_changeset").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Empty aggregate changeset
	let cs = db.read_aggregate_changeset(WalletKind::Rounds).await.unwrap();
	assert!(cs.is_none(), "no changesets stored yet");

	// Build a minimal ChangeSet
	let cs1 = bdk_wallet::ChangeSet {
		network: Some(bitcoin::Network::Regtest),
		..Default::default()
	};

	db.store_changeset(WalletKind::Rounds, &cs1).await.unwrap();

	let agg = db.read_aggregate_changeset(WalletKind::Rounds).await.unwrap()
		.expect("should have one changeset");
	assert_eq!(agg.network, Some(bitcoin::Network::Regtest));

	// Watchman wallet is independent
	let cs_watchman = db.read_aggregate_changeset(WalletKind::Watchman).await.unwrap();
	assert!(cs_watchman.is_none(), "watchman has no changesets");
}
