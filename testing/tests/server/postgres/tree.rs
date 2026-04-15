use bitcoin::Txid;
use bitcoin::hashes::Hash;

use ark::ServerVtxo;
use ark::test_util::VTXO_VECTORS;

use server::database::Db;
use server::database::tree::VtxoTreeUpdate;

use ark_testing::TestContext;

/// Helper: create a db for a test.
async fn test_db(name: &str) -> (TestContext, Db) {
	let mut ctx = TestContext::new_minimal(&format!("postgresd/tree/{}", name)).await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");
	(ctx, db)
}

/// Helper: dummy txid (different from any vtxo-related txid).
fn dummy_txid(byte: u8) -> Txid {
	Txid::from_byte_array([byte; 32])
}

/// Helper: insert a dummy round row and return its id.
/// Required because spent_in_round has a foreign key to round.id.
async fn insert_dummy_round(db: &Db, seq: i64) -> i64 {
	let funding_txid = dummy_txid(seq as u8);
	let conn = db.get_conn().await.expect("connection");
	let row = conn.query_one(
		"INSERT INTO round (seq, funding_txid, funding_tx, signed_tree, expiry, created_at)
		VALUES ($1, $2, '\\x00', '\\x00', 1000, NOW())
		RETURNING id",
		&[&seq, &funding_txid.to_string()],
	).await.expect("insert dummy round");
	row.get::<_, i64>("id")
}

#[tokio::test]
async fn insert_spendable_vtxos() {
	let (_ctx, db) = test_db("insert_spendable_vtxos").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert succeeded");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.vtxo_id, vtxo.id());
}

#[tokio::test]
async fn insert_spendable_is_idempotent() {
	let (_ctx, db) = test_db("insert_spendable_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("first insert");

	// Second insert with same vtxo should succeed (ON CONFLICT DO NOTHING)
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("idempotent insert");
}

#[tokio::test]
async fn insert_oor_spent_vtxos() {
	let (_ctx, db) = test_db("insert_oor_spent_vtxos").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("insert succeeded");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn insert_oor_spent_is_idempotent() {
	let (_ctx, db) = test_db("insert_oor_spent_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("first insert");

	// Re-inserting the same vtxo with the same spending txid is a no-op.
	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("idempotent insert");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn insert_oor_spent_double_spend_fails() {
	let (_ctx, db) = test_db("insert_oor_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), dummy_txid(0x01))]);
	db.execute_vtxo_tree_update(update).await.expect("first insert");

	// A second oor-spent insert for the same vtxo with a different txid
	// would silently authorize a double-spend under ON CONFLICT DO NOTHING.
	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), dummy_txid(0x02))]);
	let err = db.execute_vtxo_tree_update(update).await.unwrap_err();
	assert!(err.to_string().contains("already spent"), "got: {}", err);
}

#[tokio::test]
async fn mark_oor_spent() {
	let (_ctx, db) = test_db("mark_oor_spent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xbb);

	// First insert as spendable
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	// Then mark as oor spent
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("mark oor spent");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn mark_oor_spent_is_idempotent() {
	let (_ctx, db) = test_db("mark_oor_spent_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xcc);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("first mark");

	// Same mark again should succeed
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("idempotent mark");
}

#[tokio::test]
async fn mark_oor_spent_double_spend_fails() {
	let (_ctx, db) = test_db("mark_oor_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0x01))]);
	db.execute_vtxo_tree_update(update).await.expect("first spend");

	// Try to spend with a different txid
	let err = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0x02))]);
	let err = db.execute_vtxo_tree_update(err).await.unwrap_err();
	assert!(err.to_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn mark_oor_spent_missing_vtxo_fails() {
	let (_ctx, db) = test_db("mark_oor_spent_missing_vtxo_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0xdd))]);
	let err = db.execute_vtxo_tree_update(err).await.unwrap_err();
	assert!(err.to_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn insert_and_mark_in_single_update() {
	let (_ctx, db) = test_db("insert_and_mark_in_single_update").await;

	let input_vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let output_vtxo = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	let spending_txid = dummy_txid(0xee);

	// Insert the input as spendable first
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([input_vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert input");

	// Arkoor-style update: insert output + internal vtxos, mark input spent
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([output_vtxo.clone()])
		.insert_oor_spent_vtxos([(ServerVtxo::from(VTXO_VECTORS.arkoor2_vtxo.clone()), spending_txid)])
		.mark_vtxos_oor_spent([(input_vtxo.id(), spending_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("arkoor update");

	// Input should be spent
	let state = db.get_user_vtxo_by_id(input_vtxo.id()).await.expect("input found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));

	// Output should exist
	db.get_user_vtxo_by_id(output_vtxo.id()).await.expect("output found");
}

#[tokio::test]
async fn mark_round_spent() {
	let (_ctx, db) = test_db("mark_round_spent").await;
	let round_id = insert_dummy_round(&db, 1).await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id)]);
	db.execute_vtxo_tree_update(update).await.expect("mark round spent");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.spent_in_round, Some(round_id));
}

#[tokio::test]
async fn mark_round_spent_double_spend_fails() {
	let (_ctx, db) = test_db("mark_round_spent_double_spend_fails").await;
	let round_id_1 = insert_dummy_round(&db, 1).await;
	let round_id_2 = insert_dummy_round(&db, 2).await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id_1)]);
	db.execute_vtxo_tree_update(update).await.expect("first spend");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id_2)]);
	let err = db.execute_vtxo_tree_update(err).await.unwrap_err();
	assert!(err.to_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn mark_offboard_spent() {
	let (_ctx, db) = test_db("mark_offboard_spent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let offboard_txid = dummy_txid(0xff);
	let forfeit_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), offboard_txid, forfeit_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("mark offboard spent");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.offboarded_in, Some(offboard_txid));
	assert_eq!(state.oor_spent_txid, Some(forfeit_txid));
}

#[tokio::test]
async fn mark_offboard_spent_double_spend_fails() {
	let (_ctx, db) = test_db("mark_offboard_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), dummy_txid(0x01), dummy_txid(0x11))]);
	db.execute_vtxo_tree_update(update).await.expect("first spend");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), dummy_txid(0x02), dummy_txid(0x22))]);
	let err = db.execute_vtxo_tree_update(err).await.unwrap_err();
	assert!(err.to_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn round_forfeit_after_round_spend() {
	let (_ctx, db) = test_db("round_forfeit_after_round_spend").await;
	let round_id = insert_dummy_round(&db, 1).await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let forfeit_txid = dummy_txid(0xab);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id)]);
	db.execute_vtxo_tree_update(update).await.expect("round spend");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_forfeited([(vtxo.id(), forfeit_txid)]);
	db.execute_vtxo_tree_update(update).await.expect("round forfeit");

	let state = db.get_user_vtxo_by_id(vtxo.id()).await.expect("vtxo found");
	assert_eq!(state.spent_in_round, Some(round_id));
	assert_eq!(state.oor_spent_txid, Some(forfeit_txid));
}

#[tokio::test]
async fn round_forfeit_without_round_spend_fails() {
	let (_ctx, db) = test_db("round_forfeit_without_round_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_round_forfeited([(vtxo.id(), dummy_txid(0xcd))]);
	let err = db.execute_vtxo_tree_update(err).await.unwrap_err();
	assert!(
		err.to_string().contains("vtxo not round-spent or already forfeited differently"),
		"got: {}", err,
	);
}

#[tokio::test]
async fn unclaimed_then_claimed() {
	let (_ctx, db) = test_db("unclaimed_then_claimed").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_unclaimed_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert unclaimed");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.execute_vtxo_tree_update(update).await.expect("claim");
}

#[tokio::test]
async fn claim_is_idempotent() {
	let (_ctx, db) = test_db("claim_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_unclaimed_vtxos([vtxo.clone()]);
	db.execute_vtxo_tree_update(update).await.expect("insert unclaimed");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.execute_vtxo_tree_update(update).await.expect("first claim");

	// Already claimed — should still succeed
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.execute_vtxo_tree_update(update).await.expect("idempotent claim");
}
