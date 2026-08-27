use ark_testing::util::ToAltString;
use bitcoin::Txid;
use bitcoin::hashes::Hash;

use ark::ServerVtxo;
use ark::encode::ProtocolEncoding;
use ark::test_util::VTXO_VECTORS;

use server::database::{Db, SpendState};
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
	db.write(async |t| {
		let row = t.query_one(
			"INSERT INTO round (seq, funding_txid, funding_tx, signed_tree, expiry, created_at)
			VALUES ($1, $2, '\\x00', '\\x00', 1000, NOW())
			RETURNING id",
			&[&seq, &funding_txid.to_string()],
		).await.expect("insert dummy round");
		Ok(row.get::<_, i64>("id"))
	}).await.expect("connection")
}

#[tokio::test]
async fn insert_spendable_vtxos() {
	let (_ctx, db) = test_db("insert_spendable_vtxos").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert succeeded");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.vtxo_id, vtxo.id());
}

#[tokio::test]
async fn insert_spendable_is_idempotent() {
	let (_ctx, db) = test_db("insert_spendable_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first insert");

	// Second insert with same vtxo should succeed (ON CONFLICT DO NOTHING)
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("idempotent insert");
}

#[tokio::test]
async fn insert_oor_spent_vtxos() {
	let (_ctx, db) = test_db("insert_oor_spent_vtxos").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert succeeded");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn insert_oor_spent_is_idempotent() {
	let (_ctx, db) = test_db("insert_oor_spent_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first insert");

	// Re-inserting the same vtxo with the same spending txid is a no-op.
	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("idempotent insert");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn insert_oor_spent_double_spend_fails() {
	let (_ctx, db) = test_db("insert_oor_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), dummy_txid(0x01))]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first insert");

	// A second oor-spent insert for the same vtxo with a different txid
	// would silently authorize a double-spend under ON CONFLICT DO NOTHING.
	let update = VtxoTreeUpdate::new()
		.insert_oor_spent_vtxos([(vtxo.clone(), dummy_txid(0x02))]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(update).await).await.unwrap_err();
	assert!(err.to_alt_string().contains("already spent"), "got: {}", err);
}

#[tokio::test]
async fn mark_oor_spent() {
	let (_ctx, db) = test_db("mark_oor_spent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xbb);

	// First insert as spendable
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	// Then mark as oor spent
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("mark oor spent");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));
}

#[tokio::test]
async fn mark_oor_spent_is_idempotent() {
	let (_ctx, db) = test_db("mark_oor_spent_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let spending_txid = dummy_txid(0xcc);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first mark");

	// Same mark again should succeed
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("idempotent mark");
}

#[tokio::test]
async fn mark_oor_spent_double_spend_fails() {
	let (_ctx, db) = test_db("mark_oor_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0x01))]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first spend");

	// Try to spend with a different txid
	let err = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0x02))]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(err).await).await.unwrap_err();
	assert!(err.to_alt_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn mark_oor_spent_missing_vtxo_fails() {
	let (_ctx, db) = test_db("mark_oor_spent_missing_vtxo_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0xdd))]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(err).await).await.unwrap_err();
	assert!(err.to_alt_string().contains("unspendable"), "got: {}", err);
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
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert input");

	// Arkoor-style update: insert output + internal vtxos, mark input spent
	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([output_vtxo.clone()])
		.insert_oor_spent_vtxos([(ServerVtxo::from(VTXO_VECTORS.arkoor2_vtxo.clone()), spending_txid)])
		.mark_vtxos_oor_spent([(input_vtxo.id(), spending_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("arkoor update");

	// Input should be spent
	let state = db.read(async |t| t.get_user_vtxo_by_id(input_vtxo.id()).await).await.expect("input found");
	assert_eq!(state.oor_spent_txid, Some(spending_txid));

	// Output should exist
	db.read(async |t| t.get_user_vtxo_by_id(output_vtxo.id()).await).await.expect("output found");
}

#[tokio::test]
async fn mark_round_spent() {
	let (_ctx, db) = test_db("mark_round_spent").await;
	let round_id = insert_dummy_round(&db, 1).await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("mark round spent");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
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
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id_1)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first spend");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id_2)]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(err).await).await.unwrap_err();
	assert!(err.to_alt_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn mark_offboard_spent() {
	let (_ctx, db) = test_db("mark_offboard_spent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let offboard_txid = dummy_txid(0xff);
	let forfeit_txid = dummy_txid(0xaa);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), offboard_txid, forfeit_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("mark offboard spent");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.offboarded_in, Some(offboard_txid));
	assert_eq!(state.oor_spent_txid, Some(forfeit_txid));
}

#[tokio::test]
async fn mark_offboard_spent_double_spend_fails() {
	let (_ctx, db) = test_db("mark_offboard_spent_double_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), dummy_txid(0x01), dummy_txid(0x11))]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first spend");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_offboard_spent([(vtxo.id(), dummy_txid(0x02), dummy_txid(0x22))]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(err).await).await.unwrap_err();
	assert!(err.to_alt_string().contains("unspendable"), "got: {}", err);
}

#[tokio::test]
async fn round_forfeit_after_round_spend() {
	let (_ctx, db) = test_db("round_forfeit_after_round_spend").await;
	let round_id = insert_dummy_round(&db, 1).await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let forfeit_txid = dummy_txid(0xab);

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_spent([(vtxo.id(), round_id)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("round spend");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_round_forfeited([(vtxo.id(), forfeit_txid)]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("round forfeit");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("vtxo found");
	assert_eq!(state.spent_in_round, Some(round_id));
	assert_eq!(state.oor_spent_txid, Some(forfeit_txid));
}

#[tokio::test]
async fn round_forfeit_without_round_spend_fails() {
	let (_ctx, db) = test_db("round_forfeit_without_round_spend_fails").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let err = VtxoTreeUpdate::new()
		.mark_vtxos_round_forfeited([(vtxo.id(), dummy_txid(0xcd))]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(err).await).await.unwrap_err();
	assert!(
		err.to_alt_string().contains("vtxo not round-spent or already forfeited differently"),
		"got: {}", err,
	);
}

#[tokio::test]
async fn unclaimed_then_claimed() {
	let (_ctx, db) = test_db("unclaimed_then_claimed").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_unclaimed_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert unclaimed");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("claim");
}

#[tokio::test]
async fn claim_is_idempotent() {
	let (_ctx, db) = test_db("claim_is_idempotent").await;

	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());

	let update = VtxoTreeUpdate::new()
		.insert_unclaimed_vtxos([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert unclaimed");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first claim");

	// Already claimed — should still succeed
	let update = VtxoTreeUpdate::new()
		.mark_vtxos_claimed([vtxo.id()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("idempotent claim");
}

#[tokio::test]
async fn provide_signatures_stores_full_vtxo() {
	let (_ctx, db) = test_db("provide_signatures_stores_full_vtxo").await;

	let vtxo = VTXO_VECTORS.board_vtxo.clone();

	// Insert as bare + unregistered: the stored vtxo bytes are empty until
	// the signed version is provided, so the readback below only works if
	// provide_signatures stored them. (Production unregistered inserts —
	// arkoor, lightning — store full-unsigned bytes instead; bare is the
	// leaner fixture.)
	let update = VtxoTreeUpdate::new()
		.insert_unspent_bare_vtxos(
			[ServerVtxo::from(vtxo.clone()).to_bare()], SpendState::Unregistered,
		);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert bare");

	let update = VtxoTreeUpdate::new()
		.provide_signatures([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("provide signatures");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("readback");
	assert!(state.vtxo.has_all_witnesses(), "stored vtxo should be fully signed");
}

#[tokio::test]
async fn provide_signatures_is_idempotent() {
	let (_ctx, db) = test_db("provide_signatures_is_idempotent").await;

	let vtxo = VTXO_VECTORS.board_vtxo.clone();

	let update = VtxoTreeUpdate::new()
		.insert_unspent_bare_vtxos(
			[ServerVtxo::from(vtxo.clone()).to_bare()], SpendState::Unregistered,
		);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert bare");

	let update = VtxoTreeUpdate::new()
		.provide_signatures([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("first provide");

	// Re-applying the same signatures should succeed: a registration can be
	// applied server-side without the wallet recording it (e.g. it crashed
	// before marking the vtxo registered), so a later sync re-sends it.
	let update = VtxoTreeUpdate::new()
		.provide_signatures([vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("idempotent provide");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("readback");
	assert!(state.vtxo.has_all_witnesses(), "stored vtxo should be fully signed");
}

#[tokio::test]
async fn provide_signatures_duplicate_in_batch() {
	let (_ctx, db) = test_db("provide_signatures_duplicate_in_batch").await;

	let vtxo = VTXO_VECTORS.board_vtxo.clone();

	let update = VtxoTreeUpdate::new()
		.insert_unspent_bare_vtxos(
			[ServerVtxo::from(vtxo.clone()).to_bare()], SpendState::Unregistered,
		);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert bare");

	// The same vtxo twice in one batch must not trip the existence check.
	let update = VtxoTreeUpdate::new()
		.provide_signatures([vtxo.clone(), vtxo.clone()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await
		.expect("duplicate in batch should succeed");

	let state = db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.expect("readback");
	assert!(state.vtxo.has_all_witnesses(), "stored vtxo should be fully signed");
}

/// One unknown vtxo rejects the whole batch with a badarg naming every
/// missing id, and rolls back the update for the known ones.
#[tokio::test]
async fn provide_signatures_unknown_vtxos_fail() {
	let (_ctx, db) = test_db("provide_signatures_unknown_vtxos_fail").await;

	let known = VTXO_VECTORS.board_vtxo.clone();
	let unknown1 = VTXO_VECTORS.round1_vtxo.clone();
	let unknown2 = VTXO_VECTORS.arkoor2_vtxo.clone();

	let update = VtxoTreeUpdate::new()
		.insert_unspent_bare_vtxos(
			[ServerVtxo::from(known.clone()).to_bare()], SpendState::Unregistered,
		);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert bare");

	let update = VtxoTreeUpdate::new()
		.provide_signatures([known.clone(), unknown1.clone(), unknown2.clone()]);
	let err = db.write(async |t| t.execute_vtxo_tree_update(update).await).await.unwrap_err();
	let msg = err.to_alt_string();
	assert!(msg.contains("cannot provide signatures for unknown vtxo"), "got: {}", msg);
	assert!(msg.contains(&unknown1.id().to_string()), "got: {}", msg);
	assert!(msg.contains(&unknown2.id().to_string()), "got: {}", msg);

	// The whole batch rolled back: the known vtxo's bytes are still bare.
	let blob = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo FROM vtxo WHERE vtxo_id = $1", &[&known.id().to_string()],
		).await?;
		Ok(row.get::<_, Vec<u8>>(0))
	}).await.unwrap();
	assert_eq!(blob, ServerVtxo::from(known.clone()).to_bare().serialize(),
		"stored bytes should still be the bare encoding after rollback",
	);
}

/// Providing signatures for a vtxo that is no longer `unregistered` must not
/// flip its state back to spendable: `mark_vtxos_registered` only transitions
/// `unregistered` vtxos. A regression there would resurrect spent vtxos.
#[tokio::test]
async fn provide_signatures_does_not_resurrect_spent_vtxo() {
	let (_ctx, db) = test_db("provide_signatures_does_not_resurrect_spent_vtxo").await;

	let vtxo = VTXO_VECTORS.board_vtxo.clone();

	let update = VtxoTreeUpdate::new()
		.insert_spendable_vtxos([ServerVtxo::from(vtxo.clone())]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("insert");

	let update = VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(vtxo.id(), dummy_txid(0xaa))]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("spend");

	// Re-registration of a spent vtxo, like a stale wallet re-asserting its
	// recovery state, overwrites the stored bytes but must keep it spent.
	let update = VtxoTreeUpdate::new()
		.provide_signatures([vtxo.clone()])
		.mark_vtxos_registered([vtxo.id()]);
	db.write(async |t| t.execute_vtxo_tree_update(update).await).await.expect("re-register");

	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text FROM vtxo WHERE vtxo_id = $1",
			&[&vtxo.id().to_string()],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "spent");
}
