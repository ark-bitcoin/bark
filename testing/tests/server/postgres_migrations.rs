use bitcoin::{OutPoint, Transaction};

use ark::encode::ProtocolEncoding;
use ark::offboard::OffboardForfeitResult;
use ark::test_util::VTXO_VECTORS;
use ark::{ServerVtxo, ServerVtxoPolicy};
use bitcoin_ext::P2TR_DUST;
use server::database::data_migrations;
use server::database::tree::VtxoTreeUpdate;
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
	db.write(async |t| t.upsert_vtxos([vtxo.clone()]).await).await.unwrap();

	let bare = db.read(async |t| t.get_bare_vtxo_by_id(vtxo.id()).await).await.unwrap();

	assert_eq!(bare.vtxo_id, vtxo.id());
	assert_eq!(bare.vtxo.amount(), vtxo.amount());
	assert_eq!(bare.vtxo.exit_delta(), vtxo.exit_delta());
	assert_eq!(bare.vtxo.server_pubkey(), vtxo.server_pubkey());
	assert_eq!(bare.vtxo.chain_anchor(), vtxo.chain_anchor());
	assert_eq!(bare.vtxo.expiry_height(), vtxo.expiry_height());
	assert_eq!(bare.vtxo.policy().serialize(), vtxo.policy().serialize());
}

fn dummy_tx(num: u32) -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::from_height(num).unwrap(),
		input: vec![],
		output: vec![],
	}
}

/// Offboard connector and forfeit vtxos used to be stored with an empty
/// `vtxo` blob, which makes the watchman frontier unreadable once they enter
/// it, and the connector outputs paid an ephemeral key that died with its
/// offboard session, so they can never be swept. The migration rebuilds the
/// blobs from the row columns and takes the dead connectors out of the
/// watchman's reach.
#[tokio::test]
async fn fix_offboard_vtxos() {
	let mut ctx = TestContext::new_minimal("postgresd/fix_offboard_vtxos").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// the user vtxo that gets offboarded
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |t| t.upsert_vtxos([vtxo.clone()]).await).await.unwrap();
	let signed_txs: Vec<_> = vtxo.transactions().map(|item| item.tx).collect();
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new().upsert_signed_tx(signed_txs)).await).await.unwrap();

	let offboard_tx = dummy_tx(1);
	let offboard_txid = offboard_tx.compute_txid();
	let forfeit_tx = dummy_tx(2);
	let forfeit_txid = forfeit_tx.compute_txid();

	// the connector and forfeit vtxos as the offboard flow records them
	let connector_point = OutPoint::new(offboard_txid, 1);
	let connector = ServerVtxo::new(
		connector_point,
		ServerVtxoPolicy::ServerOwned,
		P2TR_DUST,
		vtxo.expiry_height() + 144,
		vtxo.server_pubkey(),
		0,
		connector_point,
	);
	let forfeit = ServerVtxo::new(
		OutPoint::new(forfeit_txid, 0),
		ServerVtxoPolicy::ServerOwned,
		vtxo.amount(),
		vtxo.expiry_height(),
		vtxo.server_pubkey(),
		vtxo.exit_delta(),
		vtxo.chain_anchor(),
	);

	let forfeit_result = OffboardForfeitResult {
		forfeit_txs: vec![forfeit_tx],
		forfeit_vtxos: vec![forfeit.clone()],
		connector_tx: None,
		connector_vtxos: vec![connector.clone()],
	};
	db.write(async |t| t.register_offboard(&[&vtxo], &offboard_tx, &forfeit_result, 0).await).await.unwrap();

	// register_offboard frontiers the connector directly, so the legacy
	// startup path has nothing to pick up
	let unfrontiered = db.read(async |t| t.get_unfrontiered_funding_txids().await).await.unwrap();
	assert!(!unfrontiered.contains(&offboard_txid));

	// Rewrite the rows into the pre-fix format: empty vtxo blob, not in the
	// frontier.
	let client = ctx.postgres_manager().database_client(Some(&postgres_cfg.name)).await;
	let corrupted = client.execute(
		"UPDATE vtxo SET vtxo = ''::bytea, frontier_at = NULL, updated_at = NOW() \
		 WHERE spend_state IN ('offboard-connector', 'offboard-forfeit')",
		&[],
	).await.unwrap();
	assert_eq!(corrupted, 2);

	// The legacy watchman startup path now pulls the offboard vtxos into the
	// frontier, and the empty blob makes the frontier unreadable.
	let unfrontiered = db.read(async |t| t.get_unfrontiered_funding_txids().await).await.unwrap();
	assert!(unfrontiered.contains(&offboard_txid));
	db.write(async |t| t.add_funding_vtxos_to_frontier(offboard_txid, None).await).await.unwrap();
	db.read(async |t| t.get_frontier().await).await
		.expect_err("empty vtxo blob should make the frontier unreadable");

	// Undo the frontier registration again: on most deployments the migration
	// runs before any watchman restart, so the rows are not frontiered yet and
	// the migration itself must take the connector out of the legacy path.
	client.execute(
		"UPDATE vtxo SET frontier_at = NULL, updated_at = NOW() \
		 WHERE spend_state = 'offboard-connector'",
		&[],
	).await.unwrap();

	let fixed = data_migrations::fix_offboard_vtxos::run(&db).await.unwrap();
	assert_eq!(fixed, 2);

	// the frontier is readable again and the dead connector is out of reach
	let frontier = db.read(async |t| t.get_frontier().await).await.unwrap();
	assert!(!frontier.contains_key(&connector.id()),
		"dead connector must not be in the frontier",
	);
	let unfrontiered = db.read(async |t| t.get_unfrontiered_funding_txids().await).await.unwrap();
	assert!(!unfrontiered.contains(&offboard_txid),
		"the legacy path must not pick the dead connector up again",
	);

	// The rebuilt blobs decode to the original vtxos, except that the forfeit
	// gets its amount corrected for the connector dust the forfeit tx output
	// accumulates.
	let fixed_forfeit = ServerVtxo::new(
		forfeit.point(),
		ServerVtxoPolicy::ServerOwned,
		forfeit.amount() + P2TR_DUST,
		forfeit.expiry_height(),
		forfeit.server_pubkey(),
		forfeit.exit_delta(),
		forfeit.chain_anchor(),
	);
	for expected in [&connector, &fixed_forfeit] {
		let row = client.query_one(
			"SELECT vtxo, amount FROM vtxo WHERE vtxo_id = $1",
			&[&expected.id().to_string()],
		).await.unwrap();
		assert_eq!(row.get::<_, &[u8]>("vtxo"), expected.serialize().as_slice());
		assert_eq!(row.get::<_, i64>("amount") as u64, expected.amount().to_sat());
	}

	// re-running the migration is a no-op
	let fixed = data_migrations::fix_offboard_vtxos::run(&db).await.unwrap();
	assert_eq!(fixed, 0);
}
