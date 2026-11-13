use ark::ServerVtxo;
use ark::test_util::VTXO_VECTORS;
use server::database::{Db, SpendState};
use server::database::tree::VtxoTreeUpdate;

use ark_testing::TestContext;

use crate::expiry_payout::test_server_mailbox_key;

/// A database in expiry payout mode for a test.
async fn payout_db(name: &str) -> (TestContext, Db) {
	let mut ctx = TestContext::new_minimal(&format!("postgresd/{}", name)).await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create_with_payouts(&postgres_cfg, true).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");
	(ctx, db)
}

/// Every VTXO is created with the mailbox of its owner, once. A VTXO
/// without a mailbox is refused, and creating a VTXO again keeps its
/// mailbox row.
#[tokio::test]
async fn expiry_payout_vtxos_are_created_with_their_mailbox_once() {
	let (_ctx, db) = payout_db("expiry_payout_vtxos_are_created_with_their_mailbox_once").await;
	let mailbox = test_server_mailbox_key().public_key();
	let row = async |vtxo: &ServerVtxo<ark::vtxo::Full>| db.read(async |t| Ok(t.query_opt(
		"SELECT mailbox_pk, xmin::TEXT FROM vtxo_owner_mailbox WHERE vtxo_id = $1", &[&vtxo.id().to_string()],
	).await?.map(|row| (row.get::<_, String>(0), row.get::<_, String>(1))))).await.unwrap();
	let births = [
		(&VTXO_VECTORS.board_vtxo, SpendState::Spendable),
		(&VTXO_VECTORS.arkoor2_vtxo, SpendState::Unregistered),
		(&VTXO_VECTORS.round1_vtxo, SpendState::Unclaimed),
		(&VTXO_VECTORS.arkoor_htlc_out_vtxo, SpendState::HtlcRecvUnclaimed),
	];
	for (vtxo, state) in births {
		let vtxo = ServerVtxo::from(vtxo.clone());
		let update = || VtxoTreeUpdate::new().insert_unspent_vtxos([vtxo.clone()], state)
			.bind_owner_mailboxes([(vtxo.id(), mailbox)]);
		assert_eq!(db.write(async |t| t.execute_vtxo_tree_update(update()?).await).await.unwrap(), 1);
		let created = row(&vtxo).await.unwrap();
		assert_eq!(created.0, mailbox.to_string());
		assert_eq!(db.write(async |t| t.execute_vtxo_tree_update(update()?).await).await.unwrap(), 0);
		assert_eq!(row(&vtxo).await.unwrap(), created, "creating the VTXO again keeps its mailbox row");
	}
	let unbound = ServerVtxo::from(VTXO_VECTORS.arkoor3_vtxo.clone());
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([unbound.clone()]))
		.await).await.unwrap_err();
	assert!(db.read(async |t| t.try_get_bare_vtxo_by_id(unbound.id()).await).await.unwrap().is_none());
	assert!(row(&unbound).await.is_none());
}
