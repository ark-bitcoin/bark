use std::str::FromStr;

use bitcoin::Txid;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use ark::ServerVtxo;
use ark::lightning::PaymentHash;
use ark::test_util::VTXO_VECTORS;
use bark::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use server::ExpiryPayoutRefusal;
use server::database::{Db, SpendState};
use server::database::htlc_vtxo::{self, HtlcDirection};
use server::database::ln::LightningPaymentStatus;
use server::database::tree::VtxoTreeUpdate;

use ark_testing::TestContext;
use ark_testing::util::{poll_interval, FutureExt};

use crate::expiry_payout::{decide_for_payout, test_server_mailbox_key};

/// A database in expiry payout mode for a test.
async fn payout_db(name: &str) -> (TestContext, Db) {
	let mut ctx = TestContext::new_minimal(&format!("postgresd/{}", name)).await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create_with_payouts(&postgres_cfg, true).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");
	(ctx, db)
}

/// A write that competes with an expiry decision.
enum Write {
	/// Mark the sources of a successful payment spent.
	PaymentSucceeded(PaymentHash),
	Tree(VtxoTreeUpdate),
}

/// Run `write` while a transaction holds the row of `vtxo`. Once `write`
/// waits on that row, decide `vtxo` for an expiry payout and commit, then
/// return the result of `write`: the VTXOs it reported.
async fn write_behind_decision(db: &Db, vtxo: &str, write: Write) -> anyhow::Result<Vec<ark::VtxoId>> {
	let id = vtxo.to_owned();
	let competing = db.clone();
	let (pid_send, pid_recv) = tokio::sync::oneshot::channel();
	let writer = db.write(async |t| {
		t.query_one("SELECT vtxo_id FROM vtxo WHERE vtxo_id = $1 FOR UPDATE", &[&id]).await?;
		let writer = tokio::spawn(async move {
			competing.write(async |t| {
				pid_send.send(t.query_one("SELECT pg_backend_pid()", &[]).await?.get::<_, i32>(0)).unwrap();
				match write {
					Write::PaymentSucceeded(hash) => t.mark_htlc_send_vtxos_ln_spent(hash).await,
					Write::Tree(update) => t.execute_vtxo_tree_update(update).await.map(|_| Vec::new()),
				}
			}).await
		});
		let pid = pid_recv.await?;
		async {
			while !t.query_one("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)", &[&pid])
				.await.unwrap().get::<_, bool>(0) {
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(10_000).await;
		decide_for_payout(t, &[id.clone()]).await?;
		t.execute("UPDATE vtxo SET spend_state = 'spent', updated_at = NOW() WHERE vtxo_id = $1", &[&id]).await?;
		Ok(writer)
	}).await.unwrap();
	writer.await.unwrap()
}

/// The writer that marks the sources of a successful payment spent waits
/// behind an expiry decision on a source, and then leaves the decided
/// source alone: one VTXO has one spend.
#[tokio::test]
async fn expiry_payout_decision_keeps_source_from_payment() {
	let (_ctx, db) = payout_db("expiry_payout_decision_keeps_source_from_payment").await;
	let node = PublicKey::from_str("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354").unwrap();
	let (node_id, _) = db.write(async |t| t.register_lightning_node(&node).await).await.unwrap();
	let vtxo = ServerVtxo::from(VTXO_VECTORS.arkoor_htlc_out_vtxo.clone());
	let htlc = VTXO_VECTORS.arkoor_htlc_out_vtxo.policy().as_server_htlc_send().unwrap();
	db.write(async |t| {
		t.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()])
			.bind_owner_mailboxes([(vtxo.id(), test_server_mailbox_key().public_key())])?).await?;
		htlc_vtxo::create_htlc_vtxos(t, &[(vtxo.id(), htlc.payment_hash, htlc.htlc_expiry)], HtlcDirection::Incoming).await
	}).await.unwrap();
	let invoice_key = SecretKey::from_slice(&[41; 32]).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Regtest)
		.description("decided source".into())
		.payment_hash(htlc.payment_hash.to_sha256_hash())
		.payment_secret(PaymentSecret([42; 32]))
		.current_timestamp().min_final_cltv_expiry_delta(18)
		.amount_milli_satoshis(vtxo.amount().to_sat() * 1_000)
		.build_signed(|message| Secp256k1::new().sign_ecdsa_recoverable(message, &invoice_key)).unwrap();
	let hash = htlc.payment_hash.to_string();
	let id = vtxo.id().to_string();
	db.write(async |t| {
		let attempt = t.query_one("
			INSERT INTO lightning_payment_attempt(lightning_node_id, payment_hash, amount_msat, status,
				block_height, user_fee_sat, user_agent, retry_for_secs, created_at, updated_at)
			VALUES($1, $2, $3, 'requested', 1, 1, 'bark', 60, NOW(), NOW())
			RETURNING id
		", &[&node_id, &hash, &(invoice.amount_milli_satoshis().unwrap() as i64)]).await?.get::<_, i64>(0);
		t.execute("INSERT INTO lightning_payment_attempt_htlc_vtxo(lightning_payment_attempt_id, vtxo_id) VALUES($1, $2)",
			&[&attempt, &id]).await?;
		Ok(())
	}).await.unwrap();
	let attempt = db.read(async |t| t.get_open_lightning_payment_attempt_by_payment_hash(htlc.payment_hash).await)
		.await.unwrap().unwrap();
	db.write(async |t| t.update_lightning_payment_attempt_result(&attempt, LightningPaymentStatus::Succeeded, None, None)
		.await).await.unwrap().unwrap();

	let reported = write_behind_decision(&db, &id, Write::PaymentSucceeded(attempt.payment_hash)).await.unwrap();
	assert_eq!(reported, vec![vtxo.id()], "the decided source is reported, not taken");
	assert_eq!(db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.unwrap().spend_state, SpendState::Spent);
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

/// A VTXO decided for an expiry payout refuses every tree writer that
/// waited on its row, with the decided reason.
#[tokio::test]
async fn expiry_payout_decision_refuses_waiting_tree_writes() {
	let (_ctx, db) = payout_db("expiry_payout_decision_refuses_waiting_tree_writes").await;
	let vtxo = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new().insert_spendable_vtxos([vtxo.clone()])
		.bind_owner_mailboxes([(vtxo.id(), test_server_mailbox_key().public_key())])?).await).await.unwrap();
	let txid = Txid::from_byte_array([42; 32]);
	let writes = [
		("arkoor spend", VtxoTreeUpdate::new().mark_vtxos_oor_spent([(vtxo.id(), txid)])),
		("offboard", VtxoTreeUpdate::new().mark_vtxos_offboard_spent([(vtxo.id(), txid, txid)])),
		("refresh", VtxoTreeUpdate::new().mark_vtxos_round_spent([(vtxo.id(), 1)])),
		("round forfeit", VtxoTreeUpdate::new().mark_vtxos_round_forfeited([(vtxo.id(), txid)])),
		("round output claim", VtxoTreeUpdate::new().mark_vtxos_claimed([vtxo.id()])),
		("registration", VtxoTreeUpdate::new().mark_vtxos_registered([vtxo.id()])),
	];
	for (name, update) in writes {
		let error = write_behind_decision(&db, &vtxo.id().to_string(), Write::Tree(update)).await.expect_err(name);
		assert!(matches!(error.downcast_ref::<ExpiryPayoutRefusal>(),
			Some(ExpiryPayoutRefusal::DecidedForPayout(id)) if *id == vtxo.id()), "{name}: {error:#}");
		let state = db.read(async |t| t.get_user_vtxos_by_id(&[vtxo.id()]).await).await.unwrap().remove(0);
		assert_eq!((state.spend_state, state.offboarded_in, state.oor_spent_txid, state.spent_in_round),
			(SpendState::Spent, None, None, None), "{name}");
		db.write(async |t| Ok(t.batch_execute("
			DELETE FROM expiry_payout_vtxo; DELETE FROM expiry_payout;
			UPDATE vtxo SET spend_state = 'spendable', updated_at = NOW();
		").await?)).await.unwrap();
	}
}

/// Cancelling a refresh that never got its forfeits stops only that
/// refresh: it cannot store a forfeit afterwards, while its inputs stay
/// spendable for other spends. A refresh with forfeits is never cancelled.
#[tokio::test]
async fn expiry_payout_cancels_an_unfinished_refresh_only() {
	let (_ctx, db) = payout_db("expiry_payout_cancels_an_unfinished_refresh_only").await;
	let pending_input = ServerVtxo::from(VTXO_VECTORS.board_vtxo.clone());
	let other_input = ServerVtxo::from(VTXO_VECTORS.round1_vtxo.clone());
	let forfeited_input = ServerVtxo::from(VTXO_VECTORS.round2_vtxo.clone());
	let mailbox = test_server_mailbox_key().public_key();
	let pending_hash = ark::tree::signed::UnlockHash::hash(&[7; 32]);
	let forfeited_hash = ark::tree::signed::UnlockHash::hash(&[8; 32]);
	let (pending, forfeited) = db.write(async |t| {
		t.execute_vtxo_tree_update(VtxoTreeUpdate::new()
			.insert_spendable_vtxos([pending_input.clone(), other_input.clone(), forfeited_input.clone()])
			.bind_owner_mailboxes([pending_input.id(), other_input.id(), forfeited_input.id()].map(|id| (id, mailbox)))?
		).await?;
		let pending = t.query_one("INSERT INTO round_participation(unlock_hash, created_at) VALUES($1, NOW()) RETURNING id",
			&[&pending_hash.to_string()]).await?.get::<_, i64>(0);
		let forfeited = t.query_one("
			INSERT INTO round_participation(unlock_hash, created_at, forfeited_at) VALUES($1, NOW(), NOW()) RETURNING id
		", &[&forfeited_hash.to_string()]).await?.get::<_, i64>(0);
		for (participation, input) in [(pending, &pending_input), (pending, &other_input), (forfeited, &forfeited_input)] {
			t.execute("INSERT INTO round_part_input(participation_id, vtxo_id) VALUES($1, $2)",
				&[&participation, &input.id().to_string()]).await?;
		}
		Ok((pending, forfeited))
	}).await.unwrap();
	assert!(db.write(async |t| t.cancel_expiry_participations(&[pending]).await).await.unwrap());
	assert!(db.write(async |t| t.cancel_expiry_participations(&[pending]).await).await.unwrap(), "cancelling is idempotent");
	db.write(async |t| t.set_forfeit_transactions(
		pending_hash, &[pending_input.id()], &[VTXO_VECTORS.anchor_tx.clone()], &[VTXO_VECTORS.anchor_tx.compute_txid()],
	).await).await.expect_err("a cancelled refresh cannot store a forfeit");
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new()
		.mark_vtxos_oor_spent([(other_input.id(), Txid::from_byte_array([3; 32]))])).await).await.unwrap();
	assert!(!db.write(async |t| t.cancel_expiry_participations(&[forfeited]).await).await.unwrap());
}
