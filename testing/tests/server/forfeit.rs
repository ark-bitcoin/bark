use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use parking_lot::Mutex;

use ark::{musig, ProtocolEncoding, SECP};
use ark::attestations::ForfeitNoncesAttestation;
use ark::forfeit::HashLockedForfeitBundle;
use ark::tree::signed::UnlockHash;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::exit::complete_exit;

/// Forwards the hArk forfeit calls and records how the server answered them.
#[derive(Clone, Default)]
struct RecordForfeit {
	nonces: Arc<Mutex<Option<Result<(), String>>>>,
	forfeit: Arc<Mutex<Option<Result<(), String>>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for RecordForfeit {
	async fn request_forfeit_nonces(
		&self, upstream: &mut ArkClient, req: protos::ForfeitNoncesRequest,
	) -> Result<protos::ForfeitNoncesResponse, tonic::Status> {
		let res = upstream.request_forfeit_nonces(req).await;
		*self.nonces.lock() = Some(res.as_ref().map(|_| ()).map_err(|e| e.message().to_owned()));
		Ok(res?.into_inner())
	}

	async fn forfeit_vtxos(
		&self, upstream: &mut ArkClient, req: protos::ForfeitVtxosRequest,
	) -> Result<protos::ForfeitVtxosResponse, tonic::Status> {
		let res = upstream.forfeit_vtxos(req).await;
		*self.forfeit.lock() = Some(res.as_ref().map(|_| ()).map_err(|e| e.message().to_owned()));
		Ok(res?.into_inner())
	}
}

/// A round input passes every check when it joins the round and the round
/// finishes. Before the owner forfeits it, a stale copy of the wallet exits
/// the input and claims it through its exit clause. The forfeit that follows
/// could never confirm, so the server must refuse it instead of releasing
/// the unlock preimage.
#[tokio::test]
async fn forfeit_refuses_exited_input() {
	let ctx = TestContext::new("server/forfeit_refuses_exited_input").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().watchmand().create().await;
	let wm = srv.watchmand();

	// bark1 refreshes a board into a round vtxo; the clone keeps a copy of it
	let bark1 = ctx.bark("bark1", &srv).funded(sat(500_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark1.sync().await;
	assert_eq!(bark1.vtxo_ids().await.len(), 1);
	let bark1_old = bark1.full_clone("bark1_old").await;

	let record = RecordForfeit::default();
	let proxy = srv.start_proxy_no_mailbox(record.clone()).await;
	bark1.set_ark_url(&proxy.address).await;

	// the round vtxo joins a second round; bark1 only forfeits it once the
	// round tx confirmed and it syncs again
	ctx.refresh_all(&srv, &[&bark1]).await;
	assert!(record.nonces.lock().is_none(), "forfeit started before the round confirmed");

	// meanwhile the stale clone exits the input and claims it after the exit delta
	bark1_old.start_exit_all().await;
	complete_exit(&ctx, &bark1_old).await;
	bark1_old.claim_all_exits(bark1_old.get_onchain_address().await).await;
	let tip = ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	wm.wait_for_sync_height(tip).await;

	// bark1 now tries to finish the hArk swap
	bark1.sync().await;
	let nonces = record.nonces.lock().clone().expect("bark did not request forfeit nonces");
	let forfeit = record.forfeit.lock().clone();
	assert!(!matches!(forfeit, Some(Ok(()))), "server signed the forfeit of an exited input");
	let err = nonces.err().or_else(|| forfeit.and_then(|r| r.err()))
		.expect("server accepted the forfeit calls for an exited input");
	assert!(err.contains("exited onchain"), "unexpected error: {err}");

	// the participation was not forfeited, so the preimage was not released
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let forfeited = db.read(async |t| {
		let row = t.query_one(
			"SELECT forfeited_at IS NOT NULL FROM round_participation \
			WHERE round_id IS NOT NULL ORDER BY id DESC LIMIT 1",
			&[],
		).await?;
		Ok(row.get::<_, bool>(0))
	}).await.unwrap();
	assert!(!forfeited, "server released the unlock preimage for an exited input");
}

/// With `forfeit_attestation_required`, someone who knows a round input but
/// not its key gets the same answer from both forfeit calls for every unlock
/// hash, so they can't tell which participation the input belongs to.
#[tokio::test]
async fn forfeit_calls_do_not_reveal_participation_membership() {
	let ctx = TestContext::new("server/forfeit_calls_do_not_reveal_participation_membership").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().cfg(|cfg| {
		cfg.forfeit_attestation_required = true;
	}).create().await;
	let victim = ctx.bark("victim", &srv).funded(sat(1_000_000)).create().await;
	let other = ctx.bark("other", &srv).funded(sat(1_000_000)).create().await;

	let known_input = victim.board_and_confirm_and_register(&ctx, sat(200_000)).await[0];
	let private_input = victim.board_and_confirm_and_register(&ctx, sat(300_000)).await[0];
	other.board_and_confirm_and_register(&ctx, sat(400_000)).await;

	// both wallets join the round but only forfeit once it confirmed
	ctx.refresh_all(&srv, &[&victim, &other]).await;

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let hashes = db.read(async |t| {
		let rows = t.query(
			"SELECT unlock_hash FROM round_participation WHERE round_id IS NOT NULL", &[],
		).await?;
		Ok(rows.iter().map(|r| UnlockHash::from_str(r.get(0)).unwrap()).collect::<Vec<_>>())
	}).await.unwrap();
	assert_eq!(hashes.len(), 2);

	let mut observer = srv.get_public_rpc().await;
	let attacker_key = Keypair::new(&SECP, &mut thread_rng());
	let (_, user_nonce) = musig::nonce_pair(&attacker_key);
	let mut bare_nonce_errs = HashSet::new();
	let mut forged_nonce_errs = HashSet::new();
	let mut forfeit_errs = HashSet::new();
	for unlock_hash in hashes {
		let err = observer.request_forfeit_nonces(protos::ForfeitNoncesRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			vtxo_ids: vec![known_input.to_bytes().to_vec()],
			attestations: vec![],
		}).await.expect_err("nonces without attestation");
		bare_nonce_errs.insert(err.message().to_owned());

		let forged = ForfeitNoncesAttestation::new(unlock_hash, known_input, &attacker_key);
		let err = observer.request_forfeit_nonces(protos::ForfeitNoncesRequest {
			unlock_hash: unlock_hash.to_byte_array().to_vec(),
			vtxo_ids: vec![known_input.to_bytes().to_vec()],
			attestations: vec![forged.serialize()],
		}).await.expect_err("nonces with a forged attestation");
		forged_nonce_errs.insert(err.message().to_owned());

		let bundle = HashLockedForfeitBundle {
			vtxo_id: known_input,
			unlock_hash,
			user_nonce,
			part_sig: musig::PartialSignature::from_byte_array(&[1; 32]).unwrap(),
		};
		let err = observer.forfeit_vtxos(protos::ForfeitVtxosRequest {
			forfeit_bundles: vec![bundle.serialize()],
		}).await.expect_err("forfeit without nonces");
		forfeit_errs.insert(err.message().to_owned());
	}
	for errs in [&bare_nonce_errs, &forged_nonce_errs, &forfeit_errs] {
		assert_eq!(errs.len(), 1, "answers differ per unlock hash: {errs:?}");
		assert!(!errs.iter().any(|e| e.contains(&private_input.to_string())), "{errs:?}");
	}

	// the owners still forfeit, sending their attestations
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	victim.sync().await;
	other.sync().await;
	let unforfeited = db.read(async |t| {
		let row = t.query_one(
			"SELECT count(*) FROM round_participation \
			WHERE round_id IS NOT NULL AND forfeited_at IS NULL", &[],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(unforfeited, 0);
}
