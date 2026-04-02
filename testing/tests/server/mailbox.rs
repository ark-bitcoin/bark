use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use futures::future::join_all;

use ark::{ProtocolEncoding, ServerVtxo, SECP};
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use ark::test_util::dummy::DummyTestVtxoSpec;

use server::database::{Db, MailboxPayload};
use server_rpc::protos;

use ark_testing::TestContext;
use ark_testing::daemon::captaind::MailboxClient;

/// Regression test for the checkpoint visibility gap in concurrent mailbox writes.
///
/// When multiple writers call `PostVtxosMailbox` concurrently, `next_checkpoint()`
/// commits before the INSERT. A higher checkpoint can become visible while a
/// lower one is still in flight, causing readers that advance their cursor to
/// permanently skip entries.
///
/// Each individual reader has a low probability of polling in the exact window
/// where a checkpoint is allocated but not yet inserted. Running 100 readers
/// in parallel turns this into 1-(1-p)^100, making the race near-certain to
/// be caught by at least one of them.
///
/// This test should fail until the bug is fixed.
#[tokio::test]
async fn mailbox_checkpoint_visibility_gap() {
	let ctx = TestContext::new("server/mailbox_checkpoint_visibility_gap").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.postgres.max_connections = 100;
	}).await;

	let db = Db::connect(&srv.config().postgres).await.expect("connect to captaind's postgres");

	let mailbox_kp = Keypair::new(&SECP, &mut thread_rng());
	let mailbox_id = MailboxIdentifier::from_pubkey(mailbox_kp.public_key());
	let mailbox_pubkey = srv.ark_info().await.mailbox_pubkey;
	let ark_url = srv.ark_url();

	// Generate 100 unique VTXOs and seed them into the vtxo table (FK constraint).
	let vtxo_pairs: Vec<_> = (0..100).map(|_| {
		let kp = Keypair::new(&SECP, &mut thread_rng());
		let (_tx, vtxo) = DummyTestVtxoSpec {
			user_keypair: kp,
			..Default::default()
		}.build();
		(kp, vtxo)
	}).collect();

	db.upsert_vtxos(
		vtxo_pairs.iter().map(|(_, v)| ServerVtxo::from(v.clone()))
	).await.expect("upsert vtxos");

	let writers_done = Arc::new(AtomicBool::new(false));
	let expiry = chrono::Local::now() + Duration::from_secs(300);
	let auth_bytes = MailboxAuthorization::new(&mailbox_kp, expiry).serialize().to_vec();
	let unblinded_id = mailbox_id.as_ref().to_vec();

	// -- Readers: 100 tasks polling as fast as possible, advancing cursor --

	let reader_handles: Vec<_> = (0..100).map(|_| {
		let ark_url = ark_url.clone();
		let writers_done = writers_done.clone();
		let auth_bytes = auth_bytes.clone();
		let unblinded_id = unblinded_id.clone();

		tokio::spawn(async move {
			let mut client = MailboxClient::connect(ark_url).await.unwrap();
			let mut cursor: u64 = 0;
			let mut seen: usize = 0;

			loop {
				let resp = client.read_mailbox(protos::mailbox_server::MailboxRequest {
					unblinded_id: unblinded_id.clone(),
					authorization: Some(auth_bytes.clone()),
					checkpoint: cursor,
				}).await.unwrap().into_inner();

				for msg in &resp.messages {
					cursor = msg.checkpoint;
					seen += 1;
				}

				if writers_done.load(Ordering::Acquire) && resp.messages.is_empty() {
					break;
				}
			}

			seen
		})
	}).collect();

	// -- Writers: 100 tasks, each posting one VTXO to the same mailbox --

	let writer_handles: Vec<_> = vtxo_pairs.iter().map(|(kp, vtxo)| {
		let ark_url = ark_url.clone();
		let blinded_id = mailbox_id.to_blinded(mailbox_pubkey, kp);
		let vtxo_bytes = ProtocolEncoding::serialize(vtxo).to_vec();

		tokio::spawn(async move {
			let mut client = MailboxClient::connect(ark_url).await.unwrap();
			client.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
				blinded_id: blinded_id.as_ref().to_vec(),
				vtxos: vec![vtxo_bytes],
			}).await.unwrap();
		})
	}).collect();

	join_all(writer_handles).await;
	writers_done.store(true, Ordering::Release);

	let reader_results: Vec<usize> = join_all(reader_handles).await
		.into_iter().map(|r| r.unwrap()).collect();

	// Sanity: all 100 writes landed in the database.
	let all = db.get_mailbox_entries(mailbox_id, 0, 10_000).await.unwrap();
	let total: usize = all.iter().map(|e| match &e.payload {
		MailboxPayload::Arkoor { vtxos } => vtxos.len(),
		_ => 0,
	}).sum();
	assert_eq!(total, 100, "all 100 VTXOs should be in the mailbox");

	// Every reader should have seen all 100 messages. If any reader missed
	// messages, the checkpoint visibility gap caused it to skip entries.
	for (i, seen) in reader_results.iter().enumerate() {
		assert_eq!(
			*seen, 100,
			"reader {i} saw only {seen}/100 messages — \
			 checkpoint visibility gap caused it to skip entries",
		);
	}
}
