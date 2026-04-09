use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use futures::future::join_all;

use ark::{ProtocolEncoding, ServerVtxo, SECP};
use ark::lightning::PaymentHash;
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use ark::test_util::dummy::DummyTestVtxoSpec;

use server::database::{Db, MailboxPayload};
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use ark_testing::{btc, TestContext};
use ark_testing::daemon::captaind::MailboxClient;

/// Regression test for the checkpoint visibility gap in concurrent mailbox writes.
///
/// When multiple writers call `PostVtxosMailbox` concurrently, without proper
/// serialization a higher checkpoint can become visible while a lower one is
/// still in flight, causing readers that advance their cursor to permanently
/// skip entries.
///
/// The fix uses `pg_advisory_xact_lock` to serialize all mailbox writes,
/// ensuring checkpoints are allocated and committed in strict order.
///
/// Each individual reader has a low probability of polling in the exact window
/// where a checkpoint is allocated but not yet inserted. Running 100 readers
/// in parallel turns this into 1-(1-p)^100, making the race near-certain to
/// be caught by at least one of them.
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
			let mut final_poll = false;

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
					if final_poll {
						break;
					}
					final_poll = true;
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

/// Test that an incoming lightning payment posts an IncomingLightningPayment
/// notification to the receiver's mailbox with the payment hash.
#[tokio::test]
async fn mailbox_lightning_receive_pending() {
	let ctx = TestContext::new("server/mailbox_lightning_receive_pending").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Server must be linked to the receiver CLN to generate hold invoices
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;
	let bark_wallet = bark.client().await;

	// Create an invoice and have the external sender pay it
	let pay_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;

	let cloned_invoice = invoice_info.invoice.clone();
	let pay_handle = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice).await
	});

	// Read the receiver's main mailbox, retrying until the notification arrives.
	let mailbox_kp = bark_wallet.mailbox_keypair();
	let mailbox_id = MailboxIdentifier::from_pubkey(mailbox_kp.public_key());

	let incoming = tokio::time::timeout(Duration::from_secs(15), async {
		loop {
			let expiry = chrono::Local::now() + Duration::from_secs(60);
			let mailbox_auth = MailboxAuthorization::new(&mailbox_kp, expiry);

			let read_req = protos::mailbox_server::MailboxRequest {
				authorization: Some(mailbox_auth.serialize().to_vec()),
				unblinded_id: mailbox_id.to_vec(),
				checkpoint: 0,
			};

			let mailbox_msgs = mb_rpc.read_mailbox(read_req).await.unwrap().into_inner();

			let found = mailbox_msgs.messages.iter().find_map(|msg| {
				match msg.message.as_ref()? {
					Message::IncomingLightningPayment(m) => Some(m.clone()),
					_ => None,
				}
			});

			if let Some(msg) = found {
				break msg;
			}
			tokio::time::sleep(Duration::from_millis(200)).await;
		}
	}).await.expect("IncomingLightningPayment notification should arrive within 15s");

	// Verify the payment hash is valid
	PaymentHash::try_from(incoming.payment_hash.clone())
		.expect("valid payment hash");

	// We don't need to claim or await the payment — we only care that
	// the notification arrived. Drop the handle to avoid a panic from
	// the sender timing out on the unsettled hold invoice.
	drop(pay_handle);
}
