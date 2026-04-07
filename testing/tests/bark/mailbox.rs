use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::{MailboxAuthorization, MailboxIdentifier};
use server_rpc::protos;

use ark_testing::{btc, require_bark_version, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, MailboxClient};
use ark_testing::util::FutureExt;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

#[tokio::test]
async fn reject_arkoor_with_bad_signature() {
	let ctx = TestContext::new("bark/reject_arkoor_with_bad_signature").await;

	#[derive(Clone)]
	struct InvalidSigProxy;

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InvalidSigProxy {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, ArkoorMessage};

			let response = upstream.read_mailbox(req).await?.into_inner();
			let message = response.messages[0].message.as_ref().unwrap();
			let mut vtxo = match message {
				Message::Arkoor(message) => {
					Vtxo::deserialize(&message.vtxos[0]).unwrap()
				},
				_ => panic!("unexpected message type"),
			};
			vtxo.invalidate_final_sig();
			let message = ArkoorMessage { vtxos: vec![vtxo.serialize()] };

			Ok(protos::mailbox_server::MailboxMessages {
				messages: vec![protos::mailbox_server::MailboxMessage {
					message: Some(mailbox_message::Message::Arkoor(message)),
					checkpoint: 0,
				}],
				have_more: false,
			})
		}
	}

	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// create a proxy to return an arkoor with invalid signatures
	let proxy = srv.start_proxy_with_mailbox((), InvalidSigProxy).await;

	// create a third wallet to receive the invalid arkoor
	let bark2 = ctx.new_bark("bark2".to_string(), &proxy.address).await;
	let bark2_addr = bark2.address().await;

	// Send arkoor package to mailbox
	bark1.send_oor(bark2_addr, sat(10_000)).await;

	// we should drop invalid arkoors
	assert_eq!(bark2.vtxos().await.len(), 0);

	// check that we saw a log
	tokio::time::sleep(Duration::from_millis(250)).await;


	assert!(io::BufReader::new(std::fs::File::open(bark2.command_log_file()).unwrap()).lines().any(|line| {
		let line = line.unwrap();
		line.contains("Received invalid arkoor VTXO") &&
		line.contains("error verifying one of the genesis transitions \
			(idx=2/3 type=arkoor): invalid signature")
	}));
}

#[tokio::test]
async fn accept_mailbox() {
	let ctx = TestContext::new("bark/accept_mailbox").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark".to_string(), &srv, sat(1_000_000)).await;

	let _board = bark.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark2 = ctx.new_bark("bark2", &srv).await;
	bark.send_oor(bark2.address().await, sat(100_000)).await;

	bark2.maintain().await;
	let bark2_vtxos = bark2.vtxos().await;
	assert_eq!(bark2_vtxos.len(), 1);

	// Test import_vtxo
	let bark2_wallet = bark2.client().await;
	let vtxos = bark2_wallet.vtxos().await.unwrap();
	let vtxo_hex = vtxos[0].vtxo.serialize_hex();

	bark2.import_vtxos(&[&vtxo_hex]).await;
	assert_eq!(bark2.vtxos().await.len(), 1, "import should be idempotent");

	let err = bark.try_import_vtxos(&[&vtxo_hex]).await.unwrap_err();
	assert!(err.to_string().contains("signable clause") || err.to_string().contains("not owned"), "expected ownership error, got: {}", err);

	let bark3 = ctx.new_bark("bark3", &srv).await;
	bark.send_oor(bark3.address().await, sat(50_000)).await;
	bark.send_oor(bark3.address().await, sat(60_000)).await;

	bark3.maintain().await;
	let bark3_vtxos = bark3.vtxos().await;
	assert_eq!(bark3_vtxos.len(), 2, "bark3 should have 2 VTXOs");

	let bark3_wallet = bark3.client().await;
	let vtxos = bark3_wallet.vtxos().await.unwrap();
	let vtxo_hex1 = vtxos[0].vtxo.serialize_hex();
	let vtxo_hex2 = vtxos[1].vtxo.serialize_hex();

	// Drop all VTXOs from bark3 and re-import them in bulk
	bark3.drop_vtxos().await;
	assert_eq!(bark3.vtxos().await.len(), 0, "bark3 should have 0 VTXOs after drop");

	let imported = bark3.import_vtxos(&[&vtxo_hex1, &vtxo_hex2]).await;
	assert_eq!(imported.len(), 2, "should have imported 2 VTXOs");
	assert_eq!(bark3.vtxos().await.len(), 2, "bark3 should have 2 VTXOs after bulk import");

	let bark4 = ctx.new_bark("bark4", &srv).await;
	bark.send_oor(bark4.address().await, sat(40_000)).await;
	bark4.maintain().await;
	assert_eq!(bark4.vtxos().await.len(), 1, "bark4 should have 1 VTXO");

	let bark4_wallet = bark4.client().await;
	let bark4_vtxos = bark4_wallet.vtxos().await.unwrap();
	let expired_vtxo_hex = bark4_vtxos[0].vtxo.serialize_hex();

	bark4.drop_vtxos().await;
	assert_eq!(bark4.vtxos().await.len(), 0, "bark4 should have 0 VTXOs after drop");

	ctx.generate_blocks(srv.config().vtxo_lifetime as u32 + 10).await;

	let err = bark4.try_import_vtxos(&[&expired_vtxo_hex]).await.unwrap_err();
	assert!(err.to_string().contains("expired"), "expected expiry error, got: {}", err);
}

/// Helper to read all vtxo_ids from a recovery mailbox
async fn read_recovery_vtxo_ids(
	mb_rpc: &mut server_rpc::protos::mailbox_server::mailbox_service_client::MailboxServiceClient<tonic::transport::Channel>,
	wallet: &bark::Wallet,
) -> Vec<VtxoId> {
	let recovery_mailbox_kp = wallet.recovery_mailbox_keypair();
	let recovery_mailbox_id = MailboxIdentifier::from_pubkey(recovery_mailbox_kp.public_key());

	let expiry = chrono::Local::now() + Duration::from_secs(60);
	let mailbox_auth = MailboxAuthorization::new(&recovery_mailbox_kp, expiry);

	let read_mailbox = protos::mailbox_server::MailboxRequest {
		authorization: Some(mailbox_auth.serialize().to_vec()),
		unblinded_id: recovery_mailbox_id.to_vec(),
		checkpoint: 0,
	};

	let mailbox_msgs = mb_rpc.read_mailbox(read_mailbox).await.unwrap().into_inner();

	let mut vtxo_ids = Vec::new();
	for msg in mailbox_msgs.messages {
		if let Some(Message::RecoveryVtxoIds(recovery_msg)) = msg.message {
			for id_bytes in recovery_msg.vtxo_ids {
				vtxo_ids.push(VtxoId::from_slice(&id_bytes).unwrap());
			}
		}
	}
	vtxo_ids
}

/// Test that vtxo_ids are posted to the recovery mailbox in various scenarios:
/// - Board (when vtxo becomes spendable)
/// - Receiving arkoor
/// - Sending arkoor (change)
#[tokio::test]
async fn recovery_mailbox_receives_vtxo_ids() {
	// Vtxo id based recovery is only supported later than beta.9
	require_bark_version!(> "0.1.0-beta.9");
	let ctx = TestContext::new("bark/recovery_mailbox_receives_vtxo_ids").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;

	// === Test 1: Board posts vtxo_id to recovery mailbox when vtxo becomes spendable ===
	bark1.board(sat(400_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.sync().await;  // Sync to trigger board registration

	let bark1_wallet = bark1.client().await;
	let bark1_vtxos = bark1_wallet.vtxos().await.unwrap();
	assert_eq!(bark1_vtxos.len(), 1, "bark1 should have 1 VTXO after board");

	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark1_wallet).await;
	assert_eq!(recovery_ids.len(), 1, "board should post to recovery mailbox when vtxo becomes spendable");
	assert_eq!(recovery_ids[0], bark1_vtxos[0].id(), "board vtxo_id should match");

	// === Test 2: Receiving arkoor posts vtxo_id to recovery mailbox ===
	bark1.send_oor(bark2.address().await, sat(100_000)).await;
	bark2.maintain().await;

	let bark2_wallet = bark2.client().await;
	let bark2_vtxos = bark2_wallet.vtxos().await.unwrap();
	assert_eq!(bark2_vtxos.len(), 1, "bark2 should have 1 VTXO after receiving arkoor");

	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark2_wallet).await;
	assert_eq!(recovery_ids.len(), 1, "bark2 recovery mailbox should have 1 vtxo_id");
	assert_eq!(recovery_ids[0], bark2_vtxos[0].id(), "arkoor vtxo_id should match");

	// === Test 3: Sending arkoor posts change vtxo_id to recovery mailbox ===
	// bark1 sent arkoor above and should have change
	let bark1_vtxos_after_send = bark1_wallet.vtxos().await.unwrap();
	assert_eq!(bark1_vtxos_after_send.len(), 1, "bark1 should have 1 change VTXO");

	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark1_wallet).await;
	// 2 vtxo_ids: board + change from sending arkoor
	assert_eq!(recovery_ids.len(), 2, "bark1 recovery mailbox should have 2 vtxo_ids (board + change)");
	assert!(recovery_ids.contains(&bark1_vtxos_after_send[0].id()), "change vtxo_id should be in recovery mailbox");
}

/// Test that lightning send change vtxo_ids are posted to recovery mailbox
#[tokio::test]
async fn recovery_mailbox_lightning_send_change() {
	// Vtxo id based recovery is only supported later than beta.9
	require_bark_version!(> "0.1.0-beta.9");
	let ctx = TestContext::new("bark/recovery_mailbox_lightning_send_change").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server linked to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightning.sender)).await;

	// Start a bark and board
	let bark = ctx.new_bark_with_funds("bark", &srv, btc(3)).await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;
	let bark_wallet = bark.client().await;

	// Get initial recovery mailbox count (should have board vtxo)
	let initial_recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	assert_eq!(initial_recovery_ids.len(), 1, "should have 1 vtxo_id from board");

	lightning.sync().await;

	// Pay a lightning invoice - this creates change
	let invoice = lightning.receiver.invoice(Some(btc(1)), "test_payment", "A test payment").await;
	bark.pay_lightning_wait(invoice, None).await;

	// Get vtxos after payment - should have change vtxo
	let vtxos_after = bark_wallet.vtxos().await.unwrap();
	assert_eq!(vtxos_after.len(), 1, "bark should have 1 change VTXO after lightning payment");

	// Check recovery mailbox has the change vtxo
	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	// 2 vtxo_ids: board + lightning change
	assert_eq!(recovery_ids.len(), 2, "recovery mailbox should have 2 vtxo_ids (board + lightning change)");
	assert!(recovery_ids.contains(&vtxos_after[0].id()), "lightning change vtxo_id should be in recovery mailbox");
}

/// Test that lightning send revocation vtxo_ids are posted to recovery mailbox
/// when a payment fails (no channel exists)
#[tokio::test]
async fn recovery_mailbox_lightning_send_revoke() {
	// Vtxo id based recovery is only supported later than beta.9
	require_bark_version!(> "0.1.0-beta.9");
	let ctx = TestContext::new("bark/recovery_mailbox_lightning_send_revoke").await;

	// Create lightning setup WITHOUT a channel so payment will fail
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;

	// Start a server linked to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.sender), btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;

	// Start a bark and board
	let bark = ctx.new_bark_with_funds("bark", &srv, btc(3)).await;
	bark.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;
	let bark_wallet = bark.client().await;

	// Get initial recovery mailbox count (should have board vtxo)
	let initial_recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	assert_eq!(initial_recovery_ids.len(), 1, "should have 1 vtxo_id from board");

	// Create an invoice - payment will fail since no channel exists
	let invoice = lightning.receiver.invoice(Some(btc(1)), "test_payment", "A test payment").await;

	// Pay lightning - this will fail and user gets revoked vtxos back
	bark.pay_lightning_wait(invoice, None).await;

	// Get vtxos after failed payment - should have change + revoked vtxos
	let vtxos_after = bark_wallet.vtxos().await.unwrap();
	assert_eq!(vtxos_after.len(), 2, "bark should have 2 VTXOs after failed payment (change + revoked)");

	// Check recovery mailbox has the new vtxos
	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	// 3 vtxo_ids: board + lightning change + revoked payment
	assert_eq!(recovery_ids.len(), 3, "recovery mailbox should have 3 vtxo_ids (board + change + revoked)");

	// Both vtxos should be in recovery mailbox
	for vtxo in &vtxos_after {
		assert!(recovery_ids.contains(&vtxo.id()), "vtxo {} should be in recovery mailbox", vtxo.id());
	}
}

/// Test that lightning receive claimed vtxo_ids are posted to recovery mailbox
#[tokio::test]
async fn recovery_mailbox_lightning_receive() {
	// Vtxo id based recovery is only supported later than beta.9
	require_bark_version!(> "0.1.0-beta.9");
	let ctx = TestContext::new("bark/recovery_mailbox_lightning_receive").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server linked to the receiver lightning node (for incoming payments)
	let srv = ctx.new_captaind_with_funds("server", Some(&lightning.receiver), btc(10)).await;

	// Start a bark and board to be able to receive lightning
	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	let mut mb_rpc = srv.get_mailbox_public_rpc().await;
	let bark_wallet = bark.client().await;

	// Get initial recovery mailbox count (should have board vtxo)
	let initial_recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	assert_eq!(initial_recovery_ids.len(), 1, "should have 1 vtxo_id from board");

	// Create an invoice to receive payment
	let pay_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;

	// Have sender pay the invoice
	let cloned_invoice = invoice_info.invoice.clone();
	let res = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice).await
	});

	srv.wait_for_vtxopool(&ctx).await;

	// Claim the lightning receive
	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;

	// Wait for payment to settle
	res.await.unwrap();

	// Get vtxos after receive - should have board vtxo + received vtxo
	let vtxos_after = bark_wallet.vtxos().await.unwrap();
	assert_eq!(vtxos_after.len(), 2, "bark should have 2 VTXOs after lightning receive (board + received)");

	// Find the received vtxo (the one with pay_amount)
	let received_vtxo = vtxos_after.iter().find(|v| v.amount() == pay_amount)
		.expect("should have a vtxo with pay_amount");

	// Check recovery mailbox has the received vtxo
	let recovery_ids = read_recovery_vtxo_ids(&mut mb_rpc, &bark_wallet).await;
	// 2 vtxo_ids: board + lightning received
	assert_eq!(recovery_ids.len(), 2, "recovery mailbox should have 2 vtxo_ids (board + lightning received)");
	assert!(recovery_ids.contains(&received_vtxo.id()), "lightning received vtxo_id should be in recovery mailbox");
}
