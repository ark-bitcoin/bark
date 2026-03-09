use std::io::{self, BufRead};
use std::time::Duration;

use ark::{ProtocolEncoding, Vtxo};
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, MailboxClient};

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
			let message = match response.messages[0].message.as_ref().unwrap() {
				mailbox_message::Message::Arkoor(ArkoorMessage { vtxos }) => {
					let mut vtxo = Vtxo::deserialize(&vtxos[0]).unwrap();
					vtxo.invalidate_final_sig();
					ArkoorMessage { vtxos: vec![vtxo.serialize()] }
				},
			};

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
