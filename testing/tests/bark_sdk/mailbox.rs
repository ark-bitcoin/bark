use std::time::Duration;

use futures::StreamExt;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;

use ark_testing::{TestContext, sat};

use server_rpc::protos::mailbox_server::mailbox_message::Message;

/// A fresh subscription must catch up on messages that were already in
/// the mailbox, not only relay messages posted while it is connected.
#[tokio::test]
async fn subscribe_delivers_preexisting_messages() {
	let ctx = TestContext::new("bark_sdk/subscribe_delivers_preexisting_messages").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv)
		.boarded(sat(400_000))
		.create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	// Post the message before anyone has ever subscribed to this mailbox.
	let sent_amount = sat(100_000);
	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sent_amount).await.expect("arkoor send");

	// Subscribe from explicit checkpoint 0: `None` would use the wallet's
	// stored checkpoint, which the receiver's own daemon mailbox stream
	// may already have advanced past the message.
	let mut stream = receiver.subscribe_mailbox_messages(Some(0)).await
		.expect("subscribe to mailbox");
	let msg = tokio::time::timeout(Duration::from_secs(30), stream.next()).await
		.expect("timed out waiting for pre-existing mailbox message")
		.expect("stream closed without delivering message")
		.expect("error on mailbox stream");
	match msg.message.as_ref().unwrap() {
		Message::Arkoor(arkoor) => {
			assert_eq!(arkoor.vtxos.len(), 1);
			let vtxo = Vtxo::<Full, VtxoPolicy>::deserialize(&arkoor.vtxos[0]).unwrap();
			assert_eq!(vtxo.amount(), sent_amount);
		},
		_ => panic!("unexpected message type"),
	}
}
