use std::str::FromStr;
use std::time::Duration;

use futures::StreamExt;
use tokio::fs;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;

use ark_testing::{TestContext, sat};
use server::database::Db;

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

/// The recovery scan reads a seed-derived mailbox that is separate from the
/// wallet's regular event mailbox, but both share the server's global
/// monotonically-increasing checkpoint sequence. Recovery must therefore
/// never advance the regular mailbox cursor: if it did, the next regular
/// sync would silently skip every regular-mailbox event (incoming Lightning
/// notifications, round-completion messages, ...) that happened at or below
/// the recovery cursor value.
#[tokio::test]
async fn recovery_leaves_regular_mailbox_checkpoint_untouched() {
	let ctx = TestContext::new("bark_sdk/recovery_leaves_regular_mailbox_checkpoint_untouched").await;
	let srv = ctx.captaind("server").create().await;

	// Board vtxos are stored fully signed by board registration itself, so
	// the recovery mailbox is only populated for offchain-created vtxos.
	// Give the target wallet an arkoor-received vtxo so its recovery
	// mailbox has an entry with a nonzero server-side checkpoint: that is
	// the value that used to leak into the regular cursor.
	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv).create().await;

	let sent_amount = sat(100_000);
	let target_address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&target_address, sent_amount).await.expect("arkoor send");

	// Target must run a sync so it consumes the arkoor and posts its id to
	// the recovery mailbox. Assert directly that the server received a
	// recovery entry with a nonzero checkpoint so the regression assertion
	// below can't pass vacuously against an empty mailbox.
	target.sync().await;
	let target_vtxos = target.spendable_vtxos().await.expect("list target vtxos");
	assert_eq!(target_vtxos.len(), 1, "target should hold the arkoor-received vtxo");
	let vtxo_id = target_vtxos[0].id().to_string();

	let db = Db::connect(&srv.config().postgres).await.expect("connect to captaind postgres");
	let recovery_checkpoint: i64 = db.read(async |t| {
		let row = t.query_one(
			"SELECT checkpoint FROM mailbox \
			 WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1",
			&[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.expect("recovery mailbox entry must exist for the arkoor-received vtxo");
	assert!(recovery_checkpoint > 0,
		"recovery-mailbox entry should carry a nonzero server checkpoint, got {recovery_checkpoint}",
	);

	// Recover from the same seed into a fresh in-process wallet. The open
	// call runs recover_from_mailbox as part of its create-if-not-exists
	// path (bark/src/lib.rs); the recovery mailbox above will feed it the
	// vtxo id.
	let target_mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(target_mnemonic.trim()).expect("parse mnemonic");
	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	// Sanity: recovery did pull the vtxo through the recovery-mailbox path.
	let recovered_vtxos = recovered.spendable_vtxos().await.expect("list recovered vtxos");
	assert_eq!(recovered_vtxos.len(), 1, "recovered wallet should hold the arkoor vtxo");
	assert_eq!(recovered_vtxos[0].id().to_string(), vtxo_id);

	// The regression check: the regular mailbox cursor must still be zero.
	// Prior to the fix, recovery persisted its internal paging cursor here,
	// which is the server's global checkpoint (necessarily > 0 after the
	// arkoor traffic above), silently causing later regular syncs to skip
	// every event up to that value.
	let checkpoint = recovered.get_mailbox_checkpoint().await
		.expect("read recovered mailbox checkpoint");
	assert_eq!(checkpoint, 0,
		"recovery must not advance the regular mailbox checkpoint (got {checkpoint})",
	);
}
