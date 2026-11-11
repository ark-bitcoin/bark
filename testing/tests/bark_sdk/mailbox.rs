use std::str::FromStr;
use std::time::Duration;

use futures::StreamExt;
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::vtxo::Full;

use ark_testing::{TestContext, sat};
use ark_testing::util::{FutureExt, poll_interval};
use bark::vtxo::VtxoState;
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
	// call starts the recovery action as part of its create-if-not-exists
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

/// An arkoor delivery outlives the VTXO it delivered: it stays in the mailbox
/// until its checkpoint advances, and a wallet restored from the same seed
/// starts from checkpoint 0 (see
/// [recovery_leaves_regular_mailbox_checkpoint_untouched]), so it reads every
/// delivery again. Nothing local tells that replay apart from a fresh receive,
/// so the receive used to store an already-spent VTXO back into the spendable
/// set, undoing the correct verdict recovery had just reached about it.
#[tokio::test]
async fn arkoor_receive_replay_does_not_restore_a_spent_vtxo() {
	let ctx = TestContext::new("bark_sdk/arkoor_receive_replay_does_not_restore_a_spent_vtxo").await;
	let srv = ctx.captaind("server").create().await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv).create().await;

	// Deliver an arkoor vtxo to the target and let it consume the delivery,
	// so the mailbox holds a message for a vtxo the target owns.
	let target_address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&target_address, sat(100_000)).await.expect("arkoor send");
	target.sync().await;
	let received = target.spendable_vtxos().await.expect("list target vtxos");
	assert_eq!(received.len(), 1, "target should hold the arkoor-received vtxo");
	let received_id = received[0].id();

	// Spend it, so the server now reports it as spent. The delivery for it is
	// still in the mailbox: only the target's checkpoint moved past it.
	let source_address = source.new_address().await.expect("new address");
	target.send_arkoor_payment(&source_address, sat(20_000)).await.expect("arkoor send back");
	assert!(
		!target.spendable_vtxos().await.expect("list target vtxos").iter()
			.any(|v| v.id() == received_id),
		"the spent vtxo should be gone from the target's spendable set",
	);

	// Restore from the same seed. Recovery decides correctly on the spent
	// vtxo (it asks the server), then the mailbox sync replays the delivery.
	let target_mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(target_mnemonic.trim()).expect("parse mnemonic");
	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.sync().await;

	assert!(
		!recovered.spendable_vtxos().await.expect("list recovered vtxos").iter()
			.any(|v| v.id() == received_id),
		"replaying the delivery must not restore the spent vtxo {received_id}",
	);

	// The replay is recorded rather than dropped, so the wallet keeps an
	// accurate history and the next replay is a no-op.
	let stored = recovered.get_vtxo_by_id(received_id).await
		.expect("the replayed vtxo should be stored");
	assert_eq!(stored.state, VtxoState::Spent);
}

/// A TCP forwarder whose established connections can be frozen: they stay
/// open but stop carrying bytes, like a connection whose network path died
/// without either end being told. Connections made afterwards work normally,
/// unless the proxy is set to refuse them, like a network that is still down.
struct FreezableTcpProxy {
	url: String,
	/// The number of times [Self::freeze_connections] was called.
	freezes: watch::Sender<u64>,
	/// Whether new connections are closed as soon as they are accepted.
	refusing: watch::Sender<bool>,
	/// The number of connections closed because the proxy was refusing.
	refused: watch::Sender<u64>,
}

impl FreezableTcpProxy {
	async fn start(upstream_url: &str) -> FreezableTcpProxy {
		let upstream = upstream_url.strip_prefix("http://").expect("http upstream").to_owned();
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp proxy");
		let url = format!("http://{}", listener.local_addr().expect("tcp proxy address"));
		let (freezes, _) = watch::channel(0);
		let (refusing, _) = watch::channel(false);
		let (refused, _) = watch::channel(0);

		let freezes_rx = freezes.subscribe();
		let refusing_rx = refusing.subscribe();
		let refused_tx = refused.clone();
		tokio::spawn(async move {
			loop {
				let (mut client, _) = listener.accept().await.expect("accept on tcp proxy");
				if *refusing_rx.borrow() {
					drop(client);
					refused_tx.send_modify(|refused| *refused += 1);
					continue;
				}
				let mut freezes = freezes_rx.clone();
				let accepted_at = *freezes.borrow();
				let upstream = upstream.clone();
				tokio::spawn(async move {
					let mut server = TcpStream::connect(&upstream).await
						.expect("connect to tcp proxy upstream");
					let frozen = tokio::select! {
						_ = tokio::io::copy_bidirectional(&mut client, &mut server) => false,
						_ = freezes.wait_for(|freezes| *freezes > accepted_at) => true,
					};
					if frozen {
						// Keep both sockets open without forwarding anything.
						std::future::pending::<()>().await;
					}
				});
			}
		});

		FreezableTcpProxy { url, freezes, refusing, refused }
	}

	/// Freeze every connection established so far.
	fn freeze_connections(&self) {
		self.freezes.send_modify(|freezes| *freezes += 1);
	}

	/// Close new connections as soon as they are accepted, or stop doing so.
	fn refuse_connections(&self, refuse: bool) {
		self.refusing.send_replace(refuse);
	}

	/// Wait until more than `count` connections were refused.
	async fn wait_for_refused_above(&self, count: u64) {
		self.refused.subscribe().wait_for(|refused| *refused > count).await
			.expect("sender is alive");
	}
}

/// Restarting the daemon leaves a working daemon behind, whether or not one
/// was running and whether or not the server is reachable at that moment,
/// and it does so on a new server connection: a connection that
/// silently died is only noticed once its keepalive times out, which takes
/// over a minute, and a payment waiting in the mailbox must not wait for that.
#[tokio::test]
async fn restart_daemon_resumes_mailbox_delivery() {
	let ctx = TestContext::new("bark_sdk/restart_daemon_resumes_mailbox_delivery").await;
	let srv = ctx.captaind("server").create().await;
	let proxy = FreezableTcpProxy::start(&srv.ark_url()).await;

	let sender = ctx.bark_sdk("sender", &srv)
		.boarded(sat(400_000))
		.create().await;
	// Long enough that the periodic connection check never runs, so only the
	// daemon's startup sync and its mailbox subscription can deliver a payment.
	let sync_interval = Duration::from_secs(24 * 60 * 60);
	let receiver = ctx.bark_sdk("receiver", &proxy.url)
		.cfg(move |cfg| cfg.daemon_sync_interval_secs = sync_interval.as_secs())
		.create().await;

	let wait_for_spendable = |expected, timeout| {
		let receiver = &receiver;
		async move {
			loop {
				let vtxos = receiver.spendable_vtxos().await.expect("list receiver VTXOs");
				if vtxos.iter().map(|v| v.amount()).sum::<bitcoin::Amount>() == expected {
					break;
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait(timeout)
	};

	// Restart a stopped daemon: a payment sent while it was stopped arrives.
	receiver.stop_daemon_wait().await.expect("stop daemon");
	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("first arkoor send");
	receiver.restart_daemon().expect("restart stopped daemon");
	wait_for_spendable(sat(100_000), Duration::from_secs(15)).await;

	// Restart a running daemon whose connection died. The address is
	// generated up front, because the wallet cannot reach the server once
	// its connection is frozen.
	let address = receiver.new_address().await.expect("new address");
	proxy.freeze_connections();
	sender.send_arkoor_payment(&address, sat(50_000)).await.expect("second arkoor send");
	receiver.restart_daemon().expect("restart running daemon");
	// Well below the time the keepalive needs to give up on the connection.
	wait_for_spendable(sat(150_000), Duration::from_secs(15)).await;

	// Restart while the network is still down, so the new connection fails
	// and only the frozen one is left. Connections are allowed again only
	// after two were refused, which the first attempt to replace it does not
	// survive, so the payment arrives in time only if the daemon tries again.
	let address = receiver.new_address().await.expect("new address");
	proxy.freeze_connections();
	proxy.refuse_connections(true);
	let refused = *proxy.refused.borrow();
	sender.send_arkoor_payment(&address, sat(25_000)).await.expect("third arkoor send");
	receiver.restart_daemon().expect("restart running daemon");
	proxy.wait_for_refused_above(refused + 1).wait(Duration::from_secs(15)).await;
	proxy.refuse_connections(false);
	wait_for_spendable(sat(175_000), Duration::from_secs(15)).await;
}
