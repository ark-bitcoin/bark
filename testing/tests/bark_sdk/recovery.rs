use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::fs;

use ark::VtxoId;
use bark::vtxo::VtxoState;
use server_rpc::protos;

use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};

/// The gap limit must tolerate a run of unused key indices *between* matches,
/// not only before the first one.
///
/// Two VTXOs sit exactly `vtxo_key_gap_limit` unused indices apart, so the scan
/// matches the first and then has to cross the whole run to reach the second. A
/// window that stops at the end of that run instead of one past it leaves the
/// second VTXO behind.
#[tokio::test]
async fn recovery_finds_vtxos_separated_by_the_gap_limit() {
	const GAP: u32 = 2;

	let ctx = TestContext::new("bark_sdk/recovery_finds_vtxos_separated_by_the_gap_limit").await;
	let srv = ctx.captaind("server").create().await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv).create().await;

	// Receive into one key, reveal GAP more without receiving into them, then
	// receive into the key just past that run.
	let (first, first_idx) = target.new_address_with_index().await.expect("new address");
	for _ in 0..GAP {
		target.new_address().await.expect("new address");
	}
	let (second, second_idx) = target.new_address_with_index().await.expect("new address");
	assert_eq!(second_idx, first_idx + GAP + 1,
		"the two receiving keys must be exactly GAP unused indices apart",
	);

	source.send_arkoor_payment(&first, sat(10_000)).await.expect("arkoor send");
	source.send_arkoor_payment(&second, sat(20_000)).await.expect("arkoor send");
	target.sync().await;
	assert_eq!(target.spendable_vtxos().await.expect("list target vtxos").len(), 2,
		"target should hold both received vtxos",
	);

	// Recover from the same seed at that gap limit. Nothing but the scan can
	// find the second vtxo: the arkoor mailbox delivery is refused for a key
	// the wallet has not revealed.
	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.cfg(|c| c.vtxo_key_gap_limit = GAP)
		.create().await;

	let recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(recovered_ids.len(), 2,
		"both vtxos should be recovered, got {recovered_ids:?}",
	);
}

/// Acknowledges every post to the recovery mailbox without forwarding it, so the
/// recovery mailbox stays empty while the wallet believes its ids are backed up.
#[derive(Clone)]
struct SwallowRecoveryPosts;

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for SwallowRecoveryPosts {
	async fn post_recovery_vtxo_ids(
		&self,
		_upstream: &mut MailboxClient,
		_req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		Ok(protos::core::Empty {})
	}
}

/// A wallet recovered from its seed must not hold a vtxo it already spent.
///
/// The target's ids never reach the recovery mailbox, so the vtxo it receives is
/// only known to the regular mailbox. It spends that vtxo in full, and the
/// wallet recovered from the same seed must still show it as spent.
#[tokio::test]
async fn recovered_wallet_keeps_spent_vtxo_spent() {
	let ctx = TestContext::new("bark_sdk/recovered_wallet_keeps_spent_vtxo_spent").await;
	let srv = ctx.captaind("server").create().await;

	// The server acknowledges the recovery posts but stores nothing, so the
	// wallet has no way to notice its ids never got backed up.
	let proxy = srv.start_proxy_with_mailbox((), SwallowRecoveryPosts).await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &proxy).create().await;

	let target_address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&target_address, sat(100_000)).await.expect("arkoor send");
	target.sync().await;

	let received = target.spendable_vtxos().await.expect("list target vtxos");
	assert_eq!(received.len(), 1, "target should hold exactly the received vtxo");
	let vtxo_a = received[0].id();

	// Send the whole amount back, so the target keeps nothing.
	let back = source.new_address().await.expect("new address");
	target.send_arkoor_payment(&back, sat(100_000)).await.expect("arkoor send back");

	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	drop(target);

	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.sync().await;

	let states = recovered.all_vtxos().await.expect("list recovered vtxos")
		.into_iter().map(|v| (v.id(), v.state)).collect::<HashMap<_, _>>();
	assert_eq!(states.get(&vtxo_a), Some(&VtxoState::Spent),
		"the spent vtxo must stay spent after recovery, got {states:?}",
	);
}

/// A wallet recovered from its seed must show every input of a multi-input
/// arkoor send as spent.
#[tokio::test]
async fn recovered_wallet_keeps_arkoor_batch_inputs_spent() {
	let ctx = TestContext::new("bark_sdk/recovered_wallet_keeps_arkoor_batch_inputs_spent").await;
	let srv = ctx.captaind("server").create().await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv).create().await;

	let target_address = target.new_address().await.expect("new address");
	for _ in 0..10 {
		source.send_arkoor_payment(&target_address, sat(1_000)).await.expect("arkoor send");
	}
	target.sync().await;

	// Spend everything in a single arkoor send, leaving no change.
	let back = source.new_address().await.expect("new address");
	target.send_arkoor_payment(&back, sat(10_000)).await.expect("arkoor send back");

	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	drop(target);

	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.sync().await;

	let vtxos = recovered.all_vtxos().await.expect("list recovered vtxos");
	// One arkoor receive might have been delivered as multiple vtxos.
	assert!(vtxos.len() >= 10, "expected at least ten vtxos, got {}", vtxos.len());
	for vtxo in vtxos {
		assert_eq!(vtxo.state, VtxoState::Spent, "vtxo {} must be spent", vtxo.id());
	}
}

async fn read_mnemonic(ctx: &TestContext, wallet: &str) -> bip39::Mnemonic {
	let mnemonic = fs::read_to_string(ctx.datadir.join(wallet).join("mnemonic")).await
		.expect("mnemonic file");
	bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic")
}

#[derive(Default)]
struct VtxoRpcCounts {
	get_vtxo: AtomicUsize,
	get_vtxo_status: AtomicUsize,
	get_vtxos_by_ids: AtomicUsize,
	get_vtxos_status_by_ids: AtomicUsize,
}

/// Counts the vtxo lookup rpcs and fails the first `fail_status_batches`
/// GetVtxosStatusByIds requests with Unavailable.
#[derive(Clone)]
struct CountVtxoRpcs {
	counts: Arc<VtxoRpcCounts>,
	fail_status_batches: Arc<AtomicUsize>,
}

impl CountVtxoRpcs {
	fn new(counts: &Arc<VtxoRpcCounts>, fail_status_batches: usize) -> Self {
		Self {
			counts: counts.clone(),
			fail_status_batches: Arc::new(AtomicUsize::new(fail_status_batches)),
		}
	}
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for CountVtxoRpcs {
	async fn get_vtxo(
		&self, upstream: &mut ArkClient, req: protos::GetVtxoRequest,
	) -> Result<protos::GetVtxoResponse, tonic::Status> {
		self.counts.get_vtxo.fetch_add(1, Ordering::Relaxed);
		Ok(upstream.get_vtxo(req).await?.into_inner())
	}

	async fn get_vtxo_status(
		&self, upstream: &mut ArkClient, req: protos::GetVtxoStatusRequest,
	) -> Result<protos::GetVtxoStatusResponse, tonic::Status> {
		self.counts.get_vtxo_status.fetch_add(1, Ordering::Relaxed);
		Ok(upstream.get_vtxo_status(req).await?.into_inner())
	}

	async fn get_vtxos_by_ids(
		&self, upstream: &mut ArkClient, req: protos::GetVtxosByIdsRequest,
	) -> Result<protos::GetVtxosByIdsResponse, tonic::Status> {
		self.counts.get_vtxos_by_ids.fetch_add(1, Ordering::Relaxed);
		Ok(upstream.get_vtxos_by_ids(req).await?.into_inner())
	}

	async fn get_vtxos_status_by_ids(
		&self, upstream: &mut ArkClient, req: protos::GetVtxosStatusByIdsRequest,
	) -> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status> {
		self.counts.get_vtxos_status_by_ids.fetch_add(1, Ordering::Relaxed);
		let fail = self.fail_status_batches
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
		if fail.is_ok() {
			return Err(tonic::Status::unavailable("status batch dropped by test proxy"));
		}
		Ok(upstream.get_vtxos_status_by_ids(req).await?.into_inner())
	}
}

/// Recovery resolves the VTXOs of a mailbox page with the batch rpcs, not
/// with one request per VTXO.
#[tokio::test]
async fn recovery_uses_batch_rpcs() {
	let ctx = TestContext::new("bark_sdk/recovery_uses_batch_rpcs").await;
	// The xpub lookup carries each VTXO's body and status itself, so it is
	// turned off to send recovery through the mailbox path under test.
	let srv = ctx.captaind("server")
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	// The boards post their ids to the recovery mailbox; the arkoor receive
	// leaves its body in the regular mailbox. Both must go through the batch
	// rpcs.
	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv)
		.boarded(sat(100_000))
		.boarded(sat(200_000))
		.boarded(sat(300_000))
		.create().await;
	let address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&address, sat(10_000)).await.expect("arkoor send");
	target.sync().await;
	let mut expected = target.spendable_vtxos().await.expect("list target vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	expected.sort();
	assert!(expected.len() >= 4, "expected at least four vtxos, got {}", expected.len());

	let counts = Arc::new(VtxoRpcCounts::default());
	let proxy = srv.start_proxy_with_mailbox(CountVtxoRpcs::new(&counts, 0), ()).await;

	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(read_mnemonic(&ctx, "target").await)
		.create().await;

	let mut recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, expected, "every vtxo must be recovered spendable");

	assert_eq!(counts.get_vtxo.load(Ordering::Relaxed), 0,
		"recovery must not fetch vtxo bodies one by one");
	assert_eq!(counts.get_vtxo_status.load(Ordering::Relaxed), 0,
		"recovery must not query vtxo status one by one");
	assert!(counts.get_vtxos_by_ids.load(Ordering::Relaxed) >= 1,
		"recovery must fetch the boarded vtxo bodies in batch");
	assert!(counts.get_vtxos_status_by_ids.load(Ordering::Relaxed) >= 1,
		"recovery must query vtxo status in batch");
}

/// A failed status batch leaves its VTXOs failed, and a retry pass asks for
/// them again in batch.
#[tokio::test]
async fn recovery_retries_a_failed_status_batch() {
	let ctx = TestContext::new("bark_sdk/recovery_retries_a_failed_status_batch").await;
	// The xpub lookup carries each VTXO's body and status itself, so it is
	// turned off to send recovery through the mailbox path under test.
	let srv = ctx.captaind("server")
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let target = ctx.bark_sdk("target", &srv)
		.boarded(sat(100_000))
		.boarded(sat(200_000))
		.create().await;
	let mut expected = target.spendable_vtxos().await.expect("list target vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	expected.sort();
	assert_eq!(expected.len(), 2);

	let counts = Arc::new(VtxoRpcCounts::default());
	let proxy = srv.start_proxy_with_mailbox(CountVtxoRpcs::new(&counts, 1), ()).await;

	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(read_mnemonic(&ctx, "target").await)
		.create().await;

	let mut recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, expected, "the retry pass must recover every vtxo");
	assert!(counts.get_vtxos_status_by_ids.load(Ordering::Relaxed) >= 2,
		"the retry pass must query vtxo status in batch again");
	assert_eq!(counts.get_vtxo_status.load(Ordering::Relaxed), 0,
		"a failed batch must not fall back to single status requests");
}

/// An id in the recovery mailbox the server does not know is reported as
/// missing, and the other VTXOs of the same batch are still recovered.
#[tokio::test]
async fn recovery_tolerates_an_unknown_vtxo_id() {
	let ctx = TestContext::new("bark_sdk/recovery_tolerates_an_unknown_vtxo_id").await;
	let srv = ctx.captaind("server").create().await;

	let target = ctx.bark_sdk("target", &srv)
		.boarded(sat(100_000))
		.boarded(sat(200_000))
		.create().await;
	let mut expected = target.spendable_vtxos().await.expect("list target vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	expected.sort();
	assert_eq!(expected.len(), 2);

	// Inject a well-formed id no server has ever seen into every mailbox read.
	#[derive(Clone)]
	struct InjectUnknownId { unknown: VtxoId }

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InjectUnknownId {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, MailboxMessage, RecoveryVtxoIdsMessage};

			let mut resp = upstream.read_mailbox(req).await?.into_inner();
			resp.messages.push(MailboxMessage {
				message: Some(mailbox_message::Message::RecoveryVtxoIds(RecoveryVtxoIdsMessage {
					vtxo_ids: vec![self.unknown.to_bytes().to_vec()],
				})),
				checkpoint: 0,
			});
			Ok(resp)
		}
	}

	let unknown = VtxoId::from_slice(&[0u8; 36]).unwrap();
	let proxy = srv.start_proxy_with_mailbox((), InjectUnknownId { unknown }).await;

	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(read_mnemonic(&ctx, "target").await)
		.create().await;

	let mut recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, expected, "the known vtxos of the batch must be recovered");
	assert!(recovered.all_vtxos().await.expect("list all vtxos").iter().all(|v| v.id() != unknown),
		"the unknown id must not be stored");
}
