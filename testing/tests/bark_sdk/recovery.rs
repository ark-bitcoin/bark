use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::fs;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use bark::actions::recovery;
use bark::vtxo::VtxoState;
use server_rpc::protos;

use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use ark_testing::util::action_drive_factor;

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

/// Serves the first `allowed` mailbox reads with the signature of every arkoor
/// body broken, and fails every read after them.
#[derive(Clone)]
struct BreakArkoorSignatures {
	allowed: Arc<AtomicUsize>,
	broken: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for BreakArkoorSignatures {
	async fn read_mailbox(
		&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
	) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
		use protos::mailbox_server::mailbox_message::Message;

		let allowed = self.allowed
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
		if allowed.is_err() {
			return Err(tonic::Status::unavailable("mailbox down"));
		}

		let mut resp = upstream.read_mailbox(req).await?.into_inner();
		for msg in &mut resp.messages {
			let Some(Message::Arkoor(arkoor)) = &mut msg.message else { continue };
			for raw in &mut arkoor.vtxos {
				let mut vtxo = Vtxo::<Full>::deserialize(raw).expect("decode arkoor vtxo");
				vtxo.invalidate_final_sig();
				*raw = vtxo.serialize();
				self.broken.fetch_add(1, Ordering::Relaxed);
			}
		}
		Ok(resp)
	}
}

/// An arkoor body the mailbox serves is only as good as its relay, so recovery
/// must not store one that fails validation, not even locked.
///
/// The target's ids never reach the recovery mailbox and the xpub lookup is
/// off, so the regular mailbox is the only place the recovery hears of the
/// vtxo, and it hears of it with a broken signature. The read of the recovery
/// mailbox then fails, so the recovery stops before the server is asked about
/// anything it staged.
#[tokio::test]
async fn recovery_drops_an_invalid_arkoor_body_from_the_mailbox() {
	let ctx = TestContext::new("bark_sdk/recovery_drops_an_invalid_arkoor_body_from_the_mailbox").await;
	let srv = ctx.captaind("server")
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let target_proxy = srv.start_proxy_with_mailbox((), SwallowRecoveryPosts).await;
	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &target_proxy).create().await;

	let target_address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&target_address, sat(100_000)).await.expect("arkoor send");
	target.sync().await;
	assert_eq!(target.spendable_vtxos().await.expect("list target vtxos").len(), 1,
		"target should hold exactly the received vtxo");

	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	drop(target);

	// Only the regular mailbox read goes through, once per drive of its step.
	let broken = Arc::new(AtomicUsize::new(0));
	let mailbox = BreakArkoorSignatures {
		allowed: Arc::new(AtomicUsize::new(action_drive_factor())),
		broken: broken.clone(),
	};
	let proxy = srv.start_proxy_with_mailbox((), mailbox).await;
	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(mnemonic)
		.create().await;

	assert!(broken.load(Ordering::Relaxed) > 0, "the recovery must have read the arkoor body");
	let stored = recovered.all_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert!(stored.is_empty(), "an invalid arkoor body must not be stored, got {stored:?}");
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
	let proxy = srv.start_proxy_with_mailbox(CountVtxoRpcs::new(&counts, action_drive_factor()), ()).await;

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

/// Recovering by id retries a VTXO that is locked without a holder, as a
/// recovery of an earlier version left one whose status it did not get.
#[tokio::test]
async fn recover_vtxos_retries_a_vtxo_locked_without_a_holder() {
	let ctx = TestContext::new("bark_sdk/recover_vtxos_retries_a_vtxo_locked_without_a_holder").await;
	let srv = ctx.captaind("server").create().await;

	let wallet = ctx.bark_sdk("wallet", &srv).boarded(sat(100_000)).create().await;
	let vtxos = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(vtxos.len(), 1);
	let id = vtxos[0].id();

	wallet.lock_vtxos([id], None).await.expect("lock vtxo");
	assert!(wallet.spendable_vtxos().await.expect("list vtxos").is_empty());

	let report = wallet.recover_vtxos([id], None).await.expect("recover by id");
	assert_eq!(report.recovered().len(), 1, "the locked vtxo must be recovered: {:?}", report);
	let spendable = wallet.spendable_vtxos().await.expect("list vtxos");
	assert_eq!(spendable.len(), 1, "the locked vtxo must be spendable again");
	assert_eq!(spendable[0].id(), id);
}

/// Sync `wallet` until it has no recovery in progress.
async fn sync_until_recovered(wallet: &bark::Wallet) {
	for _ in 0..30 {
		wallet.sync().await;
		if wallet.pending_recovery().await.expect("read pending recovery").is_none() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	let pending = wallet.pending_recovery().await.expect("read pending recovery");
	panic!("recovery still in progress after syncing: {:?}", pending);
}

/// Serves the first `allowed` mailbox reads, then fails every read while `down`
/// is set.
#[derive(Clone)]
struct FlakyMailbox {
	allowed: Arc<AtomicUsize>,
	down: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for FlakyMailbox {
	async fn read_mailbox(
		&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
	) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
		let allowed = self.allowed
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
		if allowed.is_err() && self.down.load(Ordering::Relaxed) {
			return Err(tonic::Status::unavailable("mailbox down"));
		}
		Ok(upstream.read_mailbox(req).await?.into_inner())
	}
}

/// A recovery stopped by a failed mailbox read resumes from the mailbox page it
/// was on, keeping what the earlier pages staged.
///
/// The regular mailbox is read, then the recovery mailbox read fails, so the
/// open leaves a checkpoint at the start of the recovery mailbox with the arkoor
/// vtxo of the regular mailbox staged. Once the mailbox is back, a sync finishes
/// the recovery.
#[tokio::test]
async fn recovery_resumes_after_a_failed_mailbox_read() {
	let ctx = TestContext::new("bark_sdk/recovery_resumes_after_a_failed_mailbox_read").await;
	// The xpub lookup carries each VTXO's body and status itself, so it is
	// turned off to send recovery through the mailbox path under test.
	let srv = ctx.captaind("server")
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv)
		.boarded(sat(100_000))
		.boarded(sat(200_000))
		.create().await;
	let address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&address, sat(10_000)).await.expect("arkoor send");
	target.sync().await;
	let mut expected = target.spendable_vtxos().await.expect("list target vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	expected.sort();
	assert!(expected.len() >= 3, "expected at least three vtxos, got {}", expected.len());

	// Only the regular mailbox read goes through, once per drive of its step.
	let down = Arc::new(AtomicBool::new(true));
	let mailbox = FlakyMailbox { allowed: Arc::new(AtomicUsize::new(action_drive_factor())), down: down.clone() };
	let proxy = srv.start_proxy_with_mailbox((), mailbox).await;

	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(read_mnemonic(&ctx, "target").await)
		.create().await;

	let pending = recovered.pending_recovery().await.expect("read pending recovery")
		.expect("a recovery stopped by a failed read must stay in progress");
	assert_eq!(pending.progress, recovery::Progress::Scanning {
		mailbox: recovery::RecoveryMailbox::Recovery,
		checkpoint: 0,
	}, "the recovery must resume at the start of the recovery mailbox");
	assert!(!pending.report.failed().is_empty(),
		"the arkoor vtxo of the regular mailbox must be staged");
	assert!(recovered.spendable_vtxos().await.expect("list recovered vtxos").is_empty(),
		"no vtxo may be spendable before the server gave its status");

	down.store(false, Ordering::Relaxed);
	sync_until_recovered(&recovered).await;

	let mut recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, expected, "the resumed recovery must recover every vtxo");
}

/// A recovery whose status requests keep failing stays in progress with its
/// vtxos locked, and a sync finishes it once the server answers.
#[tokio::test]
async fn recovery_resumes_failed_status_batches_on_sync() {
	let ctx = TestContext::new("bark_sdk/recovery_resumes_failed_status_batches_on_sync").await;
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

	#[derive(Clone)]
	struct StatusDown(Arc<AtomicBool>);

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for StatusDown {
		async fn get_vtxos_status_by_ids(
			&self, upstream: &mut ArkClient, req: protos::GetVtxosStatusByIdsRequest,
		) -> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status> {
			if self.0.load(Ordering::Relaxed) {
				return Err(tonic::Status::unavailable("status down"));
			}
			Ok(upstream.get_vtxos_status_by_ids(req).await?.into_inner())
		}
	}

	let down = Arc::new(AtomicBool::new(true));
	let proxy = srv.start_proxy_with_mailbox(StatusDown(down.clone()), ()).await;

	let recovered = ctx.bark_sdk("recovered", &proxy)
		.mnemonic(read_mnemonic(&ctx, "target").await)
		.create().await;

	let pending = recovered.pending_recovery().await.expect("read pending recovery")
		.expect("a recovery without status answers must stay in progress");
	assert!(matches!(pending.progress, recovery::Progress::Resolving { .. }),
		"both mailboxes are read, only the status is missing, got {:?}", pending.progress);
	let mut failed = pending.report.failed().ids().collect::<Vec<_>>();
	failed.sort();
	assert_eq!(failed, expected, "every vtxo must be reported failed");
	for vtxo in recovered.all_vtxos().await.expect("list recovered vtxos") {
		assert!(matches!(vtxo.state, VtxoState::Locked { .. }),
			"vtxo {} must stay locked without a status, got {:?}", vtxo.id(), vtxo.state);
	}

	down.store(false, Ordering::Relaxed);
	sync_until_recovered(&recovered).await;

	let mut recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, expected, "the resumed recovery must recover every vtxo");
}
