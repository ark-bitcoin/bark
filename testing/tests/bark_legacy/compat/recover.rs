use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::fs;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use bark::BarkNetwork;
use bitcoin_ext::BlockHeight;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, require_bark_version, sat, Bark, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::exit::complete_exit;
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use ark_testing::util::{get_bark_chain_source_from_env, TestContextChainSource};

#[ignore] // we removed this functionality, might be added again later
#[tokio::test]
async fn recover_mnemonic() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("bark/recover_mnemonic").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(2_000_000)).create().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// make sure we have a round and an board vtxo (arkoor doesn't work)
	bark.refresh_all().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let onchain = bark.onchain_balance().await;
	let _offchain = bark.spendable_balance().await;

	const MNEMONIC_FILE: &str = "mnemonic";
	let mnemonic = fs::read_to_string(bark.datadir().join(MNEMONIC_FILE)).await.unwrap();
	let _ = bip39::Mnemonic::parse(&mnemonic).expect("invalid mnemonic?");

	// first ensure we need to set a birthday for bitcoin core
	let bitcoind = if ctx.electrs.is_none() {
		Some(Arc::new(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await))
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_no_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_deref());
	let result = Bark::try_new_with_create_opts(
		"bark_recovered_no_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		None,
		true,
		None,
	).await;

	match get_bark_chain_source_from_env() {
		TestContextChainSource::BitcoinCore => {
			// it's not easy to get a grip of what the actual error was
			assert!(result.expect_err("--birthday-height should be required").to_string().contains(
				"You need to set the --birthday-height field when recovering from mnemonic.",
			));
		}
		_ => {
			let balance = result
				.expect("mnemonic should work without birthday")
				.onchain_balance()
				.await;
			assert_eq!(onchain, balance);
		}
	}

	// Now check that specifying a birthday height always succeeds
	let bitcoind = if ctx.electrs.is_none() {
		Some(Arc::new(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await))
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_with_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_deref());
	let recovered = Bark::try_new_with_create_opts(
		"bark_recovered_with_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		Some(BlockHeight::new(0)),
		true,
		None,
	).await.expect("mnemonic + birthday should work");
	assert_eq!(onchain, recovered.onchain_balance().await);
	//TODO(stevenroose) implement offchain recovery
	// assert_eq!(offchain, recovered.offchain_balance().await);
}

/// A vtxo whose recovery post and registration were lost (e.g. the wallet
/// crashed or went offline at store time) must be caught up by the next
/// wallet sync: its ID posted to the recovery mailbox and its fully-signed
/// transaction chain stored server-side. Once caught up, the vtxo is marked
/// registered and later syncs skip it entirely.
#[tokio::test]
async fn recovery_state_catches_up_on_sync() {
	let ctx = TestContext::new("bark/recovery_state_catches_up_on_sync").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Proxy that, while enabled, pretends registrations succeeded without
	// forwarding them and fails recovery mailbox posts, so the flows below
	// leave no recovery state on the server and no vtxo gets marked
	// registered from a fake success. Forwarded mailbox posts are counted
	// so the test can assert that a caught-up wallet stops posting.
	#[derive(Clone)]
	struct DropRecovery {
		enabled: Arc<AtomicBool>,
		posts: Arc<std::sync::atomic::AtomicUsize>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for DropRecovery {
		async fn register_vtxo_transactions(
			&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.enabled.load(Ordering::Relaxed) {
				Ok(protos::Empty {})
			} else {
				Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
			}
		}
	}
	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for DropRecovery {
		async fn post_recovery_vtxo_ids(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
		) -> Result<protos::core::Empty, tonic::Status> {
			if self.enabled.load(Ordering::Relaxed) {
				Err(tonic::Status::unavailable("recovery post dropped by test proxy"))
			} else {
				self.posts.fetch_add(1, Ordering::Relaxed);
				Ok(upstream.post_recovery_vtxo_ids(req).await?.into_inner())
			}
		}
	}

	let dropping = Arc::new(AtomicBool::new(true));
	let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_with_mailbox(
		DropRecovery { enabled: dropping.clone(), posts: posts.clone() },
		DropRecovery { enabled: dropping.clone(), posts: posts.clone() },
	).await;

	// NB board vtxos are stored fully signed by board registration itself,
	// so the recovery mechanism only matters for offchain-created vtxos:
	// receive one via arkoor.
	let bark1 = ctx.bark("bark1", &proxy.address).funded(sat(90_000)).create().await;
	let bark2 = ctx.bark("bark2", &proxy.address).funded(sat(5_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	let addr2 = bark2.address().await;
	bark1.send_oor(&addr2, sat(20_000)).await;

	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	let vtxo_id = vtxos[0].id.to_string();

	// The drops left the vtxo unregistered server-side and the mailbox empty.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text FROM vtxo WHERE vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "unregistered");
	let mailbox_rows = db.read(async |t| {
		let row = t.query_one(
			"SELECT COUNT(*) FROM mailbox WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(mailbox_rows, 0);

	// Let calls through again; any syncing bark command catches up the
	// recovery state.
	dropping.store(false, Ordering::Relaxed);
	bark2.vtxos().await;

	let (state, blob) = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text, vtxo FROM vtxo WHERE vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok((row.get::<_, String>(0), row.get::<_, Vec<u8>>(1)))
	}).await.unwrap();
	assert_eq!(state, "spendable");
	let stored = Vtxo::<Full>::deserialize(&blob).expect("stored vtxo should parse");
	assert!(stored.has_all_witnesses(), "stored vtxo should be fully signed");

	let mailbox_rows = db.read(async |t| {
		let row = t.query_one(
			"SELECT COUNT(*) FROM mailbox WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(mailbox_rows, 1);

	// The catch-up marked the vtxo registered, so another sync skips it:
	// no new mailbox post reaches the server at all.
	let posts_after_catchup = posts.load(Ordering::Relaxed);
	bark2.vtxos().await;
	assert_eq!(posts.load(Ordering::Relaxed), posts_after_catchup,
		"a caught-up wallet should not re-post recovery vtxo IDs",
	);
	let mailbox_rows = db.read(async |t| {
		let row = t.query_one(
			"SELECT COUNT(*) FROM mailbox WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(mailbox_rows, 1);
}

/// One permanently-rejected vtxo must not block the catch-up for the others:
/// the endpoint rejects a batch wholesale, so a rejected chunk is retried
/// per vtxo.
#[tokio::test]
async fn recovery_catchup_survives_rejected_vtxo() {
	let ctx = TestContext::new("bark/recovery_catchup_survives_rejected_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// While `dropping`, registrations are pretended successful without
	// forwarding and recovery mailbox posts fail (so no vtxo gets marked
	// registered from a fake success); while `reject` is set, any
	// registration request containing that vtxo is rejected instead.
	#[derive(Clone)]
	struct SelectiveProxy {
		dropping: Arc<AtomicBool>,
		reject: Arc<Mutex<Option<VtxoId>>>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for SelectiveProxy {
		async fn register_vtxo_transactions(
			&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.dropping.load(Ordering::Relaxed) {
				return Ok(protos::Empty {});
			}
			if let Some(reject) = *self.reject.lock().unwrap() {
				let contains_rejected = req.vtxos.iter().any(|v| {
					Vtxo::<Full>::deserialize(v).expect("invalid vtxo in request").id() == reject
				});
				if contains_rejected {
					return Err(tonic::Status::invalid_argument("rejected by test proxy"));
				}
			}
			Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
		}
	}
	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for SelectiveProxy {
		async fn post_recovery_vtxo_ids(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
		) -> Result<protos::core::Empty, tonic::Status> {
			if self.dropping.load(Ordering::Relaxed) {
				return Err(tonic::Status::unavailable("recovery post dropped by test proxy"));
			}
			Ok(upstream.post_recovery_vtxo_ids(req).await?.into_inner())
		}
	}

	let dropping = Arc::new(AtomicBool::new(true));
	let reject = Arc::new(Mutex::new(None));
	let proxy = srv.start_proxy_with_mailbox(
		SelectiveProxy { dropping: dropping.clone(), reject: reject.clone() },
		SelectiveProxy { dropping: dropping.clone(), reject: reject.clone() },
	).await;

	let bark1 = ctx.bark("bark1", &proxy.address).funded(sat(90_000)).create().await;
	let bark2 = ctx.bark("bark2", &proxy.address).funded(sat(5_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	let addr2 = bark2.address().await;
	bark1.send_oor(&addr2, sat(20_000)).await;

	// The drop also left bark1's change unregistered, which the server would
	// reject as input of the second send. Let bark1's own sync-time
	// catch-up register it, then drop again.
	dropping.store(false, Ordering::Relaxed);
	bark1.vtxos().await;
	dropping.store(true, Ordering::Relaxed);

	bark1.send_oor(&addr2, sat(10_000)).await;

	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 2);
	let poison = vtxos[0].id;
	let healthy = vtxos[1].id;

	// Let calls through again, except any registration involving `poison`.
	*reject.lock().unwrap() = Some(poison);
	dropping.store(false, Ordering::Relaxed);
	bark2.vtxos().await;

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (state, blob) = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text, vtxo FROM vtxo WHERE vtxo_id = $1",
			&[&healthy.to_string()],
		).await?;
		Ok((row.get::<_, String>(0), row.get::<_, Vec<u8>>(1)))
	}).await.unwrap();
	assert_eq!(state, "spendable");
	let stored = Vtxo::<Full>::deserialize(&blob).expect("stored vtxo should parse");
	assert!(stored.has_all_witnesses(), "healthy vtxo should be fully signed");

	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text FROM vtxo WHERE vtxo_id = $1",
			&[&poison.to_string()],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "unregistered");

	// Once the rejection clears, the next sync catches up the remaining vtxo.
	*reject.lock().unwrap() = None;
	bark2.vtxos().await;
	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text FROM vtxo WHERE vtxo_id = $1",
			&[&poison.to_string()],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "spendable");
}

/// An exited vtxo whose recovery state never reached the server must still be
/// backed up by the sync-time catch-up: broadcasting the exit transactions
/// doesn't mean the user claimed the resulting on-chain outputs, so a wallet
/// recovering from seed must learn about the vtxo to claim the funds.
#[tokio::test]
async fn recovery_catchup_includes_exited_vtxos() {
	let ctx = TestContext::new("bark/recovery_catchup_includes_exited_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Same dropping proxy as recovery_state_catches_up_on_sync: fake
	// registration success and fail mailbox posts, so no recovery state
	// reaches the server and no vtxo gets marked registered.
	#[derive(Clone)]
	struct DropRecovery {
		enabled: Arc<AtomicBool>,
		posts: Arc<std::sync::atomic::AtomicUsize>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for DropRecovery {
		async fn register_vtxo_transactions(
			&self, upstream: &mut ArkClient, req: protos::RegisterVtxoTransactionsRequest,
		) -> Result<protos::Empty, tonic::Status> {
			if self.enabled.load(Ordering::Relaxed) {
				Ok(protos::Empty {})
			} else {
				Ok(upstream.register_vtxo_transactions(req).await?.into_inner())
			}
		}
	}
	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for DropRecovery {
		async fn post_recovery_vtxo_ids(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
		) -> Result<protos::core::Empty, tonic::Status> {
			if self.enabled.load(Ordering::Relaxed) {
				Err(tonic::Status::unavailable("recovery post dropped by test proxy"))
			} else {
				self.posts.fetch_add(1, Ordering::Relaxed);
				Ok(upstream.post_recovery_vtxo_ids(req).await?.into_inner())
			}
		}
	}

	let dropping = Arc::new(AtomicBool::new(true));
	let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_with_mailbox(
		DropRecovery { enabled: dropping.clone(), posts: posts.clone() },
		DropRecovery { enabled: dropping.clone(), posts: posts.clone() },
	).await;

	// bark2 receives a vtxo via arkoor (board vtxos are stored fully signed
	// by board registration itself) and needs onchain funds to pay for the
	// exit transactions.
	let bark1 = ctx.bark("bark1", &proxy.address).funded(sat(90_000)).create().await;
	let bark2 = ctx.bark("bark2", &proxy.address).funded(sat(1_000_000)).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(80_000)).await;

	let addr2 = bark2.address().await;
	bark1.send_oor(&addr2, sat(20_000)).await;

	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	let vtxo_id = vtxos[0].id.to_string();

	// The drops left the vtxo unregistered server-side and the mailbox empty.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let state = db.read(async |t| {
		let row = t.query_one(
			"SELECT spend_state::text FROM vtxo WHERE vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, String>(0))
	}).await.unwrap();
	assert_eq!(state, "unregistered");

	// Exit the vtxo unilaterally, but never claim the resulting output.
	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;

	let mailbox_rows = db.read(async |t| {
		let row = t.query_one(
			"SELECT COUNT(*) FROM mailbox WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(mailbox_rows, 0);

	// Let calls through again; the next sync must back up the exited vtxo.
	dropping.store(false, Ordering::Relaxed);
	bark2.vtxos().await;

	let mailbox_rows = db.read(async |t| {
		let row = t.query_one(
			"SELECT COUNT(*) FROM mailbox WHERE mailbox_type = 'recovery-vtxo-id' AND vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(mailbox_rows, 1);
	let blob = db.read(async |t| {
		let row = t.query_one(
			"SELECT vtxo FROM vtxo WHERE vtxo_id = $1", &[&vtxo_id],
		).await?;
		Ok(row.get::<_, Vec<u8>>(0))
	}).await.unwrap();
	let stored = Vtxo::<Full>::deserialize(&blob).expect("stored vtxo should parse");
	assert!(stored.has_all_witnesses(), "stored vtxo should be fully signed");

	// The exited vtxo is marked registered like any other, so another sync
	// doesn't re-post it.
	let posts_after_catchup = posts.load(Ordering::Relaxed);
	bark2.vtxos().await;
	assert_eq!(posts.load(Ordering::Relaxed), posts_after_catchup,
		"a caught-up wallet should not re-post recovery vtxo IDs",
	);
}

/// Hides every mailbox message from the wallet behind it and counts how often
/// the xpub lookup is used.
#[derive(Clone)]
struct NoMailbox {
	xpub_calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for NoMailbox {
	async fn recover_vtxos_by_xpub(
		&self, upstream: &mut ArkClient, req: protos::RecoverVtxosByXpubRequest,
	) -> Result<protos::RecoverVtxosByXpubResponse, tonic::Status> {
		self.xpub_calls.fetch_add(1, Ordering::Relaxed);
		Ok(upstream.recover_vtxos_by_xpub(req).await?.into_inner())
	}
}
#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for NoMailbox {
	async fn read_mailbox(
		&self, _upstream: &mut MailboxClient, _req: protos::mailbox_server::MailboxRequest,
	) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
		Ok(protos::mailbox_server::MailboxMessages { messages: vec![], have_more: false })
	}
}

/// A wallet restored from its mnemonic gets its VTXOs back from the server's
/// xpub lookup alone: the proxy makes sure neither mailbox has anything to
/// offer, so the recovery can only have come from the xpub rpc.
#[tokio::test]
async fn recovered_wallet_finds_vtxos_via_xpub_without_mailbox() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("bark/recovered_wallet_finds_vtxos_via_xpub_without_mailbox").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// bark2 receives two arkoors on two different keys through the real
	// server; it registers them itself on sync, so the server holds the
	// signed vtxos.
	let bark1 = ctx.bark("bark1", &srv).funded(sat(190_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(180_000)).await;
	bark1.send_oor(&bark2.address().await, sat(30_000)).await;
	bark1.send_oor(&bark2.address().await, sat(40_000)).await;

	let original = bark2.vtxos().await;
	assert_eq!(original.len(), 2);
	let mut original_ids = original.iter().map(|v| v.id).collect::<Vec<_>>();
	original_ids.sort();

	// Restore from the same seed behind the proxy, so neither mailbox can
	// feed the recovery. Wallet creation runs the recovery.
	let xpub_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_with_mailbox(
		NoMailbox { xpub_calls: xpub_calls.clone() },
		NoMailbox { xpub_calls: xpub_calls.clone() },
	).await;
	let mnemonic = bark2.mnemonic().await.expect("bark2 has a mnemonic");
	let recovered = ctx.bark("bark2_recovered", &proxy.address).mnemonic(mnemonic).create().await;
	assert_eq!(xpub_calls.load(Ordering::Relaxed), 1,
		"wallet creation should look up the xpub exactly once",
	);

	let mut recovered_ids = recovered.vtxos().await.iter().map(|v| v.id).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, original_ids, "recovered wallet should hold the same vtxos");
	assert_eq!(recovered.spendable_balance().await, sat(70_000));

	// Both keys were revealed, so the wallet can address them, and it can
	// sign with them: spending is the proof that the keys were recovered.
	recovered.address_at_idx(1).await;
	let bark1_balance = bark1.spendable_balance().await;
	recovered.send_oor(&bark1.address().await, sat(50_000)).await;
	assert_eq!(bark1.spendable_balance().await, bark1_balance + sat(50_000));
}

/// With the xpub lookup disabled on the server, a restored wallet still
/// recovers through the recovery mailbox.
#[tokio::test]
async fn recovered_wallet_falls_back_to_mailbox_when_xpub_disabled() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("bark/recovered_wallet_falls_back_to_mailbox_when_xpub_disabled").await;
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 0)
		.create().await;

	let bark1 = ctx.bark("bark1", &srv).funded(sat(190_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(180_000)).await;
	bark1.send_oor(&bark2.address().await, sat(30_000)).await;

	let original = bark2.vtxos().await;
	assert_eq!(original.len(), 1);

	let mnemonic = bark2.mnemonic().await.expect("bark2 has a mnemonic");
	let recovered = ctx.bark("bark2_recovered", &srv).mnemonic(mnemonic).create().await;

	let recovered = recovered.vtxos().await;
	assert_eq!(recovered.len(), 1);
	assert_eq!(recovered[0].id, original[0].id);
}

/// A wallet whose keys reach past the range the server scans per call asks
/// for the next range, starting where the previous call stopped, until the
/// server reports that nothing more may follow.
#[tokio::test]
async fn recovered_wallet_continues_xpub_lookup_past_server_range() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("bark/recovered_wallet_continues_xpub_lookup_past_server_range").await;
	let srv = ctx.captaind("server").funded(btc(10))
		.cfg(|c| c.recovery_xpub_nb_keys = 2)
		.create().await;

	// bark2 receives on its first key and on the key two indices further,
	// which lies in the second range the server scans.
	let bark1 = ctx.bark("bark1", &srv).funded(sat(190_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(180_000)).await;
	let first = bark2.address().await;
	bark2.address().await;
	let third = bark2.address().await;
	bark1.send_oor(&first, sat(30_000)).await;
	bark1.send_oor(&third, sat(40_000)).await;

	let mut original_ids = bark2.vtxos().await.iter().map(|v| v.id).collect::<Vec<_>>();
	assert_eq!(original_ids.len(), 2);
	original_ids.sort();

	let xpub_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_with_mailbox(
		NoMailbox { xpub_calls: xpub_calls.clone() },
		NoMailbox { xpub_calls: xpub_calls.clone() },
	).await;
	let mnemonic = bark2.mnemonic().await.expect("bark2 has a mnemonic");
	let recovered = ctx.bark("bark2_recovered", &proxy.address).mnemonic(mnemonic).create().await;

	// The third call scans a range without vtxos and ends the lookup.
	assert_eq!(xpub_calls.load(Ordering::Relaxed), 3,
		"wallet creation should look up each range once, plus one empty range",
	);

	let mut recovered_ids = recovered.vtxos().await.iter().map(|v| v.id).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, original_ids, "recovered wallet should hold the same vtxos");
	assert_eq!(recovered.spendable_balance().await, sat(70_000));
}

/// A wallet follows the cursor_vtxo_id of a response that stopped inside the
/// VTXOs of a key, and gets the rest of them from the next calls.
#[tokio::test]
async fn recovered_wallet_follows_xpub_lookup_cursor() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("bark/recovered_wallet_follows_xpub_lookup_cursor").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Passes on the first VTXO of every response only, as if the server had
	// run out of room right after it, and points the cursor at it.
	#[derive(Clone)]
	struct OneVtxoPerCall {
		xpub_calls: Arc<std::sync::atomic::AtomicUsize>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for OneVtxoPerCall {
		async fn recover_vtxos_by_xpub(
			&self, upstream: &mut ArkClient, req: protos::RecoverVtxosByXpubRequest,
		) -> Result<protos::RecoverVtxosByXpubResponse, tonic::Status> {
			self.xpub_calls.fetch_add(1, Ordering::Relaxed);
			let start_index = req.start_index;
			let mut resp = upstream.recover_vtxos_by_xpub(req).await?.into_inner();
			if resp.vtxos.len() > 1 {
				resp.vtxos.truncate(1);
				let first = &resp.vtxos[0];
				resp.nb_keys_scanned = first.derivation_index - start_index;
				resp.have_more = true;
				let id = Vtxo::<Full>::deserialize(&first.vtxo).unwrap().id();
				resp.cursor_vtxo_id = Some(id.to_bytes().to_vec());
			}
			Ok(resp)
		}
	}
	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for OneVtxoPerCall {
		async fn read_mailbox(
			&self, _upstream: &mut MailboxClient, _req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			Ok(protos::mailbox_server::MailboxMessages { messages: vec![], have_more: false })
		}
	}

	// bark2 receives three arkoors on its first key and one on its second.
	let bark1 = ctx.bark("bark1", &srv).funded(sat(290_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(280_000)).await;
	let first = bark2.address().await;
	let second = bark2.address().await;
	bark1.send_oor(&first, sat(30_000)).await;
	bark1.send_oor(&first, sat(40_000)).await;
	bark1.send_oor(&first, sat(50_000)).await;
	bark1.send_oor(&second, sat(60_000)).await;

	// A payment can arrive as several vtxos, so there may be more than four.
	let mut original_ids = bark2.vtxos().await.iter().map(|v| v.id).collect::<Vec<_>>();
	assert!(original_ids.len() >= 4);
	original_ids.sort();

	let xpub_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_with_mailbox(
		OneVtxoPerCall { xpub_calls: xpub_calls.clone() },
		OneVtxoPerCall { xpub_calls: xpub_calls.clone() },
	).await;
	let mnemonic = bark2.mnemonic().await.expect("bark2 has a mnemonic");
	let recovered = ctx.bark("bark2_recovered", &proxy.address).mnemonic(mnemonic).create().await;

	// One call for each vtxo, the last of which also ends the lookup.
	assert_eq!(xpub_calls.load(Ordering::Relaxed), original_ids.len());

	let mut recovered_ids = recovered.vtxos().await.iter().map(|v| v.id).collect::<Vec<_>>();
	recovered_ids.sort();
	assert_eq!(recovered_ids, original_ids, "recovered wallet should hold the same vtxos");
	assert_eq!(recovered.spendable_balance().await, sat(180_000));
}

/// The xpub lookup lists a VTXO whatever its spend state: a spent one comes
/// back too, with its state, and the restored wallet keeps it out of its
/// balance without asking the server anything else about it.
#[tokio::test]
async fn recovered_wallet_xpub_lookup_returns_spent_vtxos() {
	require_bark_version!(> "0.7.1");

	let ctx = TestContext::new("bark/recovered_wallet_xpub_lookup_returns_spent_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Records the vtxos the xpub lookup returns, and counts the requests
	// for single vtxos or their status.
	#[derive(Clone)]
	struct RecordXpubVtxos {
		returned: Arc<Mutex<Vec<(VtxoId, protos::VtxoSpendState)>>>,
		vtxo_requests: Arc<std::sync::atomic::AtomicUsize>,
	}
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for RecordXpubVtxos {
		async fn recover_vtxos_by_xpub(
			&self, upstream: &mut ArkClient, req: protos::RecoverVtxosByXpubRequest,
		) -> Result<protos::RecoverVtxosByXpubResponse, tonic::Status> {
			let resp = upstream.recover_vtxos_by_xpub(req).await?.into_inner();
			self.returned.lock().unwrap().extend(resp.vtxos.iter().map(|v| (
				Vtxo::<Full>::deserialize(&v.vtxo).unwrap().id(),
				protos::VtxoSpendState::try_from(v.spend_state).unwrap(),
			)));
			Ok(resp)
		}
		async fn get_vtxo(
			&self, upstream: &mut ArkClient, req: protos::GetVtxoRequest,
		) -> Result<protos::GetVtxoResponse, tonic::Status> {
			self.vtxo_requests.fetch_add(1, Ordering::Relaxed);
			Ok(upstream.get_vtxo(req).await?.into_inner())
		}
		async fn get_vtxo_status(
			&self, upstream: &mut ArkClient, req: protos::GetVtxoStatusRequest,
		) -> Result<protos::GetVtxoStatusResponse, tonic::Status> {
			self.vtxo_requests.fetch_add(1, Ordering::Relaxed);
			Ok(upstream.get_vtxo_status(req).await?.into_inner())
		}
		async fn get_vtxos_by_ids(
			&self, upstream: &mut ArkClient, req: protos::GetVtxosByIdsRequest,
		) -> Result<protos::GetVtxosByIdsResponse, tonic::Status> {
			self.vtxo_requests.fetch_add(1, Ordering::Relaxed);
			Ok(upstream.get_vtxos_by_ids(req).await?.into_inner())
		}
		async fn get_vtxos_status_by_ids(
			&self, upstream: &mut ArkClient, req: protos::GetVtxosStatusByIdsRequest,
		) -> Result<protos::GetVtxosStatusByIdsResponse, tonic::Status> {
			self.vtxo_requests.fetch_add(1, Ordering::Relaxed);
			Ok(upstream.get_vtxos_status_by_ids(req).await?.into_inner())
		}
	}

	let bark1 = ctx.bark("bark1", &srv).funded(sat(190_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).create().await;
	bark1.board_and_confirm_and_register(&ctx, sat(180_000)).await;
	bark1.send_oor(&bark2.address().await, sat(30_000)).await;

	let original = bark2.vtxos().await;
	assert_eq!(original.len(), 1);
	let spent_id = original[0].id;

	// Spending the whole vtxo leaves bark2 without any.
	bark2.send_oor(&bark1.address().await, sat(30_000)).await;
	assert!(bark2.vtxos().await.is_empty());

	let returned = Arc::new(Mutex::new(Vec::new()));
	let vtxo_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let proxy = srv.start_proxy_no_mailbox(RecordXpubVtxos {
		returned: returned.clone(),
		vtxo_requests: vtxo_requests.clone(),
	}).await;
	let mnemonic = bark2.mnemonic().await.expect("bark2 has a mnemonic");
	let recovered = ctx.bark("bark2_recovered", &proxy.address).mnemonic(mnemonic).create().await;

	assert!(returned.lock().unwrap().contains(&(spent_id, protos::VtxoSpendState::Spent)),
		"the xpub lookup should return the spent vtxo as spent",
	);
	assert_eq!(vtxo_requests.load(Ordering::Relaxed), 0,
		"the xpub lookup should carry everything recovery needs",
	);
	assert!(recovered.vtxos().await.is_empty(), "a spent vtxo is not recovered as spendable");
	assert_eq!(recovered.spendable_balance().await, sat(0));
}
