use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::fs;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use bark::BarkNetwork;
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
		Some(0),
		true,
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
