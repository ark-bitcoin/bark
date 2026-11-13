use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::body::Bytes;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::post;
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::RpcApi;
use tokio::sync::{oneshot, Notify};

use ark::ProtocolEncoding;
use ark::attestations::RoundParticipationStatusAttestation;
use server::database::Db;
use server::database::expiry_payout::ownership::{OwnershipDisposition, OwnershipEvidence};
use server_log::ProgressBroadcast;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::exit::progress_exit_until_awaiting_delta;
use ark_testing::util::{poll_interval, FutureExt};

use super::{
	current_share, fund_watchman, mine, mine_past, payout_output, payout_shares, wait_for_query_lock,
	wait_payout,
};

/// Loses the reply to a finished offboard, so the client never broadcasts it.
#[derive(Clone)]
struct LoseFinishedReply(Arc<Mutex<Option<Vec<u8>>>>);

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for LoseFinishedReply {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let result = upstream.finish_offboard(req).await?.into_inner();
		*self.0.lock().unwrap() = Some(result.signed_offboard_tx);
		Err(tonic::Status::unavailable("reply lost"))
	}
}

/// Serve a bitcoind RPC proxy on a local port that refuses every
/// `sendrawtransaction` while `refuse` is set, and return its URL.
async fn refusing_bitcoind_proxy(ctx: &TestContext, refuse: Arc<AtomicBool>) -> String {
	let upstream = ctx.bitcoind().rpc_url();
	let client = reqwest::Client::builder().no_proxy().build().unwrap();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let url = format!("http://{}", listener.local_addr().unwrap());
	let app = Router::new().route("/", post(move |headers: HeaderMap, body: Bytes| {
		let (refuse, upstream, client) = (refuse.clone(), upstream.clone(), client.clone());
		async move {
			let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
			if request["method"] == "sendrawtransaction" && refuse.load(Ordering::SeqCst) {
				let error = serde_json::json!({
					"result": null, "id": request["id"],
					"error": { "code": -26, "message": "broadcast refused" },
				});
				return (StatusCode::OK, Bytes::from(serde_json::to_vec(&error).unwrap()));
			}
			let response = client.post(upstream)
				.header(header::AUTHORIZATION, headers[header::AUTHORIZATION].clone())
				.header(header::CONTENT_TYPE, "application/json")
				.body(body).send().await.unwrap();
			(response.status(), response.bytes().await.unwrap())
		}
	})).layer(axum::extract::DefaultBodyLimit::disable());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	url
}

/// An offboard the server signed but nobody broadcast keeps its VTXO out of
/// the expiry payout until the offboard confirms. Then the VTXO goes to the
/// operator, who paid the offboard.
#[tokio::test]
async fn expiry_payout_waits_for_an_unbroadcast_offboard() {
	let ctx = TestContext::new("server/expiry_payout_waits_for_an_unbroadcast_offboard").await;
	let refuse = Arc::new(AtomicBool::new(false));
	let bitcoind_url = refusing_bitcoind_proxy(&ctx, refuse.clone()).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().funded(btc(1))
		.cfg(move |cfg| {
			cfg.bitcoind.url = bitcoind_url;
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(24);
		}).create().await;
	let signed = Arc::new(Mutex::new(None));
	let proxy = srv.start_proxy_no_mailbox(LoseFinishedReply(signed.clone())).await;
	let owner = ctx.bark_sdk("owner", &proxy).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let vtxo = owner.spendable_vtxos().await.unwrap().pop().unwrap();
	let destination = ctx.bitcoind().get_new_address();
	fund_watchman(&ctx, &srv, sat(100_000)).await;

	refuse.store(true, Ordering::SeqCst);
	owner.offboard_vtxos([vtxo.id()], destination.clone()).await.expect_err("the reply is lost");
	let offboard: Transaction = deserialize(&signed.lock().unwrap().clone().unwrap()).unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let source = db.read(async |t| t.get_user_vtxos_by_id(&[vtxo.id()]).await).await.unwrap();
	assert_eq!(source[0].offboarded_in, Some(offboard.compute_txid()));

	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	for _ in 0..3 {
		srv.watchmand().trigger_sweep().await;
		mine(&ctx, &srv, 1).await;
	}
	assert!(payout_shares(&db, vtxo.id()).await.is_empty(), "an unpaid offboard keeps its VTXO");
	assert_eq!(ctx.bitcoind().get_received_by_address(&destination), sat(0));

	refuse.store(false, Ordering::SeqCst);
	ctx.bitcoind().sync_client().send_raw_transaction(&offboard).unwrap();
	mine(&ctx, &srv, 6).await;
	assert!(ctx.bitcoind().get_received_by_address(&destination) > sat(0));
	async {
		loop {
			srv.watchmand().trigger_sweep().await;
			if let Some(share) = current_share(&db, vtxo.id()).await {
				assert_eq!(share.owner, None, "the offboard paid the owner");
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
}

/// Holds the first offboard finish request until released.
#[derive(Clone)]
struct HoldFinish {
	arrived: Arc<Mutex<Option<oneshot::Sender<protos::FinishOffboardRequest>>>>,
	release: Arc<Notify>,
	response: Arc<Mutex<Option<Result<protos::FinishOffboardResponse, tonic::Status>>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for HoldFinish {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, request: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		let arrived = self.arrived.lock().unwrap().take();
		if let Some(arrived) = arrived {
			arrived.send(request.clone()).unwrap();
			self.release.notified().await;
		}
		let result = upstream.finish_offboard(request).await.map(tonic::Response::into_inner);
		self.response.lock().unwrap().get_or_insert_with(|| result.clone());
		result
	}
}

#[derive(Clone, Copy)]
enum OffboardRace {
	/// The offboard is first in the row lock queue of the VTXO.
	OffboardFirst,
	/// The offboard commits after the decision read the VTXO, before the
	/// decision writes.
	OffboardDuringDecision,
	/// The decision commits before the offboard registers.
	DecisionFirst,
}

/// An offboard of an expired VTXO races the expiry payout decision. Exactly
/// one of them takes the VTXO: an offboard that wins is paid on chain and the
/// VTXO gets no payout, and a decision that wins makes the server refuse the
/// offboard and pay the owner.
async fn offboard_race(name: &str, race: OffboardRace) {
	let ctx = TestContext::new(&format!("server/{name}")).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().funded(btc(1))
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); }).watchmand().create().await;
	let (arrived, request) = oneshot::channel();
	let gate = HoldFinish {
		arrived: Arc::new(Mutex::new(Some(arrived))),
		release: Arc::new(Notify::new()),
		response: Arc::new(Mutex::new(None)),
	};
	let proxy = srv.start_proxy_no_mailbox(gate.clone()).await;
	let wallet = Arc::new(ctx.bark_sdk("owner", &proxy).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await);
	let vtxo = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
	let id = vtxo.id();
	let script = wallet.payout_script();
	let address = ctx.bitcoind().get_new_address();
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let offboard = tokio::spawn({
		let (wallet, address) = (wallet.clone(), address.clone());
		async move { wallet.offboard_vtxos([id], address).await }
	});
	let request = request.wait_millis(15_000).await.unwrap();
	let offboard_txid = Txid::from_slice(&request.offboard_txid).unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	// A stopped watchman makes no decision while the chain reaches expiry.
	srv.watchmand().stop().await.unwrap();
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(vtxo.expiry_height().to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	let decision_write = "SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE";
	match race {
		OffboardRace::OffboardFirst => db.write(async |t| {
			t.query_one("SELECT vtxo_id FROM vtxo WHERE vtxo_id = $1 FOR UPDATE", &[&id.to_string()]).await?;
			gate.release.notify_one();
			wait_for_query_lock(t, "SELECT vtxo_id FROM vtxo WHERE vtxo_id = ANY%").await?;
			srv.watchmand().start().await.unwrap();
			wait_for_query_lock(t, decision_write).await
		}).await.unwrap(),
		OffboardRace::OffboardDuringDecision => db.write(async |t| {
			// KEY SHARE blocks the decision's FOR UPDATE, not the offboard.
			t.query("SELECT vtxo_id FROM vtxo WHERE anchor_point = $1 ORDER BY vtxo_id FOR KEY SHARE",
				&[&vtxo.vtxo.chain_anchor().to_string()]).await?;
			srv.watchmand().start().await.unwrap();
			wait_for_query_lock(t, decision_write).await?;
			gate.release.notify_one();
			while gate.response.lock().unwrap().is_none() {
				tokio::time::sleep(poll_interval()).await;
			}
			Ok(())
		}).await.unwrap(),
		OffboardRace::DecisionFirst => srv.watchmand().start().await.unwrap(),
	}

	if let OffboardRace::DecisionFirst = race {
		let (_, payout) = wait_payout(&db, id).await;
		gate.release.notify_one();
		offboard.wait_millis(20_000).await.unwrap().unwrap_err();
		let refusal = gate.response.lock().unwrap().clone().unwrap().unwrap_err();
		assert_eq!(refusal.metadata().get("expiry-payout-reason").unwrap(), "decided_for_payout");
		let state = db.read(async |t| t.get_user_vtxos_by_id(&[id]).await).await.unwrap();
		assert_eq!(state[0].offboarded_in, None, "the refused offboard is not stored");
		payout_output(&payout, &script, vtxo.amount() - sat(2_000));
		mine(&ctx, &srv, 6).await;
		assert_eq!(ctx.bitcoind().get_received_by_address(&address), sat(0));
	} else {
		let txid = offboard.wait_millis(20_000).await.unwrap().unwrap().txid;
		assert_eq!(txid, offboard_txid);
		ctx.bitcoind().await_transaction(txid).await;
		mine(&ctx, &srv, 6).await;
		assert!(ctx.bitcoind().get_received_by_address(&address) > sat(0));
		assert!(current_share(&db, id).await.is_none_or(|share| share.owner.is_none()),
			"an offboarded VTXO gets no owner payout");
	}
}

#[tokio::test]
async fn expiry_payout_offboard_first_in_the_lock_queue_wins() {
	offboard_race("expiry_payout_offboard_first_in_the_lock_queue_wins", OffboardRace::OffboardFirst).await;
}

#[tokio::test]
async fn expiry_payout_offboard_during_the_decision_aborts_it() {
	offboard_race("expiry_payout_offboard_during_the_decision_aborts_it", OffboardRace::OffboardDuringDecision).await;
}

#[tokio::test]
async fn expiry_payout_decision_refuses_a_later_offboard() {
	offboard_race("expiry_payout_decision_refuses_a_later_offboard", OffboardRace::DecisionFirst).await;
}

/// While an expiry decision is stalled in the database, the watchman still
/// broadcasts the exit progress of other VTXOs.
#[tokio::test]
async fn expiry_payout_stalled_decision_keeps_exits_going() {
	let ctx = TestContext::new("server/expiry_payout_stalled_decision_keeps_exits_going").await;
	let srv = ctx.captaind("server").funded(btc(10)).bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(40);
			cfg.vtxo_exit_delta = BlockDelta::new(6);
		})
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = std::time::Duration::from_millis(250);
			cfg.watchman.sweep_interval = std::time::Duration::from_secs(600);
		}).create().await;
	let wm = srv.watchmand();
	// This board expires well before the VTXOs of the sender.
	let (old, _, _) = super::idle_board(&ctx, &srv, "idle", sat(100_000)).await;
	ctx.generate_blocks(18).await;

	let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
	let receiver = ctx.bark("receiver", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	sender.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	ctx.refresh_all(&srv, &[&sender]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	sender.sync().await;
	let sender_vtxo = sender.vtxo_ids().await[0];
	let stale_sender = sender.full_clone("stale_sender").await;
	sender.send_oor(receiver.address().await, sat(50_000)).await;
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let old_expiry = old.expiry_height().to_u32();
	db.write(async |t| {
		t.execute(&format!(r#"
			CREATE FUNCTION test_stall_decision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			IF NEW.expiry_height = {old_expiry} THEN PERFORM pg_sleep(90); END IF;
			RETURN NEW;
			END $$
		"#), &[]).await?;
		t.execute("
			CREATE TRIGGER test_stall_decision BEFORE INSERT ON expiry_payout
			FOR EACH ROW EXECUTE FUNCTION test_stall_decision()
		", &[]).await?;
		Ok(())
	}).await.unwrap();

	mine_past(&ctx, &srv, old.expiry_height()).await;
	let stalled = async {
		loop {
			let pid = db.read(async |t| Ok(t.query_opt("
				SELECT pid FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event = 'PgSleep' LIMIT 1
			", &[]).await?.map(|row| row.get::<_, i32>(0)))).await.unwrap();
			if let Some(pid) = pid {
				break pid;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(20_000).await;
	let still_stalled = async || db.read(async |t| Ok(t.query_one("
		SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event = 'PgSleep')
	", &[&stalled]).await?.get::<_, bool>(0))).await.unwrap();

	// The stale clone exits the round VTXO it spent with the arkoor. Only
	// the watchman can broadcast the signed arkoor transaction that follows.
	let mut progress = wm.subscribe_log::<ProgressBroadcast>();
	stale_sender.start_exit_all().await;
	let observed = async {
		let progress = progress.recv().await.unwrap();
		assert_eq!(progress.vtxo_id, sender_vtxo);
		assert!(ctx.bitcoind().sync_client().get_raw_transaction(&progress.txid, None).is_ok());
		assert!(still_stalled().await, "the progress waited for the stalled decision");
	};
	let grace = wm.config().watchman.progress_grace_period.to_u32();
	let exit = async {
		progress_exit_until_awaiting_delta(&ctx, &stale_sender).await;
		let tip = ctx.generate_blocks(grace).await;
		wm.wait_for_sync_height(tip).await;
	};
	async { tokio::join!(exit, observed) }.wait_millis(65_000).await;
	assert!(db.write(async |t| Ok(t.query_one("SELECT pg_cancel_backend($1)", &[&stalled]).await?
		.get::<_, bool>(0))).await.unwrap());
}

/// A refresh that the expiry payout cancelled before its forfeits were
/// accepted never releases its unlock preimage, and its inputs stay with
/// their owner.
#[tokio::test]
async fn expiry_payout_cancelled_refresh_keeps_its_preimage() {
	let ctx = TestContext::new("server/expiry_payout_cancelled_refresh_keeps_its_preimage").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true)
		.create().await;
	let wallet = ctx.bark("wallet", &srv).funded(sat(500_000)).create().await;
	let ids = wallet.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&wallet]).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (participation, hash, leaf) = db.read(async |t| {
		let row = t.query_one("
			SELECT id, unlock_hash FROM round_participation
			WHERE round_id IS NOT NULL AND forfeited_at IS NULL ORDER BY id DESC LIMIT 1
		", &[]).await?;
		let hash: ark::tree::signed::UnlockHash = row.get::<_, &str>("unlock_hash").parse()?;
		let unclaimed = t.query("SELECT vtxo_id FROM vtxo WHERE spend_state = 'unclaimed'", &[]).await?
			.into_iter().map(|row| row.get::<_, &str>(0).parse()).collect::<Result<Vec<_>, _>>()?;
		let leaf = t.get_server_vtxos_by_id(&unclaimed).await?.into_iter()
			.find(|state| state.vtxo.clone().try_into_user_vtxo().is_ok_and(|v| v.unlock_hash() == Some(hash)))
			.unwrap().vtxo;
		Ok((row.get::<_, i64>("id"), hash, leaf))
	}).await.unwrap();
	let mailbox = wallet.client().await.mailbox_keypair();
	let request = protos::RoundParticipationStatusRequest {
		unlock_hash: hash.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(hash, &mailbox).serialize(),
	};
	let mut rpc = srv.get_public_rpc().await;
	let issued = rpc.round_participation_status(request.clone()).await.unwrap().into_inner();
	assert_eq!(issued.status, protos::RoundParticipationStatus::RoundPartIssued as i32);
	assert!(issued.unlock_preimage.is_none());
	let unknown = ark::tree::signed::UnlockHash::from_byte_array([42; 32]);
	let error = rpc.round_participation_status(protos::RoundParticipationStatusRequest {
		unlock_hash: unknown.to_byte_array().to_vec(),
		attestation: RoundParticipationStatusAttestation::new(unknown, &mailbox).serialize(),
	}).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::NotFound);
	assert!(error.metadata().get("expiry-payout-reason").is_none());

	// Without its input rows, a participation does not count as forfeited.
	let inputs = db.write(async |t| Ok(t.query("
		DELETE FROM round_part_input WHERE participation_id = $1 RETURNING vtxo_id
	", &[&participation]).await?.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>()))
		.await.unwrap();
	let partial = rpc.round_participation_status(request.clone()).await.unwrap().into_inner();
	assert!(partial.unlock_preimage.is_none());
	db.write(async |t| {
		for input in &inputs {
			t.execute("INSERT INTO round_part_input(participation_id, vtxo_id) VALUES($1, $2)",
				&[&participation, input]).await?;
		}
		Ok(())
	}).await.unwrap();

	assert!(db.write(async |t| t.cancel_expiry_participations(&[participation]).await).await.unwrap());
	let refusal = rpc.round_participation_status(request).await.unwrap_err();
	assert_eq!(refusal.code(), tonic::Code::NotFound);
	assert_eq!(refusal.metadata().get("expiry-payout-reason").unwrap(), "round_cancelled_before_forfeit");
	let released = db.read(async |t| Ok(t.query_one("
		SELECT forfeited_at IS NOT NULL FROM round_participation WHERE id = $1
	", &[&participation]).await?.get::<_, bool>(0))).await.unwrap();
	assert!(!released);
	assert!(db.write(async |t| t.remove_round_participation(hash).await).await.unwrap());

	// The round output belongs to the operator, and the inputs stay spendable.
	let tip = bitcoin_ext::BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	ctx.bitcoind().await_transaction(leaf.chain_anchor().txid).await;
	let root = leaf.to_bare();
	let snapshot = db.read(async |t| t.expired_tree_snapshot(&[root.clone()]).await).await.unwrap();
	let fact = snapshot.iter().find(|fact| fact.state.vtxo_id == root.id()).unwrap();
	let proposal = db.read(async |t| t.propose_expiry_ownership(fact, tip).await).await.unwrap();
	assert_eq!(proposal.disposition, OwnershipDisposition::Operator);
	assert!(matches!(proposal.evidence, Some(OwnershipEvidence::Participation)));
	let inputs = db.read(async |t| t.get_user_vtxos_by_id(&ids).await).await.unwrap();
	assert!(inputs.iter().all(|v| v.spend_state == server::database::SpendState::Spendable));
}
