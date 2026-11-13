//! Expiry payouts of large trees and large groups of trees. These tests are
//! slow and run with the `slow_test` feature.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::rand::{thread_rng, RngCore};
use bitcoin_ext::BlockDelta;

use ark::{ProtocolEncoding, Vtxo, VtxoPolicy};
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::vtxo::Full;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{sat, Captaind, TestContext};
use ark_testing::util::{poll_interval, FutureExt};

use super::{
	bind_to_wallets, blinded_mailbox, current_share, fund_watchman, mine, mine_past, published_payout, Owner,
};

const PAYEES: usize = 327;
const LEAF_SAT: u64 = 5_000;

/// Send `input` to `destinations` by arkoor and register the outputs.
async fn arkoor_node(
	srv: &Captaind, wallet: &bark::Wallet, input: Vtxo<Full>, key: Keypair,
	destinations: Vec<(ArkoorDestination, Option<&Owner>)>,
) -> Vec<Vtxo<Full>> {
	let builder = ArkoorPackageBuilder::new_with_checkpoints(
		[input], destinations.iter().map(|(destination, _)| destination.clone()).collect(),
	).unwrap().generate_user_nonces(&[key]).unwrap();
	let owners = destinations.iter()
		.filter_map(|(destination, owner)| owner.map(|owner| (destination.policy.user_pubkey(), owner)))
		.collect::<Vec<_>>();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	for output in request.parts.iter_mut().flat_map(|p| p.outputs.iter_mut().chain(&mut p.isolated_outputs)) {
		let key = VtxoPolicy::deserialize(&output.policy).unwrap().user_pubkey();
		if let Some((_, owner)) = owners.iter().find(|(owner_key, _)| *owner_key == key) {
			output.blinded_mailbox_id = blinded_mailbox(srv, &owner.key(1), owner.mailbox_id()).await;
		}
	}
	let request = bind_to_wallets(srv, &[wallet], request).await;
	let response = srv.get_public_rpc().await.request_arkoor_cosign(request).await.unwrap().into_inner();
	let outputs = builder.user_cosign(&[key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos();
	wallet.register_vtxo_transactions_with_server(&outputs).await.unwrap();
	outputs
}

/// One root that pays 327 owners needs a payout transaction above 10 kvB,
/// and it pays every owner.
#[tokio::test]
async fn expiry_payout_above_ten_kilovbytes_pays_every_owner() {
	let ctx = TestContext::new("server/expiry_payout_above_ten_kilovbytes_pays_every_owner").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(4_320);
		cfg.vtxo_exit_delta = BlockDelta::new(144);
		cfg.max_vtxo_exit_depth = 100;
		cfg.max_arkoor_fanout = 4;
	}).create().await;
	let owners = (0..PAYEES).map(|_| {
		let mut seed = [0; 64];
		thread_rng().fill_bytes(&mut seed);
		Owner::new(&seed)
	}).collect::<Vec<_>>();
	let wallet = ctx.bark_sdk("source", &srv).boarded(sat(PAYEES as u64 * LEAF_SAT))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let source = super::full_vtxos(&wallet).await.pop().unwrap();
	let source_key = wallet.get_vtxo_key(&source).await.unwrap();
	for _ in 0..16 {
		fund_watchman(&ctx, &srv, sat(200_000)).await;
	}

	// Split the board by arkoor into one VTXO per owner, four outputs per
	// node, with the owners' outputs bound to their own mailboxes.
	let mut jobs = VecDeque::from([(source.clone(), source_key, (0..PAYEES).collect::<Vec<_>>())]);
	let mut leaves = Vec::new();
	while let Some((input, key, group)) = jobs.pop_front() {
		let parts = group.len().min(4);
		let mut destinations = Vec::new();
		let mut children = Vec::new();
		let mut offset = 0;
		for part in 0..parts {
			let count = group.len() / parts + usize::from(part < group.len() % parts);
			let indices = group[offset..offset + count].to_vec();
			offset += count;
			let (child_key, owner) = if count == 1 {
				(owners[indices[0]].key(1), Some(&owners[indices[0]]))
			} else {
				(wallet.derive_store_next_keypair().await.unwrap().0, None)
			};
			destinations.push((ArkoorDestination {
				total_amount: sat(count as u64 * LEAF_SAT), policy: VtxoPolicy::new_pubkey(child_key.public_key()),
			}, owner));
			children.push((indices, child_key));
		}
		let outputs = arkoor_node(&srv, &wallet, input, key, destinations).await;
		for (output, (indices, child_key)) in outputs.into_iter().zip(children) {
			if indices.len() == 1 {
				leaves.push((indices[0], output));
			} else {
				jobs.push_back((output, child_key, indices));
			}
		}
	}
	assert_eq!(leaves.len(), PAYEES);
	let mut mailbox = srv.get_mailbox_public_rpc().await;
	for (index, leaf) in &leaves {
		let owner = &owners[*index];
		mailbox.post_arkoor_message(protos::mailbox_server::PostArkoorMessageRequest {
			blinded_id: blinded_mailbox(&srv, &owner.key(1), owner.mailbox_id()).await,
			vtxos: vec![leaf.serialize()],
		}).await.unwrap();
	}
	drop(wallet);

	mine_past(&ctx, &srv, source.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	// Deciding and signing a payout of this size takes a while.
	let payout = async {
		loop {
			srv.watchmand().trigger_sweep().await;
			if let Some((_, payout)) = published_payout(&db, leaves[0].1.id()).await {
				break payout;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(180_000).await;
	assert!(payout.vsize() > 10_000 && payout.vsize() <= 100_000);
	for (index, leaf) in &leaves {
		let share = current_share(&db, leaf.id()).await.unwrap();
		assert_eq!(share.tx.as_ref(), Some(&payout), "one root has one payout");
		assert_eq!(share.owner, Some(owners[*index].mailbox.public_key().to_string()));
		super::payout_output(&payout, &owners[*index].script, sat(LEAF_SAT - 2_000));
	}
	mine(&ctx, &srv, 6).await;
	super::assert_six_deep(&ctx, &payout);
}

/// The decision of a large group of roots that expire together reads them
/// without locks and holds their rows only for a short write. The Lightning
/// settlement lock stays free, and every VTXO is paid to its owner.
#[tokio::test]
async fn expiry_payout_large_group_keeps_server_serving() {
	const WALLETS: usize = 3;
	const BOARDS: usize = 20;
	let ctx = TestContext::new("server/expiry_payout_large_group_keeps_server_serving").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(30); }).create().await;
	let mut wallets = Vec::new();
	for index in 0..WALLETS {
		wallets.push(ctx.bark(format!("owner{index}"), &srv).funded(sat(BOARDS as u64 * 25_000))
			.cfg(|cfg| cfg.daemon_manual_sync = true).create().await);
	}
	fund_watchman(&ctx, &srv, sat(1_000_000)).await;
	// Every board confirms in the same block, so all roots share one expiry.
	let mut boards = Vec::new();
	for wallet in &wallets {
		for _ in 0..BOARDS {
			boards.push(wallet.board(sat(20_000)).await);
		}
	}
	ctx.generate_blocks(ark_testing::constants::BOARD_CONFIRMATIONS).await;
	let mut vtxos = Vec::new();
	for (index, wallet) in wallets.iter().enumerate() {
		wallet.sync().await;
		let client = wallet.client().await;
		for board in &boards[index * BOARDS..(index + 1) * BOARDS] {
			vtxos.push((client.get_full_vtxo(board.vtxos[0]).await.unwrap(), client.payout_script()));
		}
	}
	let expiry = vtxos[0].0.expiry_height();
	assert!(vtxos.iter().all(|(vtxo, _)| vtxo.expiry_height() == expiry));

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let done = Arc::new(AtomicBool::new(false));
	// The longest-running decision write, the only writer here that holds
	// VTXO row locks, whether it held the settlement lock, and the longest
	// lock wait of any connection.
	let sampler = tokio::spawn({
		let (db, done) = (db.clone(), done.clone());
		async move {
			let (mut hold, mut settlement, mut wait) = (0_f64, false, 0_f64);
			while !done.load(Ordering::Relaxed) {
				let row = db.read(async |t| Ok(t.query_one("
					WITH decision AS (
						SELECT a.pid, a.xact_start FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
						WHERE l.locktype = 'relation' AND l.relation = 'vtxo'::regclass
						AND l.mode = 'RowShareLock' AND l.granted AND a.pid <> pg_backend_pid())
					SELECT
						COALESCE((SELECT MAX(EXTRACT(EPOCH FROM clock_timestamp() - xact_start)) FROM decision), 0)::FLOAT8,
						EXISTS(SELECT 1 FROM decision d JOIN pg_locks l ON l.pid = d.pid
							WHERE l.locktype = 'advisory' AND l.classid = 0 AND l.objid = 2 AND l.objsubid = 1 AND l.granted),
						COALESCE((SELECT MAX(EXTRACT(EPOCH FROM clock_timestamp() - query_start)) FROM pg_stat_activity
							WHERE wait_event_type = 'Lock' AND datname = current_database()), 0)::FLOAT8
				", &[]).await?)).await.unwrap();
				hold = hold.max(row.get(0));
				settlement |= row.get::<_, bool>(1);
				wait = wait.max(row.get(2));
				tokio::time::sleep(Duration::from_millis(5)).await;
			}
			(hold, settlement, wait)
		}
	});
	// Every Lightning send admission, receive grant and settlement takes the
	// exclusive settlement lock.
	let admission = tokio::spawn({
		let (db, done) = (db.clone(), done.clone());
		async move {
			let mut slowest = Duration::ZERO;
			while !done.load(Ordering::Relaxed) {
				let start = Instant::now();
				db.write(async |t| Ok(t.execute("SELECT pg_advisory_xact_lock(2)", &[]).await?)).await.unwrap();
				slowest = slowest.max(start.elapsed());
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
			slowest
		}
	});

	mine_past(&ctx, &srv, expiry).await;
	async {
		for round in 0.. {
			let mut decided = 0;
			for (vtxo, _) in &vtxos {
				decided += usize::from(current_share(&db, vtxo.id()).await.is_some());
			}
			if decided == vtxos.len() {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
			if round % 20 == 19 {
				mine(&ctx, &srv, 1).await;
			}
		}
	}.wait_millis(120_000).await;
	done.store(true, Ordering::Relaxed);
	let (hold, settlement, wait) = sampler.await.unwrap();
	let slowest_admission = admission.await.unwrap();

	for (vtxo, script) in &vtxos {
		let share = current_share(&db, vtxo.id()).await.unwrap();
		let mailbox = share.owner.expect("each VTXO is paid to its owner").parse().unwrap();
		assert_eq!(&ark::expiry_payout::payout_script(mailbox), script);
	}
	assert!(hold > 0.0, "the sampler must see the decision write");
	assert!(!settlement, "a group without Lightning VTXOs must not take the settlement lock");
	assert!(hold < 1.0, "the decision write held the rows of the group for {hold:.3}s");
	assert!(wait < 1.0, "a connection waited {wait:.3}s on a lock");
	assert!(slowest_admission < Duration::from_secs(1), "the settlement lock waited {slowest_admission:?}");
}
