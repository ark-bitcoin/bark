use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use bitcoin::{Transaction, Txid, TxIn, TxOut, Witness};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use serde_json::json;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::attestations::VtxoStatusAttestation;
use ark::lightning::PaymentHash;
use ark::vtxo::Full;
use ark::vtxo::policy::signing::VtxoSigner;
use server::database::{BlockTable, Db, SpendState};
use server_rpc::protos;

use ark_testing::{btc, sat, Bitcoind, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};
use ark_testing::util::{poll_interval, FutureExt};

use super::{
	idle_board, allocation_count, assert_paid, assert_six_deep, confirm_exit_path, current_share,
	fund_watchman, grant_closures, htlc_send, mine, mine_past, onchain_spend, outputs_to, payout_output,
	payout_shares, receive_claim_keypair, send_request, wait_watchman_tip, wait_for_confirmation,
	wait_for_query_lock, wait_payout, wait_synced,
};

async fn core_tip(ctx: &TestContext) -> bitcoin_ext::BlockRef {
	server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap()
}

/// A reorg removes the block of a payout. The same payout confirms again on
/// the new branch, the decision keeps its one payout, and the VTXO stays spent.
#[tokio::test]
async fn expiry_payout_survives_a_reorg_of_its_block() {
	let ctx = TestContext::new("server/expiry_payout_survives_a_reorg_of_its_block").await;
	// Both daemons follow the same bitcoind, so both see the reorg.
	let core_url = ctx.bitcoind().rpc_url();
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand_cfg(move |cfg| cfg.bitcoind.url = core_url).create().await;
	let (vtxo, script, _) = idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, payout) = wait_payout(&db, vtxo.id()).await;
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	let old_block = assert_six_deep(&ctx, &payout);
	let old_tip = core_tip(&ctx).await;
	wait_for_confirmation(&db, allocation, old_tip, old_block.hash).await;

	// The daemons refuse a lower tip, so they stay down until the new branch
	// is longer than the old one.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	let core = ctx.bitcoind().sync_client();
	core.invalidate_block(&old_block.hash).unwrap();
	core.generate_to_address(7, &ctx.bitcoind().get_new_address()).unwrap();
	let new_tip = core_tip(&ctx).await;
	assert!(new_tip.height > old_tip.height);
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();

	let new_block = assert_six_deep(&ctx, &payout);
	assert_ne!(new_block.hash, old_block.hash);
	wait_for_confirmation(&db, allocation, new_tip, new_block.hash).await;
	let shares = payout_shares(&db, vtxo.id()).await;
	assert_eq!(shares.len(), 1);
	assert_eq!(shares[0].tx.as_ref(), Some(&payout));
	assert_eq!(db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.unwrap().spend_state,
		SpendState::Spent);
}

/// A reorg lands after a payout decision read an expired root and before
/// it writes. The new branch confirms the owner's own exit of that root.
/// The stale decision must not be stored, and the exited VTXO is not paid.
///
/// A lock on a table the decision reads last holds it after its read. The
/// reorg is real: a second bitcoind mines a longer branch from the block
/// before expiry, and Core switches to it in one step, so no daemon sees a
/// lower tip.
#[tokio::test]
async fn expiry_payout_reorg_during_the_decision_aborts_it() {
	let ctx = TestContext::new("server/expiry_payout_reorg_during_the_decision_aborts_it").await;
	let core_url = ctx.bitcoind().rpc_url();
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand_cfg(move |cfg| cfg.bitcoind.url = core_url).create().await;
	let (vtxo, _, _) = idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	let exit = vtxo.transactions().map(|step| step.tx).collect::<Vec<_>>();
	let exit_txid = exit.iter().find(|tx| tx.input.iter().any(|i| i.previous_output == vtxo.chain_anchor()))
		.unwrap().compute_txid();
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let expiry = vtxo.expiry_height().to_u32();
	let fork = mine_past(&ctx, &srv, BlockHeight::new(expiry - 2)).await;

	// The second bitcoind has no peer: it copies the chain up to the block
	// before expiry and stays there.
	let chain = ctx.bitcoind().sync_client();
	let side = Bitcoind::new("side".into(), ctx.bitcoind_default_cfg("side"), None);
	side.start().await.unwrap();
	let side_chain = side.sync_client();
	for height in side_chain.get_block_count().unwrap() + 1..=fork.to_u32() as u64 {
		let raw = chain.call::<String>("getblock", &[json!(chain.get_block_hash(height).unwrap()), json!(0)]).unwrap();
		side_chain.call::<serde_json::Value>("submitblock", &[json!(raw)]).unwrap();
	}

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let old_hash = db.write(async |tx| {
		// Held until this transaction ends. Here only the decision reads this
		// table, after it took its snapshot.
		tx.batch_execute("LOCK TABLE lightning_payment_attempt_htlc_vtxo IN ACCESS EXCLUSIVE MODE").await?;
		assert_eq!(ctx.generate_blocks(1).await, BlockHeight::new(expiry));
		let old_hash = chain.get_block_hash(expiry as u64)?;
		wait_for_query_lock(tx, "SELECT DISTINCT a.id,a.lightning_htlc_subscription_id%").await?;

		// The new branch: the owner's exit at the expiry height, then one
		// more block, so Core switches to it.
		let miner = ctx.bitcoind().get_new_address().to_string();
		let exit_hex = exit.iter().map(serialize_hex).collect::<Vec<_>>();
		side_chain.call::<serde_json::Value>("generateblock", &[json!(miner), json!(exit_hex)])?;
		side_chain.call::<serde_json::Value>("generateblock", &[json!(miner), json!([])])?;
		for height in expiry as u64..=expiry as u64 + 1 {
			let raw = side_chain.call::<String>("getblock", &[json!(side_chain.get_block_hash(height)?), json!(0)])?;
			chain.call::<serde_json::Value>("submitblock", &[json!(raw)])?;
		}
		assert_ne!(chain.get_block_hash(expiry as u64)?, old_hash);

		// Release the decision once the watchman dropped the old block.
		async {
			loop {
				let stored = tx.query_opt("SELECT hash FROM watchmand_block WHERE height = $1",
					&[&i64::from(expiry)]).await?.map(|row| row.get::<_, String>("hash"));
				if stored != Some(old_hash.to_string()) {
					return Ok::<_, anyhow::Error>(());
				}
				tokio::time::sleep(poll_interval()).await;
			}
		}.wait_millis(60_000).await?;
		Ok(old_hash)
	}).await.unwrap();
	assert_eq!(allocation_count(&db).await, 0);

	// The stale decision reaches its write and aborts on the moved tip.
	let log = srv.watchmand().config().data_dir.join("stdout.log");
	async {
		while !std::fs::read_to_string(&log).unwrap().contains("published watchman tip changed") {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await;

	// Later passes see the exit on the chain.
	mine(&ctx, &srv, 2).await;
	assert_ne!(chain.get_block_hash(expiry as u64).unwrap(), old_hash);
	async {
		loop {
			if onchain_spend(&db, VtxoId::from(vtxo.chain_anchor())).await == Some(exit_txid) {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert_eq!(allocation_count(&db).await, 0, "an exited VTXO is not paid");
}

/// Restart bitcoind with an empty mempool and load its wallets again.
async fn restart_without_mempool(ctx: &TestContext) {
	let wallets = ctx.bitcoind().sync_client().list_wallets().unwrap();
	ctx.bitcoind().restart_wiping_mempool().await;
	for name in wallets {
		if !ctx.bitcoind().sync_client().list_wallets().unwrap().contains(&name) {
			ctx.bitcoind().load_wallet(&name).await;
		}
	}
}

/// Each of `vtxos` has one current payout, confirmed in `payers[vtxo]`.
/// Every other payout of it is conflicted.
async fn assert_paid_once(db: &Db, payers: &BTreeMap<VtxoId, Txid>) {
	for (vtxo, payer) in payers {
		let share = current_share(db, *vtxo).await.unwrap();
		assert_eq!(share.status, "confirmed");
		assert_eq!(share.tx.unwrap().compute_txid(), *payer);
	}
}

/// A holder exits one of two roots that expire together, and a reorg then
/// removes the exit and the holder's claim. Each root is paid exactly once.
#[tokio::test]
async fn expiry_payout_reorg_of_an_exit_pays_each_root_once() {
	let ctx = TestContext::new("server/expiry_payout_reorg_of_an_exit_pays_each_root_once").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(24);
		cfg.vtxo_exit_delta = BlockDelta::new(3);
	}).create().await;
	// The watchman stays unfunded until the new branch: each payout pays its
	// mining fee from the payout fee.
	let wallet = ctx.bark("holder", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	ctx.fund_bark(&wallet, sat(500_000)).await;
	let first = wallet.board(sat(100_000)).await;
	let second = wallet.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync().await;
	let client = wallet.client().await;
	let exiting = client.get_full_vtxo(first.vtxos[0]).await.unwrap();
	let untouched = client.get_full_vtxo(second.vtxos[0]).await.unwrap();
	let exiting_key = client.get_vtxo_key(&exiting).await.unwrap();
	let script = client.payout_script();
	drop(client);
	assert_eq!(exiting.expiry_height(), untouched.expiry_height());
	let roots = [exiting.chain_anchor(), untouched.chain_anchor()];
	let ids = [exiting.id(), untouched.id()];
	wallet.start_exit_vtxos([exiting.id()]).await;
	mine_past(&ctx, &srv, exiting.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut stored = BTreeMap::new();
	for (id, root) in ids.iter().zip(roots) {
		let (allocation, payout) = wait_payout(&db, *id).await;
		assert_eq!(payout.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), [root]);
		payout_output(&payout, &script, sat(98_000));
		stored.insert(allocation, payout);
	}
	// Drop both payouts from the mempool, then confirm the holder's exit of
	// the first root.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	restart_without_mempool(&ctx).await;
	progress_exit_until_awaiting_delta(&ctx, &wallet).await;
	let root_exit = exiting.transactions().find(|step|
		step.tx.input.iter().any(|input| input.previous_output == roots[0])).unwrap().tx.compute_txid();
	let core = ctx.bitcoind().sync_client();
	let conflict_block = core.custom_get_raw_transaction_info(root_exit, None).unwrap().unwrap().blockhash.unwrap();
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	async {
		while payout_shares(&db, ids[0]).await.iter().any(|share| share.status != "conflicted") {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;

	srv.watchmand().stop().await.unwrap();
	complete_exit(&ctx, &wallet).await;
	let claim_address = ctx.bitcoind().get_new_address();
	wallet.claim_exits([exiting.id()], &claim_address).await;
	ctx.generate_blocks(1).await;
	assert!(ctx.bitcoind().get_received_by_address(&claim_address) > sat(0));
	// The holder is gone, so it cannot broadcast its exit again.
	drop(wallet);
	srv.watchmand().start().await.unwrap();
	let claim = async {
		loop {
			if let Some(txid) = onchain_spend(&db, exiting.id()).await {
				break txid;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert_ne!(current_share(&db, ids[1]).await.unwrap().status, "conflicted",
		"the untouched root keeps its decision");
	// The holder put the VTXO on chain itself, so it gets no payout.
	let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: exiting.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(exiting.id(), &exiting_key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.spend_state, protos::VtxoSpendState::Spent as i32);
	assert!(status.expiry_payout.is_none());
	let old_tip = core_tip(&ctx).await;
	wait_watchman_tip(&db, old_tip).await;

	// Remove the block of the exit, and with it the claim.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	core.invalidate_block(&conflict_block).unwrap();
	let removed = old_tip.height.to_u32() - core_tip(&ctx).await.height.to_u32();
	restart_without_mempool(&ctx).await;
	// A restarted bitcoind has a new cookie.
	let core = ctx.bitcoind().sync_client();
	for root in roots {
		assert!(core.get_tx_out(&root.txid, root.vout, Some(true)).unwrap().is_some(), "the roots are back");
	}
	core.generate_to_address(u64::from(removed + 2), &ctx.bitcoind().get_new_address()).unwrap();
	// Two payouts may each need a watchman input.
	for _ in 0..2 {
		ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	}
	ctx.bitcoind().generate(2).await;
	let new_tip = core_tip(&ctx).await;
	assert!(new_tip.height > old_tip.height);
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	async {
		while db.read(async |t| t.get_highest_block(BlockTable::Captaind).await).await.unwrap() != Some(new_tip) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	wait_watchman_tip(&db, new_tip).await;
	assert_ne!(onchain_spend(&db, exiting.id()).await, Some(claim), "the removed claim is not the spend of the VTXO");

	// Both roots are paid again; the stored payouts do not change.
	let covered = async {
		loop {
			let mempool = core.get_raw_mempool().unwrap();
			let mut covered = BTreeSet::new();
			for id in ids {
				for share in payout_shares(&db, id).await {
					let Some(tx) = share.tx else { continue };
					if let Some(old) = stored.get(&share.allocation) {
						assert_eq!(*old, tx, "a signed payout does not change");
					}
					if mempool.contains(&tx.compute_txid()) {
						covered.extend(tx.input.iter().map(|input| input.previous_output));
					}
					stored.insert(share.allocation, tx);
				}
			}
			if roots.iter().all(|root| covered.contains(root)) {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	};
	covered.wait_millis(30_000).await;
	mine(&ctx, &srv, 6).await;
	wait_synced(&ctx, &srv, &db).await;
	let mut payers = BTreeMap::new();
	for (id, root) in ids.iter().zip(roots) {
		let payers_of_root = stored.values().filter(|tx| {
			tx.input.iter().any(|input| input.previous_output == root)
				&& core.custom_get_raw_transaction_info(tx.compute_txid(), None).unwrap()
					.is_some_and(|info| info.confirmations.unwrap_or(0) > 0)
		}).collect::<Vec<_>>();
		assert_eq!(payers_of_root.len(), 1, "each root is paid exactly once");
		payout_output(payers_of_root[0], &script, sat(98_000));
		payers.insert(*id, payers_of_root[0].compute_txid());
	}
	assert_paid_once(&db, &payers).await;

	// Making the shorter old branch valid again changes nothing.
	core.reconsider_block(&conflict_block).unwrap();
	assert_eq!(core_tip(&ctx).await.height, new_tip.height + 6);
	mine(&ctx, &srv, 1).await;
	wait_synced(&ctx, &srv, &db).await;
	assert_paid_once(&db, &payers).await;
	assert!(core.custom_get_raw_transaction_info(claim, None).unwrap()
		.is_none_or(|info| info.confirmations.unwrap_or(0) == 0));
}

/// The grants of a receive are reclaimed by the operator on chain, and a
/// reorg five blocks deep, before the sender's refund, removes those claims.
/// The receiver then claims the grants with the preimage. The sender is not
/// refunded as well.
#[tokio::test]
async fn expiry_payout_reorg_of_grant_claims_pays_receiver() {
	let ctx = TestContext::new("server/expiry_payout_reorg_of_grant_claims_pays_receiver").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).watchmand().cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![server::vtxopool::VtxoTarget { amount: sat(50_000), count: 4 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let start = ctx.bitcoind().get_block_count().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = recipient.bolt11_invoice(sat(90_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receiver_key = receive_claim_keypair(&srv, &recipient, hash).await;
	let receiver_script = recipient.payout_script();
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = super::full_vtxos(&sender).await.pop().unwrap();
	let sender_script = sender.payout_script();
	let (source, key) = htlc_send(&ctx, &srv, &sender, input, hash).await;
	let mut rpc = srv.get_public_rpc().await;
	lightning.sync().await;
	rpc.initiate_lightning_payment(send_request(&srv, &invoice, sat(90_000), &[source.id()], &key).await)
		.await.unwrap();
	let deadline = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32) + BlockDelta::new(36);
	let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		payment_hash: hash.to_vec(),
		user_pubkey: receiver_key.public_key().serialize().to_vec(),
		htlc_recv_expiry: deadline.to_u32(),
		lightning_receive_anti_dos: None,
		claim_attestation: Some(ark::attestations::LightningReceiveClaimAttestation::new(
			hash, deadline, &receiver_key).serialize()),
	}).await.unwrap().into_inner().htlc_vtxos.iter()
		.map(|raw| <Vtxo<Full> as ark::ProtocolEncoding>::deserialize(raw).unwrap()).collect::<Vec<_>>();
	assert_eq!(grants.iter().map(|grant| grant.amount()).sum::<bitcoin::Amount>(), sat(90_000));
	drop(sender);
	// Put the grants on chain, where the receiver could claim them.
	for grant in &grants {
		confirm_exit_path(&ctx, grant).await;
	}
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let core = ctx.bitcoind().sync_client();
	let depth = |txid: Txid| core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap()
		.confirmations.unwrap_or(0);

	// Mine until the operator's claims of the grants are five blocks deep.
	let reclaims = async {
		loop {
			mine(&ctx, &srv, 1).await;
			assert!(current_share(&db, source.id()).await.is_none_or(|share| share.owner.is_none()),
				"the sender is refunded before the grant claims are six blocks deep");
			let Some(closures) = grant_closures(&db, &grants).await else { continue };
			let reclaims = closures.into_values().collect::<BTreeSet<_>>();
			for txid in &reclaims {
				let claim = ctx.bitcoind().await_transaction(*txid).await;
				assert!(claim.output.iter().all(|output| output.script_pubkey != receiver_script));
			}
			if reclaims.iter().all(|txid| depth(*txid) == 5) {
				break reclaims;
			}
		}
	}.wait_millis(200_000).await;
	wait_synced(&ctx, &srv, &db).await;
	assert!(current_share(&db, source.id()).await.is_none_or(|share| share.owner.is_none()));

	// The reorg replays the five blocks without the claims and their children.
	let old_tip = core.get_block_count().unwrap();
	let fork = old_tip + 1 - 5;
	let mut excluded = reclaims.clone();
	let mut replay = Vec::<Vec<Transaction>>::new();
	for height in fork..=old_tip {
		let block = core.get_block(&core.get_block_hash(height).unwrap()).unwrap();
		let mut kept = Vec::new();
		for tx in block.txdata.into_iter().skip(1) {
			if excluded.contains(&tx.compute_txid()) || tx.input.iter().any(|i| excluded.contains(&i.previous_output.txid)) {
				excluded.insert(tx.compute_txid());
			} else {
				kept.push(tx);
			}
		}
		replay.push(kept);
	}
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	core.invalidate_block(&core.get_block_hash(fork).unwrap()).unwrap();
	let miner = ctx.bitcoind().get_new_address().to_string();
	let generate = |txs: &[Transaction]| {
		core.call::<serde_json::Value>("generateblock",
			&[json!(miner), json!(txs.iter().map(serialize_hex).collect::<Vec<_>>())]).unwrap();
	};
	for txs in &replay {
		generate(txs);
	}

	// The receiver claims every grant with the preimage.
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: Vec::new(),
		output: vec![TxOut { value: sat(88_000), script_pubkey: receiver_script.clone() }],
	};
	let clauses = grants.iter().map(|grant| grant.policy().as_server_htlc_recv().unwrap()
		.user_reveals_preimage_clause(grant.exit_delta())).collect::<Vec<_>>();
	for (grant, clause) in grants.iter().zip(&clauses) {
		claim.input.push(TxIn {
			previous_output: grant.point(), script_sig: Default::default(),
			sequence: clause.sequence(), witness: Witness::new(),
		});
	}
	let prevouts = grants.iter().map(Vtxo::txout).collect::<Vec<_>>();
	for (index, (grant, clause)) in grants.iter().zip(&clauses).enumerate() {
		claim.input[index].witness = recipient.sign_input_with_clause(grant, &clause.clone().into(), index,
			&mut SighashCache::new(&claim), &Prevouts::All(&prevouts)).await.unwrap();
	}
	for _ in 0..200 {
		if core.test_mempool_accept(&[&claim]).unwrap()[0].allowed {
			break;
		}
		generate(&[]);
	}
	generate(std::slice::from_ref(&claim));
	assert!(depth(claim.compute_txid()) > 0);
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();

	// However long the server runs, the sender is not paid as well.
	for _ in 0..20 {
		mine(&ctx, &srv, 1).await;
	}
	assert!(current_share(&db, source.id()).await.is_none_or(|share| share.owner.is_none()));
	assert!(outputs_to(&ctx, &sender_script, start).is_empty());
	assert_eq!(outputs_to(&ctx, &receiver_script, start), [(bitcoin::OutPoint::new(claim.compute_txid(), 0), sat(88_000))]);
}
