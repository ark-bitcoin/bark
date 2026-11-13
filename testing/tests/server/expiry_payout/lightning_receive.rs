use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Transaction, TxIn, TxOut, Witness};
use bitcoin::secp256k1::Keypair;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};
use cln_rpc::plugins::hold;

use ark::{ProtocolEncoding, SECP, Vtxo, VtxoId, VtxoPolicy};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::{LightningReceiveClaimAttestation, VtxoStatusAttestation};
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use ark::vtxo::policy::signing::VtxoSigner;
use bark::actions::lightning::receive::LightningReceiveState;
use server::database::Db;
use server::database::htlc_vtxo::HtlcResolution;
use server::database::expiry_payout::ownership::OwnershipDisposition;
use server::vtxopool::VtxoTarget;
use server_rpc::protos;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::util::{poll_interval, FutureExt};

use crate::lightning::{lightning_subscription_status, wait_for_subscription_status};
use super::{
	assert_paid, bind_outputs, birth_owner, confirm_exit_path, current_share, decide_during, fund_watchman,
	grant_closures, htlc_send, lightning_payout_server, mine, mine_past, miner_fee, onchain_spend,
	operator_script, outputs_to, payout_shares, proposal, receive_claim_keypair, revoke, send_request,
	wait_payout, wait_synced,
};

/// A server in payout mode with a short-lived VTXO pool of `amount` VTXOs,
/// whose receives grant HTLCs that expire with their tree.
async fn grant_server(ctx: &TestContext, lightning: &ark_testing::context::LightningPaymentSetup, lifetime: u16, amount: Amount)
	-> Arc<Captaind>
{
	let srv = ctx.captaind("server").lightningd(&lightning.internal).bitcoind(ctx.bitcoind_arc())
		.funded(btc(10)).watchmand().cfg(move |cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(lifetime);
			cfg.vtxopool.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxopool.vtxo_pre_expiry = BlockDelta::new(2);
			cfg.vtxopool.vtxo_targets = vec![VtxoTarget { amount, count: 8 }];
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).create().await;
	srv.wait_for_vtxopool(ctx).await;
	srv
}

/// Grant the receive of `hash` to `key` until `deadline`.
async fn grants(srv: &Captaind, hash: PaymentHash, key: &Keypair, deadline: BlockHeight) -> Vec<Vtxo<Full>> {
	srv.get_public_rpc().await.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		payment_hash: hash.to_vec(),
		user_pubkey: key.public_key().serialize().to_vec(),
		htlc_recv_expiry: deadline.to_u32(),
		lightning_receive_anti_dos: None,
		claim_attestation: Some(LightningReceiveClaimAttestation::new(hash, deadline, key).serialize()),
	}).await.unwrap().into_inner().htlc_vtxos.iter().map(|raw| Vtxo::<Full>::deserialize(raw).unwrap()).collect()
}

/// Mine a block at a time until `vtxo` is paid out.
async fn mine_until_paid(ctx: &TestContext, srv: &Captaind, db: &Db, vtxo: VtxoId) -> Transaction {
	for _ in 0..100 {
		if let Some(share) = current_share(db, vtxo).await.filter(|share| share.published) {
			return share.tx.unwrap();
		}
		mine(ctx, srv, 1).await;
	}
	panic!("{vtxo} was not paid out");
}

/// A Lightning payer can give its HTLC a far expiry. A payout server still
/// refuses HTLC grants that expire later than a new send could, because a
/// grant that has not expired holds the payout of its whole tree, and the
/// receiver claims with grants at the expiry that the wallet asks for.
#[tokio::test]
async fn expiry_payout_far_htlc_grant_is_refused() {
	let ctx = TestContext::new("server/expiry_payout_far_htlc_grant_is_refused").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	srv.wait_for_vtxopool(&ctx).await;
	let receiver = ctx.bark_sdk("receiver", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	lightning.sync().await;
	let invoice = receiver.bolt11_invoice(sat(100_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (paid, ()) = tokio::join!(lightning.external.try_pay_bolt11(invoice.to_string()), async {
		srv.wait_for_lightning_receive_accepted(hash).await;
		// Stand in for a payer that gave its HTLC a far expiry.
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let far = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(7);
		let incoming = i64::from(far + BlockDelta::new(100));
		db.write(async |t| Ok(t.execute("
			UPDATE lightning_htlc_subscription SET lowest_incoming_htlc_expiry = $2, updated_at = NOW()
			WHERE payment_hash = $1
		", &[&hash.to_string(), &incoming]).await?)).await.unwrap();
		let key = receive_claim_keypair(&srv, &receiver, hash).await;
		let error = srv.get_public_rpc().await.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
			payment_hash: hash.to_vec(),
			user_pubkey: key.public_key().serialize().to_vec(),
			htlc_recv_expiry: far.to_u32(),
			lightning_receive_anti_dos: None,
			claim_attestation: Some(LightningReceiveClaimAttestation::new(hash, far, &key).serialize()),
		}).await.unwrap_err();
		assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
		assert!(error.message().contains("too high"), "{error}");
		assert!(matches!(receiver.try_claim_lightning_receive(hash, true).await.unwrap(), LightningReceiveState::Settled(_)));
	});
	paid.expect("the Lightning payment succeeds");
}

/// One payment attempt spends two sources to pay a receive on the same
/// server. The sender claims the first source on chain itself and goes
/// away with the receiver. The second source is still paid to the sender,
/// and the first is not paid twice.
#[tokio::test]
async fn expiry_payout_pays_unclaimed_source_of_partial_send() {
	let ctx = TestContext::new("server/expiry_payout_pays_unclaimed_source_of_partial_send").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = grant_server(&ctx, &lightning, 24, sat(50_000)).await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let invoice = recipient.bolt11_invoice(sat(180_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receive_key = receive_claim_keypair(&srv, &recipient, hash).await;
	let receiver_script = recipient.payout_script();
	let actor = ctx.bark("sender", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(400_000)).create().await;
	actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	actor.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let sender = actor.client().await;
	let mut inputs = Vec::new();
	let mut keys = Vec::new();
	for vtxo in super::full_vtxos(&sender).await {
		keys.push(sender.get_vtxo_key(&vtxo).await.unwrap());
		inputs.push(vtxo);
	}
	// One attempt pays with two HTLC-send VTXOs of one key.
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(inputs,
		VtxoPolicy::new_server_htlc_send(keys[0].public_key(), hash, deadline)).unwrap()
		.generate_user_nonces(&keys).unwrap();
	let request = super::bind_to_wallets(&srv, &[&sender], builder.cosign_request().into()).await;
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest { parts: request.parts })
		.await.unwrap().into_inner();
	let sources = builder.user_cosign(&keys, response.try_into().unwrap()).unwrap().build_signed_vtxos();
	assert_eq!(sources.len(), 2);
	sender.register_vtxo_transactions_with_server(&sources).await.unwrap();
	let script = sender.payout_script();
	let ids = sources.iter().map(|source| source.id()).collect::<Vec<_>>();
	lightning.sync().await;
	rpc.initiate_lightning_payment(send_request(&srv, &invoice, sat(180_000), &ids, &keys[0]).await)
		.await.unwrap();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let grants = grants(&srv, hash, &receive_key, tip + BlockDelta::new(36)).await;
	assert_eq!(grants.iter().map(|grant| grant.amount()).sum::<Amount>(), sat(180_000));

	// The grants are on chain, and the sender claims the first source with
	// its timeout clause while the watchman is down.
	srv.watchmand().stop().await.unwrap();
	for grant in &grants {
		confirm_exit_path(&ctx, grant).await;
	}
	let (claimed, unclaimed) = (&sources[0], &sources[1]);
	confirm_exit_path(&ctx, claimed).await;
	let clause = claimed.policy().as_server_htlc_send().unwrap().user_claim_after_expiry_clause(claimed.exit_delta());
	let core = ctx.bitcoind().sync_client();
	let confirmations = core.get_tx_out(&claimed.point().txid, claimed.point().vout, Some(true)).unwrap().unwrap()
		.confirmations as u32;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let mature = deadline.to_u32().max(tip + 1 - confirmations + clause.block_delta.to_u32()) + 1;
	if mature > tip {
		ctx.generate_blocks(mature - tip).await;
	}
	let mut claim = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: clause.locktime(),
		input: vec![TxIn {
			previous_output: claimed.point(), script_sig: Default::default(),
			sequence: clause.sequence(), witness: Witness::new(),
		}],
		output: vec![TxOut { value: sat(98_000), script_pubkey: actor.get_onchain_address().await.script_pubkey() }],
	};
	claim.input[0].witness = sender.sign_input_with_clause(claimed, &clause.clone().into(), 0,
		&mut SighashCache::new(&claim), &Prevouts::All(&[claimed.txout()])).await.unwrap();
	core.send_raw_transaction(&claim).unwrap();
	ctx.generate_blocks(6).await;
	drop(sender);
	drop(recipient);
	for _ in 0..4 {
		ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(150_000)).await;
	}
	ctx.generate_blocks(2).await;
	srv.watchmand().start().await.unwrap();

	// The watchman records the claim before it decides anything for the
	// grants or the sources.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	async {
		while onchain_spend(&db, claimed.id()).await != Some(claim.compute_txid()) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(payout_shares(&db, claimed.id()).await.is_empty());

	let payout = mine_until_paid(&ctx, &srv, &db, unclaimed.id()).await;
	let mut path = unclaimed.transactions().map(|step| OutPoint::new(step.tx.compute_txid(), step.output_idx as u32))
		.collect::<BTreeSet<_>>();
	path.insert(unclaimed.chain_anchor());
	assert!(payout.input.iter().any(|input| path.contains(&input.previous_output)));
	assert!(payout.output.iter().all(|output| output.script_pubkey != receiver_script));
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	for txid in grant_closures(&db, &grants).await.expect("the grants are reclaimed").into_values() {
		let closure = ctx.bitcoind().await_transaction(txid).await;
		assert!(closure.output.iter().all(|output| output.script_pubkey != receiver_script));
	}
	async {
		while current_share(&db, unclaimed.id()).await.unwrap().status != "confirmed" {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	let htlc = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, claimed.id()).await).await.unwrap().unwrap();
	assert_eq!((htlc.htlc.offchain_resolution, htlc.htlc.chain_resolution), (None, Some(HtlcResolution::Revoked)));
	assert!(payout_shares(&db, claimed.id()).await.iter().all(|share| share.owner.is_none()),
		"the claimed source is not paid again");
}

/// An intra-Ark payment pays a receive, and the receive is never claimed.
/// The grants go on chain and the operator takes them back with their
/// timeout clause. The sender is refunded only once those claims are six
/// blocks deep, and the receiver is never paid.
#[tokio::test]
async fn expiry_payout_refunds_sender_after_grants_reclaimed() {
	let ctx = TestContext::new("server/expiry_payout_refunds_sender_after_grants_reclaimed").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	// The pool has 45,000-sat VTXOs, so one grant is a 330-sat leaf.
	let srv = grant_server(&ctx, &lightning, 400, sat(45_000)).await;
	let start = ctx.bitcoind().get_block_count().await;
	let recipient = ctx.bark_sdk("recipient", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	recipient.stop_daemon_wait().await.unwrap();
	let invoice = recipient.bolt11_invoice(sat(90_330), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	let receive_key = receive_claim_keypair(&srv, &recipient, hash).await;
	let receiver_script = recipient.payout_script();
	drop(recipient);
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(100_000)).cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	let input = super::full_vtxos(&sender).await.pop().unwrap();
	let script = sender.payout_script();
	let (source, key) = htlc_send(&ctx, &srv, &sender, input, hash).await;
	drop(sender);
	lightning.sync().await;
	srv.get_public_rpc().await.initiate_lightning_payment(
		send_request(&srv, &invoice, sat(90_330), &[source.id()], &key).await,
	).await.unwrap();
	let deadline = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32) + BlockDelta::new(36);
	let grants = grants(&srv, hash, &receive_key, deadline).await;
	assert_eq!(grants.len(), 3);
	assert!(grants.iter().any(|grant| grant.amount() == sat(330)));
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let operator = operator_script(&srv);

	srv.watchmand().stop().await.unwrap();
	let mut mature = deadline.to_u32();
	for grant in &grants {
		confirm_exit_path(&ctx, grant).await;
		mature = mature.max(ctx.bitcoind().get_block_count().await as u32 + grant.exit_delta().to_u32())
			.max(grant.expiry_height().to_u32());
	}
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	ctx.generate_blocks(mature.saturating_sub(tip)).await;
	srv.watchmand().start().await.unwrap();
	let core = ctx.bitcoind().sync_client();
	let depth = |txid| core.custom_get_raw_transaction_info(txid, None).unwrap().unwrap().confirmations.unwrap_or(0);
	let closures = async {
		loop {
			mine(&ctx, &srv, 1).await;
			if let Some(closures) = grant_closures(&db, &grants).await {
				break closures;
			}
		}
	}.wait_millis(45_000).await;
	for txid in closures.values() {
		let closure = ctx.bitcoind().await_transaction(*txid).await;
		assert!(miner_fee(&ctx, &closure).await > Amount::ZERO);
		assert!(closure.output.iter().all(|output| output.script_pubkey == operator),
			"the operator takes back the grants");
	}
	let shallowest = || closures.values().map(|txid| depth(*txid)).min().unwrap();
	assert!(shallowest() < 6);
	while shallowest() < 5 {
		mine(&ctx, &srv, 1).await;
	}
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	wait_synced(&ctx, &srv, &db).await;
	assert!(matches!(proposal(&db, &source, tip).await.disposition, OwnershipDisposition::Unresolved(_)),
		"the sender waits for six confirmations of the grant claims");
	let tip = mine(&ctx, &srv, 1).await;
	wait_synced(&ctx, &srv, &db).await;
	// The watchman records the depth of the grant claims as it processes
	// the block.
	let owner = birth_owner(&db, source.id()).await;
	async {
		while proposal(&db, &source, tip).await.disposition != owner {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;

	// The refund is paid with the expired tree of the source.
	mine_past(&ctx, &srv, BlockHeight::new(source.expiry_height().to_u32() - 40)).await;
	let payout = mine_until_paid(&ctx, &srv, &db, source.id()).await;
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	assert_eq!(outputs_to(&ctx, &script, start).len(), 1, "the sender is paid once");
	assert!(outputs_to(&ctx, &receiver_script, start).is_empty(), "the receiver is never paid");
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	let htlc = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
	assert!(htlc.htlc.offchain_resolution.is_none(), "an expiry payout does not revoke the HTLC");
}

/// A claim of a receive whose grants are decided for an expiry payout while
/// the claim waits is refused, and its preimage is not stored.
#[tokio::test]
async fn expiry_payout_decided_grant_claim_stores_no_preimage() {
	let ctx = TestContext::new("server/expiry_payout_decided_grant_claim_stores_no_preimage").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	srv.wait_for_vtxopool(&ctx).await;
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let receiver = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(receiver.public_key());
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: hash.to_vec(), amount_sat: 100_000,
		min_cltv_delta: srv.config().max_user_invoice_cltv_delta.into(),
		mailbox_id: Some(mailbox.serialize()), description: None, expiry_secs: None,
		claim_pubkey: Some(receiver.public_key().serialize().to_vec()), ark_address_hint: false,
	}).await.unwrap().into_inner().bolt11;
	let payer = lightning.external;
	let payment = tokio::spawn(async move { payer.try_pay_bolt11(invoice).await });
	srv.wait_for_lightning_receive_accepted(hash).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let sub = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap();
	let expiry = sub.lowest_incoming_htlc_expiry.unwrap().saturating_sub(srv.config().htlc_expiry_delta);
	let grants = grants(&srv, hash, &receiver, expiry).await;
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		grants.clone(), VtxoPolicy::new_pubkey(receiver.public_key()),
	).unwrap().generate_user_nonces(&vec![receiver; grants.len()]).unwrap();
	let mut package = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut package, &receiver, mailbox).await;
	let ids = grants.iter().map(|grant| grant.id()).collect::<Vec<_>>();
	let refusal = decide_during(&db, &ids, async move {
		rpc.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
			payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(), cosign_request: Some(package),
		}).await
	}).await.unwrap_err();
	assert_eq!(refusal.metadata().get("expiry-payout-reason").unwrap(), "decided_for_payout");
	assert!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap().is_none());
	payment.abort();
}

/// A receive paid over Lightning does not become the collateral of an Ark
/// sender that pays the same invoice and fails: its attempt is failed and
/// unlinked, and its source can still be revoked.
#[tokio::test]
async fn expiry_payout_failed_intra_ark_payment_takes_no_grants() {
	let ctx = TestContext::new("server/expiry_payout_failed_intra_ark_payment_takes_no_grants").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.receive_htlc_forward_timeout = Duration::from_secs(3600); })
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000)).cfg(|cfg| cfg.daemon_manual_sync = true)
		.create().await;
	let hash = Preimage::random().compute_payment_hash();
	let receiver = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: hash.to_vec(), amount_sat: 90_000, min_cltv_delta: 58,
		mailbox_id: Some(MailboxIdentifier::from_pubkey(receiver.public_key()).serialize()),
		description: None, expiry_secs: None,
		claim_pubkey: Some(receiver.public_key().serialize().to_vec()), ark_address_hint: false,
	}).await.unwrap().into_inner().bolt11;
	lightning.sync().await;
	let payment = tokio::spawn({
		let invoice = invoice.clone();
		let mut payer = lightning.external.grpc_client().await;
		async move { payer.xpay(cln_rpc::XpayRequest { invstring: invoice, ..Default::default() }).await }
	});
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_for_subscription_status(&db, hash, "accepted").await;
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	assert!(!grants(&srv, hash, &receiver, tip + BlockDelta::new(32)).await.is_empty());
	wait_for_subscription_status(&db, hash, "htlcs-ready").await;

	let input = super::full_vtxos(&wallet).await.pop().unwrap();
	let (source, key) = htlc_send(&ctx, &srv, &wallet, input, hash).await;
	rpc.initiate_lightning_payment(send_request(&srv, &invoice, sat(90_000), &[source.id()], &key).await)
		.await.unwrap();
	let records = db.read(async |t| {
		let row = t.query_one("
			SELECT
				(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash = $1
					AND status = 'failed' AND lightning_htlc_subscription_id IS NULL),
				(SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash = $1),
				(SELECT COUNT(*) FROM cln_xpay WHERE payment_hash = $1)
		", &[&hash.to_string()]).await?;
		Ok((row.get::<_, i64>(0), row.get::<_, i64>(1), row.get::<_, i64>(2)))
	}).await.unwrap();
	assert_eq!(records, (1, 1, 0), "one failed, unlinked attempt and no Lightning payment");
	revoke(&srv, &wallet, &[source], &key).await.expect("the failed sender keeps its refund");
	assert_eq!(lightning_subscription_status(&db, hash).await.as_deref(), Some("htlcs-ready"));
	assert!(!payment.is_finished(), "the Lightning payer stays held");
	payment.abort();
}

/// The Lightning node cancels an external receive while the server is
/// down, after the preimage was stored but before the receive was settled.
/// The server then takes the expired root of the grant back in one payout,
/// without a separate claim of the grant.
#[tokio::test]
async fn expiry_payout_sweeps_root_of_a_cancelled_receive() {
	let ctx = TestContext::new("server/expiry_payout_sweeps_root_of_a_cancelled_receive").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let payer = Arc::new(lightning.external);
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(btc(10)).watchmand().cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.receive_htlc_forward_timeout = Duration::from_secs(120);
			cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		}).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let receiver = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(receiver.public_key());
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: hash.to_vec(), amount_sat: 100_000,
		min_cltv_delta: srv.config().max_user_invoice_cltv_delta.into(),
		mailbox_id: Some(mailbox.serialize()), description: None, expiry_secs: None,
		claim_pubkey: Some(receiver.public_key().serialize().to_vec()), ark_address_hint: false,
	}).await.unwrap().into_inner().bolt11;
	let pay = tokio::spawn({
		let (payer, invoice) = (payer.clone(), invoice.clone());
		async move { payer.try_pay_bolt11(invoice).await }
	});
	wait_for_subscription_status(&db, hash, "accepted").await;
	let incoming_expiry = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap()
		.unwrap().lowest_incoming_htlc_expiry.unwrap();
	let deadline = incoming_expiry.saturating_sub(srv.config().htlc_expiry_delta);
	let grants = grants(&srv, hash, &receiver, deadline).await;
	assert_eq!(grants.len(), 1);
	let grant = &grants[0];
	let root = grant.chain_anchor();
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		grants.clone(), VtxoPolicy::new_pubkey(receiver.public_key()),
	).unwrap().generate_user_nonces(&[receiver]).unwrap();
	let mut package = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut package, &receiver, mailbox).await;

	// The Lightning node is down when the claim settles the invoice. The
	// preimage is stored, but the receive is not settled.
	lightning.internal.stop().await.unwrap();
	rpc.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(), cosign_request: Some(package),
	}).wait_millis(10_000).await.expect_err("the invoice cannot be settled without its node");
	assert_eq!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();

	// The node comes back and cancels the invoice before the server returns.
	lightning.internal.start().await.unwrap();
	lightning.internal.hold_client().await.cancel(hold::CancelRequest { payment_hash: hash.to_vec() })
		.await.unwrap();
	lightning.internal.connect(&payer).await;
	assert!(pay.wait_millis(30_000).await.unwrap().is_err());
	// The node got new ports when it restarted.
	let (grpc, plugin) = (lightning.internal.grpc_details().await, lightning.internal.hold_details().await);
	{
		let mut cfg = srv.config_mut();
		cfg.vtxopool.vtxo_targets.clear();
		let node = &mut cfg.cln_array[0];
		node.uri = grpc.uri.parse().unwrap();
		node.hold_invoice.as_mut().unwrap().uri = plugin.uri.parse().unwrap();
	}
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	mine_past(&ctx, &srv, incoming_expiry).await;
	wait_for_subscription_status(&db, hash, "canceled").await;

	let fee_input = fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, grant.expiry_height()).await;
	let (allocation, payout) = wait_payout(&db, grant.id()).await;
	assert!(payout.input.iter().any(|input| input.previous_output == root), "the root is swept directly");
	assert!(payout.input.iter().all(|input| input.previous_output == root || input.previous_output == fee_input));
	assert!(payout.output.iter().all(|output| output.script_pubkey == operator_script(&srv)));
	assert_eq!(super::payout_attempts(&db, allocation).await[&payout.compute_txid()], miner_fee(&ctx, &payout).await);
	mine(&ctx, &srv, 6).await;
	super::assert_six_deep(&ctx, &payout);
	async {
		while current_share(&db, grant.id()).await.unwrap().status != "confirmed" {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(10_000).await;
	assert_eq!(current_share(&db, grant.id()).await.unwrap().owner, None);
}

/// A forwarded receive is settled but its claim output is never registered.
/// Its grants still belong to the provider that started the receive, and
/// are paid out to it.
#[tokio::test]
async fn expiry_payout_pays_unclaimed_forward_to_provider() {
	let ctx = TestContext::new("server/expiry_payout_pays_unclaimed_forward_to_provider").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let payer = Arc::new(lightning.external);
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.funded(btc(10)).watchmand().cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxopool.vtxo_targets = vec![VtxoTarget { count: 2, amount: sat(100_000) }];
		}).create().await;
	srv.wait_for_vtxopool(&ctx).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let provider = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let grant_key = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let provider_script = ark::expiry_payout::payout_script(provider.public_key());
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let mut rpc = srv.get_public_rpc().await;
	let invoice = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: hash.to_vec(), amount_sat: 100_000,
		min_cltv_delta: srv.config().max_user_invoice_cltv_delta.into(),
		mailbox_id: Some(MailboxIdentifier::from_pubkey(provider.public_key()).serialize()),
		description: None, expiry_secs: None,
		claim_pubkey: Some(grant_key.public_key().serialize().to_vec()), ark_address_hint: false,
	}).await.unwrap().into_inner().bolt11;
	let pay = tokio::spawn({
		let payer = payer.clone();
		async move { payer.try_pay_bolt11(invoice).await }
	});
	wait_for_subscription_status(&db, hash, "accepted").await;
	let incoming_expiry = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap()
		.unwrap().lowest_incoming_htlc_expiry.unwrap();
	let deadline = incoming_expiry.saturating_sub(srv.config().htlc_expiry_delta);
	let grants = grants(&srv, hash, &grant_key, deadline).await;
	let ids = grants.iter().map(|grant| grant.id()).collect::<Vec<_>>();
	let owners = db.read(async |t| t.vtxo_owner_mailboxes(&ids).await).await.unwrap();
	assert!(ids.iter().all(|id| owners.get(id) == Some(&provider.public_key())));

	// The preimage reaches the server without a claim, which settles the
	// invoice.
	assert!(db.write(async |t| t.store_htlc_settlement(preimage).await).await.unwrap().is_some());
	wait_for_subscription_status(&db, hash, "settled").await;
	pay.wait_millis(30_000).await.unwrap().expect("the invoice is paid");

	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let latest = grants.iter().map(|grant| grant.expiry_height()).max().unwrap();
	mine_past(&ctx, &srv, latest).await;
	let status = async |grant: &Vtxo<Full>| srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: grant.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(grant.id(), &grant_key).serialize(),
	}).await.unwrap().into_inner();
	for grant in &grants {
		let (_, payout) = wait_payout(&db, grant.id()).await;
		assert!(payout.output.iter().any(|out| out.script_pubkey == provider_script));
		assert_eq!(current_share(&db, grant.id()).await.unwrap().owner, Some(provider.public_key().to_string()));
	}
	assert_eq!(status(&grants[0]).await.expiry_payout.map(|p| p.state), Some(protos::ExpiryPayoutState::Pending as i32),
		"a payout is pending until it is six blocks deep");
	mine(&ctx, &srv, 6).await;
	for grant in &grants {
		let status = status(grant).await;
		assert_eq!(status.owner_mailbox, provider.public_key().serialize().to_vec());
		assert_eq!(status.expiry_payout.map(|p| p.state), Some(protos::ExpiryPayoutState::Paid as i32));
	}
}
