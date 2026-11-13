use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, BlockHash};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight, BlockRef};
use bitcoin_ext::rpc::RpcApi;
use cln_rpc::listpays_pays::ListpaysPaysStatus;
use cln_rpc::plugins::hold;

use ark::{ProtocolEncoding, SECP, Vtxo, VtxoId, VtxoPolicy};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::LightningReceiveClaimAttestation;
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::Full;
use bark::LightningSendOptions;
use bark::actions::lightning::pay::{LightningSendState, Progress};
use bark::lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use server::database::{BlockTable, Db};
use server::database::expiry_payout::ownership::OwnershipDisposition;
use server::database::ln::{LightningHtlcSubscriptionStatus, LightningPaymentStatus};
use server_log::ExpiryHoldObserved;
use server_rpc::protos;
use server_rpc::protos::lightning_payment_status::PaymentStatus;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::daemon::lightningd::Lightningd;
use ark_testing::exit::complete_exit;
use ark_testing::lightning::sign_lightning_send_request;
use ark_testing::util::{poll_interval, FutureExt};

use crate::lightning::{htlc_send_vtxo_ids, is_preimage_recorded, wait_for_hold_invoice_accepted, wait_for_subscription_status};
use super::{
	assert_paid, bind_outputs, bind_to_wallets, birth_owner, current_share, decide_during, fund_watchman,
	full_vtxos, lightning_payout_server, mine, mine_past, outputs_to, payout_output, payout_shares, proposal,
	revoke, send_request, wait_for_query_lock, wait_payout, wait_synced,
};

/// The status of the latest payment attempt for `hash`.
async fn latest_attempt(db: &Db, hash: PaymentHash) -> Option<LightningPaymentStatus> {
	db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap()
		.map(|attempt| attempt.status)
}

/// Wait until the latest payment attempt for `hash` has `status`.
async fn wait_attempt(db: &Db, hash: PaymentHash, status: LightningPaymentStatus) {
	async {
		while latest_attempt(db, hash).await != Some(status) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(45_000).await
}

async fn attempt_count(db: &Db, hash: PaymentHash) -> i64 {
	db.read(async |t| Ok(t.query_one("SELECT COUNT(*) FROM lightning_payment_attempt WHERE payment_hash = $1",
		&[&hash.to_string()]).await?.get(0))).await.unwrap()
}

/// The payments of `node` for `hash`.
async fn pays(node: &Lightningd, hash: PaymentHash) -> Vec<cln_rpc::ListpaysPays> {
	node.grpc_client().await.list_pays(cln_rpc::ListpaysRequest {
		payment_hash: Some(hash.to_vec()), ..Default::default()
	}).await.unwrap().into_inner().pays
}

/// The status the server reports for the payment of `hash` by `sources`.
async fn payment_status(srv: &Captaind, hash: PaymentHash, sources: &[VtxoId]) -> Result<PaymentStatus, tonic::Status> {
	let mut sources = sources.to_vec();
	sources.sort_unstable();
	Ok(srv.get_public_rpc().await.check_lightning_payment(protos::CheckLightningPaymentRequest {
		hash: hash.to_vec(),
		wait: false,
		htlc_vtxo_ids: sources.iter().map(|id| id.to_bytes().to_vec()).collect(),
	}).await?.into_inner().payment_status.unwrap())
}

/// A hold invoice of `node` for `hash`.
async fn hold_invoice(node: &Lightningd, hash: PaymentHash, amount: Amount, cltv: u64) -> String {
	node.hold_client().await.invoice(hold::InvoiceRequest {
		payment_hash: hash.to_vec(),
		amount_msat: amount.to_msat(),
		description: Some(hold::invoice_request::Description::Memo("expiry payout".into())),
		min_final_cltv_expiry: Some(cltv),
		expiry: Some(3600),
		routing_hints: vec![],
	}).await.unwrap().into_inner().bolt11
}

async fn cancel_hold_invoice(node: &Lightningd, hash: PaymentHash) {
	node.hold_client().await.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
}

/// Two HTLC-send VTXOs share a hash, and only the first pays in the
/// successful attempt. The second cannot be revoked once the hash is
/// settled, and after its HTLC deadline it is paid to its owner. A failed
/// attempt next to a stored preimage holds its source.
#[tokio::test]
async fn expiry_payout_pays_an_unused_htlc_of_a_paid_hash() {
	let ctx = TestContext::new("server/expiry_payout_pays_an_unused_htlc_of_a_paid_hash").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool().funded(btc(10))
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand_cfg(|cfg| cfg.watchman.sweep_interval = Duration::from_secs(1)).create().await;
	let wallet = ctx.bark_sdk("owner", &srv).boarded(sat(100_000)).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let preimage = Preimage::from([23; 32]);
	let hash = preimage.compute_payment_hash();
	let invoice = lightning.external.invoice_with_preimage(Some(sat(90_000)), "paid", "paid", [23; 32]).await;
	let mut sources = Vec::new();
	for vtxo in super::full_vtxos(&wallet).await {
		sources.push(super::htlc_send(&ctx, &srv, &wallet, vtxo, hash).await);
	}
	let (paid, paid_key) = &sources[0];
	let (unused, unused_key) = &sources[1];
	lightning.sync().await;
	srv.get_public_rpc().await.initiate_lightning_payment(
		send_request(&srv, &invoice, sat(90_000), &[paid.id()], paid_key).await,
	).await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_attempt(&db, hash, LightningPaymentStatus::Succeeded).await;
	assert_eq!(db.read(async |t| t.get_htlc_settlement_by_payment_hash(hash).await).await.unwrap(), Some(preimage));
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	assert_eq!(proposal(&db, paid, tip).await.disposition, OwnershipDisposition::Operator);
	assert!(matches!(proposal(&db, unused, tip).await.disposition, OwnershipDisposition::Unresolved(_)),
		"another source's payment does not settle an unexpired HTLC");

	// A failed payment next to a stored preimage that nothing else explains
	// may have gone through: its source is held.
	let (hash_text, source) = (hash.to_string(), paid.id().to_string());
	db.write(async |t| Ok(t.batch_execute(&format!("
		UPDATE lightning_payment_attempt SET status = 'failed', updated_at = NOW() WHERE payment_hash = '{hash_text}';
		UPDATE htlc_vtxo SET offchain_resolution = NULL WHERE id = (SELECT id FROM vtxo WHERE vtxo_id = '{source}');
	")).await?)).await.unwrap();
	assert_eq!(proposal(&db, paid, tip).await.disposition,
		OwnershipDisposition::Unresolved("failed lightning payment has a stored preimage"));
	db.write(async |t| Ok(t.batch_execute(&format!("
		UPDATE lightning_payment_attempt SET status = 'succeeded', updated_at = NOW() WHERE payment_hash = '{hash_text}';
		UPDATE htlc_vtxo SET offchain_resolution = 'fulfilled' WHERE id = (SELECT id FROM vtxo WHERE vtxo_id = '{source}');
	")).await?)).await.unwrap();

	let error = revoke(&srv, &wallet, std::slice::from_ref(unused), unused_key).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(error.message().ends_with("invoice has already been paid"), "{error}");

	let deadline = unused.policy().as_server_htlc_send().unwrap().htlc_expiry;
	let tip = mine_past(&ctx, &srv, deadline).await;
	assert_eq!(proposal(&db, unused, tip).await.disposition, birth_owner(&db, unused.id()).await);
	let (_, payout) = wait_payout(&db, unused.id()).await;
	assert_paid(&ctx, &srv, &payout, &wallet.payout_script(), sat(98_000)).await;
	let share = current_share(&db, unused.id()).await.unwrap();
	assert_eq!(share.owner, Some(wallet.mailbox_identifier().as_pubkey().to_string()));
	assert_eq!(payout_shares(&db, unused.id()).await.len(), 1);
}

/// A send fails while the server is down. After the restart the server
/// records the failure without sending the payment again, and after the
/// HTLC deadline the absent sender is refunded once.
#[tokio::test]
async fn expiry_payout_refunds_a_send_failed_during_restart() {
	let ctx = TestContext::new("server/expiry_payout_refunds_a_send_failed_during_restart").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.no_vtxo_pool().funded(btc(10)).watchmand().cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxo_exit_delta = BlockDelta::new(3);
			cfg.htlc_send_expiry_delta = BlockDelta::new(40);
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).create().await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = super::full_vtxos(&wallet).await.pop().unwrap();
	let script = wallet.payout_script();
	let hash = Preimage::random().compute_payment_hash();
	let (source, key) = super::htlc_send(&ctx, &srv, &wallet, input.clone(), hash).await;
	drop(wallet);
	let deadline = source.policy().as_server_htlc_send().unwrap().htlc_expiry;
	assert!(deadline > input.expiry_height() + BlockDelta::new(4));
	let invoice = hold_invoice(&lightning.external, hash, sat(100_000), 18).await;
	lightning.sync().await;
	srv.get_public_rpc().await.initiate_lightning_payment(
		send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await,
	).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;

	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	cancel_hold_invoice(&lightning.external, hash).await;
	async {
		loop {
			let pays = pays(&lightning.internal, hash).await;
			if !pays.is_empty() && pays.iter().all(|pay| pay.status() == ListpaysPaysStatus::Failed) {
				break;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	let payments = pays(&lightning.internal, hash).await.len();
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_attempt(&db, hash, LightningPaymentStatus::Failed).await;

	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let tip = mine_past(&ctx, &srv, input.expiry_height()).await;
	assert!(tip < deadline);
	wait_synced(&ctx, &srv, &db).await;
	assert!(matches!(proposal(&db, &source, tip).await.disposition, OwnershipDisposition::Unresolved(_)));
	assert!(payout_shares(&db, source.id()).await.is_empty(), "nothing is decided before the HTLC deadline");

	mine_past(&ctx, &srv, deadline).await;
	let (_, payout) = wait_payout(&db, source.id()).await;
	assert_eq!(payout.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), [input.chain_anchor()]);
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	let shares = payout_shares(&db, source.id()).await;
	assert_eq!(shares.len(), 1);
	assert!(shares[0].owner.is_some(), "the sats of a failed send go to their owner");
	let htlc = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
	assert_eq!(htlc.htlc.resolution(), None, "an expiry payout does not revoke the HTLC");
	assert_eq!(attempt_count(&db, hash).await, 1);
	assert_eq!(pays(&lightning.internal, hash).await.len(), payments, "the restart does not pay again");
}

/// A settlement for the hash of a failed send commits after the decision
/// read the send's source and before it writes. The decision sees it and
/// holds the source instead of refunding its sender.
#[tokio::test]
async fn expiry_payout_settlement_during_decision_holds_source() {
	let ctx = TestContext::new("server/expiry_payout_settlement_during_decision_holds_source").await;
	// The nodes have no channel, so the send fails at once.
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool().funded(btc(10)).watchmand()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(400); }).create().await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = super::full_vtxos(&wallet).await.pop().unwrap();
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let (source, key) = super::htlc_send(&ctx, &srv, &wallet, input, hash).await;
	drop(wallet);
	let invoice = hold_invoice(&lightning.external, hash, sat(90_000), 18).await;
	lightning.sync().await;
	srv.get_public_rpc().await.initiate_lightning_payment(
		send_request(&srv, &invoice, sat(90_000), &[source.id()], &key).await,
	).await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_attempt(&db, hash, LightningPaymentStatus::Failed).await;
	assert!(!is_preimage_recorded(&db, hash).await);
	fund_watchman(&ctx, &srv, sat(100_000)).await;

	let mut holds = srv.watchmand().subscribe_log::<ExpiryHoldObserved>();
	db.write(async |t| {
		// The decision reads the failed send as a refund to its sender, then
		// waits here to lock the rows of its tree. Only the decision's FOR
		// UPDATE conflicts with KEY SHARE, and the settlement runs in this
		// transaction, so nothing else blocks it.
		t.query("SELECT vtxo_id FROM vtxo WHERE anchor_point = $1 ORDER BY vtxo_id FOR KEY SHARE",
			&[&source.chain_anchor().to_string()]).await?;
		let tip = ctx.bitcoind().get_block_count().await as u32;
		ctx.generate_blocks(source.expiry_height().to_u32() + 1 - tip).await;
		wait_for_query_lock(t, "SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE").await?;
		t.store_htlc_settlement(preimage).await?;
		Ok(())
	}).await.unwrap();
	mine(&ctx, &srv, 1).await;
	async {
		while let Some(hold) = holds.recv().await {
			if hold.vtxo_id == source.id() && hold.reason == "failed lightning payment has a stored preimage" {
				break;
			}
		}
	}.wait_millis(30_000).await;
	assert!(payout_shares(&db, source.id()).await.is_empty(), "a settled hash never refunds its sender");
}

/// A send that is still pending does not stop the payout of another root.
/// Once the receiver cancels it, its absent sender is refunded once.
#[tokio::test]
async fn expiry_payout_leaves_a_pending_send_alone() {
	let ctx = TestContext::new("server/expiry_payout_leaves_a_pending_send_alone").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).no_vtxo_pool().funded(btc(10)).watchmand()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(400); }).create().await;
	let start = ctx.bitcoind().get_block_count().await;
	let (earlier, earlier_script, _) = super::idle_board(&ctx, &srv, "earlier", sat(100_000)).await;
	// Age the first board so it expires before the HTLC deadline of the send.
	let aged = earlier.expiry_height().to_u32() - 64;
	while (ctx.bitcoind().get_block_count().await as u32) < aged {
		ctx.generate_blocks((aged - ctx.bitcoind().get_block_count().await as u32).min(50)).await;
	}
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = super::full_vtxos(&wallet).await.pop().unwrap();
	let script = wallet.payout_script();
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let (source, key) = super::htlc_send(&ctx, &srv, &wallet, input, hash).await;
	drop(wallet);
	let deadline = source.policy().as_server_htlc_send().unwrap().htlc_expiry;
	assert!(earlier.expiry_height() < deadline && deadline < source.expiry_height());
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	let invoice = hold_invoice(&lightning.external, hash, sat(90_000), 220).await;
	lightning.sync().await;
	srv.get_public_rpc().await.initiate_lightning_payment(
		send_request(&srv, &invoice, sat(90_000), &[source.id()], &key).await,
	).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let assert_pending = async || {
		assert!(matches!(payment_status(&srv, hash, &[source.id()]).await.unwrap(), PaymentStatus::Pending(_)));
		assert!(payout_shares(&db, source.id()).await.is_empty());
		assert!(!is_preimage_recorded(&db, hash).await);
	};
	assert_pending().await;

	mine_past(&ctx, &srv, earlier.expiry_height()).await;
	let earlier_payout = super::mine_until_payout(&ctx, &srv, &db, earlier.id()).await;
	assert_paid(&ctx, &srv, &earlier_payout, &earlier_script, sat(98_000)).await;
	assert_pending().await;

	cancel_hold_invoice(&lightning.external, hash).await;
	wait_attempt(&db, hash, LightningPaymentStatus::Failed).await;
	assert!(payout_shares(&db, source.id()).await.is_empty(), "nothing is decided before the HTLC deadline");
	let target = source.expiry_height().max(deadline).to_u32();
	while (ctx.bitcoind().get_block_count().await as u32) < target {
		ctx.generate_blocks((target - ctx.bitcoind().get_block_count().await as u32).min(50)).await;
	}
	let payout = super::mine_until_payout(&ctx, &srv, &db, source.id()).await;
	assert!(earlier_payout.input.iter().all(|a| payout.input.iter().all(|b| a.previous_output != b.previous_output)));
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	for (script, payout) in [(&earlier_script, &earlier_payout), (&script, &payout)] {
		assert_eq!(outputs_to(&ctx, script, start), [(payout_output(payout, script, sat(98_000)), sat(98_000))],
			"each owner is paid once");
	}
	assert_eq!(attempt_count(&db, hash).await, 1);
	let htlc = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, source.id()).await).await.unwrap().unwrap();
	assert_eq!(htlc.htlc.resolution(), None, "an expiry payout does not revoke the HTLC");
}

/// An HTLC-send VTXO of a new wallet for `hash`, and its key.
async fn htlc_send_source(ctx: &TestContext, srv: &Captaind, name: &str, hash: PaymentHash) -> (Vtxo<Full>, Keypair, bark::Wallet) {
	let wallet = ctx.bark_sdk(name, srv).boarded(sat(100_000)).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = super::full_vtxos(&wallet).await.pop().unwrap();
	let (source, key) = super::htlc_send(ctx, srv, &wallet, input, hash).await;
	(source, key, wallet)
}

/// A source decided for an expiry payout after its co-sign is refused when
/// its payment starts, and no attempt is stored.
#[tokio::test]
async fn expiry_payout_decided_source_is_refused_at_initiation() {
	let ctx = TestContext::new("server/expiry_payout_decided_source_is_refused_at_initiation").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	let invoice = lightning.external.invoice_with_preimage(Some(sat(100_000)), "decided", "decided", [31; 32]).await;
	let hash = Preimage::from([31; 32]).compute_payment_hash();
	let (source, key, _wallet) = htlc_send_source(&ctx, &srv, "sender", hash).await;
	let request = send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let refusal = decide_during(&db, &[source.id()], async move {
		rpc.initiate_lightning_payment(request).await
	}).await.unwrap_err();
	assert_eq!(refusal.metadata().get("expiry-payout-reason").unwrap(), "decided_for_payout");
	assert_eq!(attempt_count(&db, hash).await, 0);
}

/// The watchman stores a block while a send checks that its sources are not
/// in an expired tree. The check compares with the tips it reads after its
/// locks, so the block does not stop the send, and the payment starts.
#[tokio::test]
async fn expiry_payout_send_starts_while_the_watchman_tip_moves() {
	let ctx = TestContext::new("server/expiry_payout_send_starts_while_the_watchman_tip_moves").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	lightning.sync().await;
	let invoice = lightning.external.invoice_with_preimage(Some(sat(100_000)), "moving", "moving", [32; 32]).await;
	let hash = Preimage::from([32; 32]).compute_payment_hash();
	let (source, key, _wallet) = htlc_send_source(&ctx, &srv, "sender", hash).await;
	let request = send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await;
	// This server runs no watchman, so the test writes the watchman blocks.
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	db.write(async |t| t.store_block(BlockTable::Watchmand, &tip).await).await.unwrap();

	let mut rpc = srv.get_public_rpc().await;
	let call = db.write(async move |t| {
		t.query("SELECT height FROM watchmand_block ORDER BY height ASC LIMIT 1 FOR UPDATE", &[]).await?;
		let call = tokio::spawn(async move { rpc.initiate_lightning_payment(request).await });
		wait_for_query_lock(t, "SELECT height FROM watchmand_block ORDER BY height ASC LIMIT 1 FOR SHARE").await?;
		let next = BlockRef { height: tip.height + BlockDelta::new(1), hash: BlockHash::from_byte_array([1; 32]) };
		t.store_block(BlockTable::Watchmand, &next).await?;
		Ok(call)
	}).await.unwrap();
	call.await.unwrap().expect("the send is accepted");
	assert_eq!(attempt_count(&db, hash).await, 1, "the payment started");
	wait_attempt(&db, hash, LightningPaymentStatus::Succeeded).await;
}

/// An HTLC that has not expired holds the payout of its whole tree, so a
/// payout server refuses an HTLC send whose expiry is more than a few
/// blocks past the one it asks for. It accepts a send at the expiry that
/// the wallet asks for and one at the end of the slack. A server without
/// expiry payouts accepts the far expiry.
#[tokio::test]
async fn expiry_payout_far_htlc_send_expiry_is_refused() {
	let ctx = TestContext::new("server/expiry_payout_far_htlc_send_expiry_is_refused").await;
	for payouts in [true, false] {
		let name = if payouts { "payout" } else { "upstream" };
		let srv = ctx.captaind(name).no_vtxo_pool().cfg(move |cfg| cfg.expiry_payouts = payouts).create().await;
		let wallet = ctx.bark_sdk(&format!("{name}_sender"), &srv).boarded(sat(100_000)).boarded(sat(100_000))
			.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
		let inputs = full_vtxos(&wallet).await;
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let expiry = tip + srv.config().htlc_send_expiry_delta;
		let mut rpc = srv.get_public_rpc().await;
		let mut send = async |input: &Vtxo<Full>, deadline: BlockHeight| {
			let key = wallet.get_vtxo_key(input).await.unwrap();
			let policy = VtxoPolicy::new_server_htlc_send(key.public_key(), Preimage::random().compute_payment_hash(), deadline);
			let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input.clone()], policy).unwrap()
				.generate_user_nonces(&[key]).unwrap();
			let package = bind_to_wallets(&srv, &[&wallet], builder.cosign_request().into()).await;
			rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest { parts: package.parts }).await
		};
		let far = send(&inputs[0], expiry + BlockDelta::new(7)).await;
		if payouts {
			let error = far.unwrap_err();
			assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
			assert!(error.message().contains("too high"), "{error}");
			send(&inputs[0], expiry).await.expect("the expiry that the wallet asks for is accepted");
			send(&inputs[1], expiry + BlockDelta::new(6)).await.expect("the end of the slack is accepted");
		} else {
			far.expect("a server without expiry payouts accepts a later expiry");
		}
	}
}

/// A send needs a signature of the owner of its sources over the request.
/// The same signed request sent again, while its payment is open, after it
/// succeeded, or after it failed, is acknowledged without a new attempt. A
/// new signature retries a failed payment.
#[tokio::test]
async fn expiry_payout_send_is_signed_and_idempotent() {
	let ctx = TestContext::new("server/expiry_payout_send_is_signed_and_idempotent").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	lightning.sync().await;

	// A payment that fails: nobody can route to the invoice.
	let failing = Preimage::random().compute_payment_hash();
	let (source, key, wallet) = htlc_send_source(&ctx, &srv, "failing", failing).await;
	let unknown = bitcoin::secp256k1::SecretKey::new(&mut bip39::rand::thread_rng());
	let invoice = InvoiceBuilder::new(Currency::Regtest)
		.description("unroutable".into())
		.payment_hash(sha256::Hash::from_byte_array(failing.to_byte_array()))
		.payment_secret(PaymentSecret([17; 32]))
		.current_timestamp().min_final_cltv_expiry_delta(18)
		.amount_milli_satoshis(100_000_000)
		.build_signed(|message| SECP.sign_ecdsa_recoverable(message, &unknown)).unwrap();
	let signed = send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await;
	let foreign = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let foreign = sign_lightning_send_request(&srv, signed.clone(), &foreign).await;
	assert_eq!(rpc.initiate_lightning_payment(foreign).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	let mut unsigned = signed.clone();
	unsigned.intent_nonce = None;
	unsigned.source_owner_signature.clear();
	assert_eq!(rpc.initiate_lightning_payment(unsigned).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	rpc.initiate_lightning_payment(signed.clone()).await.unwrap();
	wait_attempt(&db, failing, LightningPaymentStatus::Failed).await;
	let mut amount = signed.clone();
	amount.payment_amount_sat += 1;
	let mut retry = signed.clone();
	retry.retry_for_secs = Some(6);
	let mut nonce = signed.clone();
	nonce.intent_nonce.as_mut().unwrap()[0] ^= 1;
	for request in [amount, retry, nonce] {
		assert_eq!(rpc.initiate_lightning_payment(request).await.unwrap_err().code(), tonic::Code::InvalidArgument);
	}
	rpc.initiate_lightning_payment(signed).await.expect("a repeat after failure is acknowledged");
	assert_eq!(attempt_count(&db, failing).await, 1);
	let fresh = send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await;
	rpc.initiate_lightning_payment(fresh).await.unwrap();
	assert_eq!(attempt_count(&db, failing).await, 2, "the owner can retry a failed send");
	wait_attempt(&db, failing, LightningPaymentStatus::Failed).await;
	revoke(&srv, &wallet, &[source], &key).await.expect("a failed source can be revoked");

	// A payment that is held, then succeeds.
	let preimage = Preimage::random();
	let held = preimage.compute_payment_hash();
	let invoice = hold_invoice(&lightning.external, held, sat(100_000), 18).await;
	let (source, key, _wallet) = htlc_send_source(&ctx, &srv, "held", held).await;
	// The board mined blocks; the payer's node must see them, or it builds an
	// HTLC that expires too soon for the receiver.
	lightning.sync().await;
	let signed = send_request(&srv, &invoice, sat(100_000), &[source.id()], &key).await;
	rpc.initiate_lightning_payment(signed.clone()).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(held).await;
	rpc.initiate_lightning_payment(signed.clone()).await.expect("a repeat while open is acknowledged");
	lightning.external.hold_client().await.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() })
		.await.unwrap();
	wait_attempt(&db, held, LightningPaymentStatus::Succeeded).await;
	rpc.initiate_lightning_payment(signed).await.expect("a repeat after success is acknowledged");
	assert_eq!(attempt_count(&db, held).await, 1);
	assert_eq!(pays(&lightning.internal, held).await.len(), 1);
}

/// The server stops between cancelling a receive and failing the intra-Ark
/// attempt that paid it. That attempt can never succeed, so its source is
/// refunded after its HTLC deadline.
#[tokio::test]
async fn expiry_payout_refunds_open_attempt_on_cancelled_receive() {
	let ctx = TestContext::new("server/expiry_payout_refunds_open_attempt_on_cancelled_receive").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10))
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.receive_htlc_forward_timeout = Duration::from_secs(2); })
		.create().await;
	let payer = ctx.bark_sdk("payer", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let receiver = ctx.bark_sdk("receiver", &srv).cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	payer.stop_daemon_wait().await.unwrap();
	receiver.stop_daemon_wait().await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	// The server stops before it fails the attempt.
	db.write(async |t| Ok(t.batch_execute("
		CREATE FUNCTION test_refuse_failure() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'the server stops here'; END; $$ LANGUAGE plpgsql;
		CREATE TRIGGER test_refuse_failure BEFORE UPDATE ON lightning_payment_attempt
			FOR EACH ROW WHEN (NEW.status = 'failed') EXECUTE FUNCTION test_refuse_failure();
	").await?)).await.unwrap();
	let invoice = receiver.bolt11_invoice(sat(10_000), None, None).await.unwrap();
	let hash = PaymentHash::from(&invoice);
	payer.pay_lightning_invoice(invoice, None, false).await.unwrap();
	async {
		while db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap().status
			!= LightningHtlcSubscriptionStatus::Canceled {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await;
	let attempt = db.read(async |t| t.get_latest_payment_attempt_by_payment_hash(hash).await).await.unwrap().unwrap();
	assert!(!attempt.status.is_final(), "the attempt stays open on its cancelled receive");
	let [source] = htlc_send_vtxo_ids(&payer, hash).await.try_into().unwrap();
	let source = payer.get_full_vtxo(source).await.unwrap();
	let deadline = source.policy().as_server_htlc_send().unwrap().htlc_expiry;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let tip = ctx.generate_blocks(deadline.to_u32() + 1 - tip).await;
	assert_eq!(proposal(&db, &source, tip).await.disposition, birth_owner(&db, source.id()).await);
}

/// A source that was never sent to a Lightning node is refunded after its
/// HTLC deadline, even when a preimage for its hash is stored.
#[tokio::test]
async fn expiry_payout_refunds_unsent_source_with_preimage() {
	let ctx = TestContext::new("server/expiry_payout_refunds_unsent_source_with_preimage").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = lightning_payout_server(&ctx, &lightning).await;
	let preimage = Preimage::random();
	let (source, _, _wallet) = htlc_send_source(&ctx, &srv, "sender", preimage.compute_payment_hash()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	assert!(db.write(async |t| t.store_htlc_settlement(preimage).await).await.unwrap().is_some());
	let deadline = source.policy().as_server_htlc_send().unwrap().htlc_expiry;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let tip = ctx.generate_blocks(deadline.to_u32() + 1 - tip).await;
	assert_eq!(proposal(&db, &source, tip).await.disposition, birth_owner(&db, source.id()).await);
}

/// Read the mailbox of a sender and assert it holds `count` messages that
/// a send for `hash` finished, none with a preimage.
async fn assert_no_preimage_in_mailbox(
	srv: &Captaind, auth: &ark::mailbox::MailboxAuthorization, hash: PaymentHash, count: usize,
) {
	let mut rpc = srv.get_mailbox_public_rpc().await;
	let mut checkpoint = 0;
	let mut finished = 0;
	loop {
		let page = rpc.read_mailbox(protos::mailbox_server::MailboxRequest {
			mailbox_id: auth.mailbox().serialize(), authorization: Some(auth.serialize()), checkpoint,
		}).await.unwrap().into_inner();
		for message in page.messages {
			checkpoint = message.checkpoint;
			if let Some(protos::mailbox_server::mailbox_message::Message::LightningSendFinished(message)) = message.message {
				if message.payment_hash == hash.to_vec() {
					finished += 1;
					assert!(message.preimage.is_none(), "the preimage of another payment reached the sender");
				}
			}
		}
		if !page.have_more {
			break;
		}
	}
	assert_eq!(finished, count);
}

/// A sender whose payment failed is not debited when another wallet later
/// pays the same hash through the server.
#[tokio::test]
async fn expiry_payout_failed_sender_not_debited_by_later_send() {
	let ctx = TestContext::new("server/expiry_payout_failed_sender_not_debited_by_later_send").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let later_receiver = ctx.lightningd("later-receiver").create().await;
	lightning.internal.connect(&later_receiver).await;
	let channel = lightning.internal.fund_channel(&later_receiver, btc(1)).await;
	ctx.await_transaction(channel).await;
	ctx.generate_blocks(6).await;
	lightning.internal.wait_for_gossip(2).await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).lightningd(&lightning.internal)
		.no_vtxo_pool().funded(btc(10)).watchmand().cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.vtxo_exit_delta = BlockDelta::new(3);
			cfg.htlc_send_expiry_delta = BlockDelta::new(40);
			cfg.invoice_check_interval = Duration::from_secs(1);
		}).create().await;
	let config = |cfg: &mut bark::Config| {
		cfg.daemon_manual_sync = true;
		cfg.vtxo_refresh_expiry_threshold = BlockDelta::new(4);
		cfg.vtxo_exit_margin = BlockDelta::new(2);
	};
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let old = ctx.bark_sdk("failed-sender", &srv).mnemonic(mnemonic.clone()).cfg(config)
		.boarded(sat(100_000)).create().await;
	old.stop_daemon_wait().await.unwrap();
	let mailbox = old.mailbox_authorization(chrono::Local::now() + Duration::from_secs(600));
	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let options = || LightningSendOptions::default().wait(false).retry_for(Some(Duration::from_secs(1)));
	let invoice = hold_invoice(&lightning.external, hash, sat(100_000), 18).await;
	lightning.sync().await;
	old.pay_lightning_invoice_with(invoice, None, options()).await.unwrap();
	lightning.external.wait_for_hold_invoice_accepted(hash).await;
	let Progress::PaymentInitiated(old_htlcs) = old.lightning_send_checkpoint(hash).await.unwrap().unwrap().progress else {
		panic!("the send must be initiated");
	};
	let old_input = old.lightning_send_checkpoint(hash).await.unwrap().unwrap().input_vtxo_ids[0];
	drop(old);

	// The payment fails while the wallet and the server are away.
	srv.watchmand().stop().await.unwrap();
	srv.stop().await.unwrap();
	cancel_hold_invoice(&lightning.external, hash).await;
	async {
		while pays(&lightning.internal, hash).await.iter().any(|pay| pay.status() != ListpaysPaysStatus::Failed) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_attempt(&db, hash, LightningPaymentStatus::Failed).await;
	async {
		// The status commits before the mailbox message.
		while !db.read(async |t| Ok(t.query_one("
			SELECT EXISTS(SELECT 1 FROM mailbox
			WHERE unblinded_mailbox_id = $1 AND payment_hash = $2 AND mailbox_type = 'ln-send-finished')
		", &[&mailbox.mailbox().to_string(), &hash.to_string()]).await?.get::<_, bool>(0))).await.unwrap() {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;

	// Another wallet pays the same hash to another node, and succeeds.
	let later = ctx.bark_sdk("later-sender", &srv).cfg(config).boarded(sat(50_000)).boarded(sat(50_000)).create().await;
	later.stop_daemon_wait().await.unwrap();
	let invoice = hold_invoice(&later_receiver, hash, sat(100_000), 18).await;
	later_receiver.wait_for_block_sync().await;
	lightning.internal.wait_for_block_sync().await;
	later.pay_lightning_invoice_with(invoice, None, options()).await.unwrap();
	later_receiver.wait_for_hold_invoice_accepted(hash).await;
	let Progress::PaymentInitiated(later_htlcs) = later.lightning_send_checkpoint(hash).await.unwrap().unwrap().progress else {
		panic!("the send must be initiated");
	};
	assert!(matches!(payment_status(&srv, hash, &old_htlcs.vtxo_ids).await.unwrap(), PaymentStatus::Failed(_)));
	assert!(matches!(payment_status(&srv, hash, &later_htlcs.vtxo_ids).await.unwrap(), PaymentStatus::Pending(_)));
	later_receiver.hold_client().await.settle(hold::SettleRequest { payment_preimage: preimage.to_vec() })
		.await.unwrap();
	assert!(matches!(later.check_lightning_payment(hash, true).await.unwrap(), LightningSendState::Paid(_)));
	assert!(matches!(payment_status(&srv, hash, &old_htlcs.vtxo_ids).await.unwrap(), PaymentStatus::Failed(_)),
		"the success of another sender is not the outcome of this send");
	assert!(matches!(payment_status(&srv, hash, &later_htlcs.vtxo_ids).await.unwrap(),
		PaymentStatus::Success(success) if success.preimage == preimage.to_vec()));
	assert_eq!(payment_status(&srv, hash, &[old_input]).await.unwrap_err().code(), tonic::Code::NotFound,
		"a VTXO that paid nothing has no payment status");
	assert_no_preimage_in_mailbox(&srv, &mailbox, hash, 1).await;
	drop(later);

	// The failed sender comes back: its payment did not succeed and its HTLC
	// VTXOs are not spent.
	let returned = ctx.bark_sdk("failed-sender", &srv).mnemonic(mnemonic).cfg(config).create().await;
	returned.sync_mailbox().await.unwrap();
	assert!(!matches!(returned.check_lightning_payment(hash, false).await, Ok(LightningSendState::Paid(_))));
	assert!(!returned.is_invoice_paid(hash).await.unwrap());
	let vtxos = returned.all_vtxos().await.unwrap();
	assert!(old_htlcs.vtxo_ids.iter().all(|id| vtxos.iter().any(|vtxo| vtxo.vtxo.id() == *id
		&& !matches!(vtxo.state, bark::vtxo::VtxoState::Spent))));
	assert_eq!(attempt_count(&db, hash).await, 2);
}

/// A failed send cannot be claimed on chain with the preimage of another
/// payment of the same hash, and its owner can still exit it after the HTLC
/// deadline.
#[tokio::test]
async fn expiry_payout_unrelated_preimage_keeps_failed_send() {
	let ctx = TestContext::new("server/expiry_payout_unrelated_preimage_keeps_failed_send").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let payer = Arc::new(lightning.external);
	let srv = ctx.captaind("server").lightningd(&lightning.internal).watchmand()
		.watchmand_cfg(|cfg| {
			cfg.watchman.reaction_interval = Duration::from_millis(100);
			cfg.watchman.sweep_interval = Duration::from_millis(100);
		})
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	ctx.fund_captaind(&srv, btc(10)).await;
	srv.wait_for_vtxopool(&ctx).await;
	let victim = ctx.bark("victim", &srv).funded(btc(3)).create().await;
	victim.board_and_confirm_and_register(&ctx, btc(2)).await;
	lightning.internal.wait_for_block_sync().await;
	payer.wait_for_block_sync().await;

	let preimage = Preimage::random();
	let hash = preimage.compute_payment_hash();
	let mut hold = payer.hold_client().await;
	let invoice = hold_invoice(&payer, hash, btc(1), 18).await;
	victim.try_pay_lightning(&invoice, None, false).await.unwrap();
	wait_for_hold_invoice_accepted(&mut hold, hash).await;
	let client = victim.client().await;
	let [source] = htlc_send_vtxo_ids(&client, hash).await.try_into().unwrap();
	let source = client.get_full_vtxo(source).await.unwrap();

	// Another receive of the same hash is paid with the preimage.
	let key = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(key.public_key());
	let mut rpc = srv.get_public_rpc().await;
	let second = rpc.start_lightning_receive(protos::StartLightningReceiveRequest {
		payment_hash: hash.to_vec(), amount_sat: 100_000, min_cltv_delta: 6,
		mailbox_id: Some(mailbox.serialize()), description: None, expiry_secs: None,
		claim_pubkey: Some(key.public_key().serialize().to_vec()), ark_address_hint: false,
	}).await.unwrap().into_inner().bolt11;
	let paying = {
		let payer = payer.clone();
		tokio::spawn(async move { payer.try_pay_bolt11(second).await })
	};
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	wait_for_subscription_status(&db, hash, "accepted").await;
	let sub = db.read(async |t| t.get_htlc_subscription_by_payment_hash(hash).await).await.unwrap().unwrap();
	let expiry = sub.lowest_incoming_htlc_expiry.unwrap().saturating_sub(srv.config().htlc_expiry_delta);
	let grants = rpc.prepare_lightning_receive_claim(protos::PrepareLightningReceiveClaimRequest {
		payment_hash: hash.to_vec(),
		user_pubkey: key.public_key().serialize().to_vec(),
		htlc_recv_expiry: expiry.into(),
		lightning_receive_anti_dos: None,
		claim_attestation: Some(LightningReceiveClaimAttestation::new(hash, expiry, &key).serialize()),
	}).await.unwrap().into_inner().htlc_vtxos.into_iter()
		.map(|raw| Vtxo::<Full>::deserialize(&raw).unwrap()).collect::<Vec<_>>();
	let keys = vec![key; grants.len()];
	let builder = ark::arkoor::package::ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		grants, VtxoPolicy::new_pubkey(key.public_key()),
	).unwrap().generate_user_nonces(&keys).unwrap();
	let mut package = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut package, &key, mailbox).await;
	rpc.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
		payment_hash: hash.to_vec(), payment_preimage: preimage.to_vec(), cosign_request: Some(package),
	}).await.unwrap();
	assert!(paying.wait_millis(10_000).await.unwrap().is_ok());
	assert!(is_preimage_recorded(&db, hash).await);

	// The original payment fails.
	hold.cancel(hold::CancelRequest { payment_hash: hash.to_vec() }).await.unwrap();
	async {
		while !pays(&lightning.internal, hash).await.iter().any(|pay| pay.status() == ListpaysPaysStatus::Failed) {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(10_000).await;

	// Put the source on chain. The watchman must not claim it.
	let mut seen = HashSet::new();
	for item in source.transactions() {
		if seen.insert(item.tx.compute_txid()) {
			ctx.broadcast_cpfp(&item.tx).await;
			ctx.generate_blocks(1).await;
		}
	}
	srv.watchmand().wait_for_sync_height(BlockHeight::new(ctx.bitcoind().get_block_count().await as u32)).await;
	let tip = ctx.generate_blocks(source.exit_delta().to_u32() + 1).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	srv.watchmand().trigger_sweep().await;
	// Give the sweep time to run: it must not claim the source.
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert!(server::bitcoind::get_mempool_spending_tx(&ctx.bitcoind().async_client(), source.point())
		.await.unwrap().is_none(), "the watchman claimed a failed source with another payment's preimage");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&source.point().txid, source.point().vout, Some(true))
		.unwrap().is_some());

	// The owner takes the timeout branch of the same HTLC.
	let deadline = source.policy().as_server_htlc_send().unwrap().htlc_expiry;
	let now = ctx.bitcoind().get_block_count().await as u32;
	if now <= deadline.to_u32() {
		ctx.generate_blocks(deadline.to_u32() + 1 - now).await;
	}
	victim.sync().await;
	assert_eq!(client.stuck_failed_lightning_sends().await.unwrap().len(), 1);
	client.allow_lightning_send_to_exit(hash).await.unwrap();
	victim.sync().await;
	assert!(!victim.list_exits().await.is_empty());
	complete_exit(&ctx, &victim).await;
	let before = victim.onchain_balance().await;
	victim.claim_all_exits(victim.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	victim.progress_exit().await;
	assert!(victim.onchain_balance().await >= before + sat(90_000_000));
}
