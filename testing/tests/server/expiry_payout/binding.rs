use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, OutPoint, Transaction, TxOut};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey};
use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;

use futures::StreamExt;

use ark::{
	musig, ProtocolEncoding, SECP, ServerVtxo, SignedVtxoRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest,
};
use ark::arkoor::ArkoorDestination;
use ark::arkoor::package::{ArkoorPackageBuilder, ArkoorPackageCosignResponse};
use ark::attestations::{DelegatedRoundParticipationAttestation, VtxoStatusAttestation};
use ark::lightning::{PaymentHash, Preimage};
use ark::mailbox::{MailboxIdentifier, MailboxType};
use ark::rounds::{RoundAttemptAttestation, RoundEvent};
use ark::test_util::dummy::DummyTestVtxoSpec;
use ark::tree::signed::{UnlockHash, UnlockPreimage};
use ark::vtxo::Full;
use bark::Wallet;
use server::database::{Db, SpendState};
use server::database::rounds::StoredRoundOutput;
use server::database::tree::VtxoTreeUpdate;
use server_log::RoundFinished;
use server_rpc::protos;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::exit::complete_exit;
use ark_testing::util::{poll_interval, FutureExt};

use crate::registration::DropRegistration;
use super::{
	assert_paid, bind_outputs, bind_to_wallets, blinded_mailbox, current_share, decide_for_payout,
	full_vtxos, fund_watchman, mine, mine_past, mine_until_payout, Owner,
};

/// A new Lightning spend of an expired VTXO and any spend of a VTXO decided
/// for a payout are refused with a reason the client can read.
#[tokio::test]
async fn expiry_payout_refusals_carry_a_reason() {
	let ctx = TestContext::new("server/expiry_payout_refusals_carry_a_reason").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); }).create().await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let source = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
	let source = wallet.get_full_vtxo(source.id()).await.unwrap();
	let key = wallet.get_vtxo_key(&source).await.unwrap();
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(source.expiry_height().to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	let request = async || {
		let deadline = expired + srv.config().htlc_send_expiry_delta + BlockDelta::new(1);
		let policy = VtxoPolicy::new_server_htlc_send(key.public_key(), PaymentHash::from([7; 32]), deadline);
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([source.clone()], policy).unwrap()
			.generate_user_nonces(&[key]).unwrap();
		let package = bind_to_wallets(&srv, &[&wallet], builder.cosign_request().into()).await;
		protos::LightningPayHtlcCosignRequest { parts: package.parts }
	};
	let reason = |error: tonic::Status| {
		error.metadata().get("expiry-payout-reason").unwrap().to_str().unwrap().to_owned()
	};
	let mut rpc = srv.get_public_rpc().await;
	let error = rpc.request_lightning_pay_htlc_cosign(request().await).await.unwrap_err();
	assert_eq!(reason(error), "expired_new_lightning");

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	db.write(async |t| {
		decide_for_payout(t, &[source.id().to_string()]).await?;
		t.execute("UPDATE vtxo SET spend_state = 'spent', updated_at = NOW() WHERE vtxo_id = $1",
			&[&source.id().to_string()]).await?;
		Ok(())
	}).await.unwrap();
	let error = rpc.request_lightning_pay_htlc_cosign(request().await).await.unwrap_err();
	assert_eq!(reason(error), "decided_for_payout");
}

/// The `vtxo` rows of `ids` and every owner binding, to check that a
/// request wrote nothing.
async fn stored_rows(db: &Db, ids: &[VtxoId]) -> (Vec<String>, Vec<(String, String)>) {
	let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
	db.read(async |t| {
		let vtxos = t.query("
			SELECT (to_jsonb(v) - 'updated_at')::TEXT FROM vtxo v WHERE vtxo_id = ANY($1) ORDER BY vtxo_id
		", &[&ids]).await?.into_iter().map(|row| row.get(0)).collect();
		let owners = t.query("
			SELECT vtxo_id, mailbox_pk FROM vtxo_owner_mailbox ORDER BY vtxo_id
		", &[]).await?.into_iter().map(|row| (row.get(0), row.get(1))).collect();
		Ok((vtxos, owners))
	}).await.unwrap()
}

/// The server binds an arkoor output to the mailbox in the request when it
/// co-signs. A refused request writes nothing, a recovery hint in another
/// mailbox is stored and leaves the binding unchanged, and a request with
/// another mailbox is refused.
#[tokio::test]
async fn expiry_payout_arkoor_mailbox_binding_is_immutable() {
	let ctx = TestContext::new("server/expiry_payout_arkoor_mailbox_binding_is_immutable").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let wallet = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = wallet.spendable_vtxos().await.unwrap().pop().unwrap();
	let input = wallet.get_full_vtxo(input.id()).await.unwrap();
	let input_key = wallet.get_vtxo_key(&input).await.unwrap();
	let recipient = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key());
	let other = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let other_mailbox = MailboxIdentifier::from_pubkey(other.public_key());
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		[input.clone()], VtxoPolicy::new_pubkey(recipient.public_key()),
	).unwrap().generate_user_nonces(&[input_key]).unwrap();
	let output_id = builder.build_unsigned_vtxos().next().unwrap().id();
	let ids = [input.id(), output_id];
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut request, &recipient, mailbox).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let original = stored_rows(&db, &ids).await;
	let mut rpc = srv.get_public_rpc().await;

	let mut missing = request.clone();
	missing.parts[0].outputs[0].blinded_mailbox_id.clear();
	let error = rpc.request_arkoor_cosign(missing).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(stored_rows(&db, &ids).await, original);

	let mut wrong_key = request.clone();
	wrong_key.parts[0].outputs[0].policy = VtxoPolicy::new_pubkey(other.public_key()).serialize();
	let error = rpc.request_arkoor_cosign(wrong_key).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert_eq!(stored_rows(&db, &ids).await, original);

	rpc.request_arkoor_cosign(request.clone()).await.unwrap();
	let bound = db.read(async |t| t.vtxo_owner_mailboxes(&[output_id]).await).await.unwrap();
	assert_eq!(bound.get(&output_id), Some(&mailbox.as_pubkey()));
	let committed = stored_rows(&db, &ids).await;
	db.write(async |t| t.store_vtxo_ids_in_mailbox(
		MailboxType::RecoveryVtxoId, other_mailbox, &[output_id],
	).await).await.unwrap().expect("a recovery hint is stored");
	assert_eq!(stored_rows(&db, &ids).await, committed, "a recovery hint cannot change the mailbox of a VTXO");

	let mut changed = request.clone();
	bind_outputs(&srv, &mut changed, &recipient, other_mailbox).await;
	assert!(rpc.request_arkoor_cosign(changed).await.is_err());
	assert_eq!(stored_rows(&db, &ids).await, committed);

	// A client that lost the reply sends the same request again.
	rpc.request_arkoor_cosign(request).await.unwrap();
	assert_eq!(stored_rows(&db, &ids).await, committed);
}

/// The inputs of an arkoor request must have one owner mailbox. A request
/// that mixes two is refused before the server co-signs and writes nothing.
#[tokio::test]
async fn expiry_payout_mixed_input_mailboxes_are_refused() {
	let ctx = TestContext::new("server/expiry_payout_mixed_input_mailboxes_are_refused").await;
	let srv = ctx.captaind("server").no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let owner = ctx.bark_sdk("owner", &srv).boarded(sat(100_000)).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let other = ctx.bark_sdk("other", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let owned = owner.spendable_vtxos().await.unwrap();
	let foreign = other.spendable_vtxos().await.unwrap();
	let mut inputs = Vec::new();
	for (wallet, vtxo) in [(&owner, &owned[0]), (&owner, &owned[1]), (&other, &foreign[0])] {
		let vtxo = wallet.get_full_vtxo(vtxo.id()).await.unwrap();
		let key = wallet.get_vtxo_key(&vtxo).await.unwrap();
		inputs.push((vtxo, key));
	}
	let recipient = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key());
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut rpc = srv.get_public_rpc().await;
	let request = async |pair: [&(Vtxo<Full>, Keypair); 2]| {
		let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
			pair.map(|(vtxo, _)| vtxo.clone()), VtxoPolicy::new_pubkey(recipient.public_key()),
		).unwrap().generate_user_nonces(&pair.map(|(_, key)| *key)).unwrap();
		let ids = builder.build_unsigned_vtxos().map(|v| v.id()).collect::<Vec<_>>();
		let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
		bind_outputs(&srv, &mut request, &recipient, mailbox).await;
		(request, ids)
	};

	let (mixed, ids) = request([&inputs[0], &inputs[2]]).await;
	let error = rpc.request_arkoor_cosign(mixed).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert!(db.read(async |t| t.vtxo_owner_mailboxes(&ids).await).await.unwrap().is_empty());
	assert!(db.read(async |t| t.get_existing_server_vtxos_by_id(&ids).await).await.unwrap().is_empty());
	for (vtxo, _) in [&inputs[0], &inputs[2]] {
		assert_eq!(db.read(async |t| t.get_user_vtxo_by_id(vtxo.id()).await).await.unwrap().spend_state,
			SpendState::Spendable);
	}

	let (same, ids) = request([&inputs[0], &inputs[1]]).await;
	rpc.request_arkoor_cosign(same).await.unwrap();
	let bound = db.read(async |t| t.vtxo_owner_mailboxes(&ids).await).await.unwrap();
	assert_eq!(bound.len(), ids.len());
	assert!(bound.values().all(|bound| *bound == mailbox.as_pubkey()));
}

/// An arkoor of `input` to one output for each of `policies`, which get
/// the key of `input` and share its amount, bound to the wallet.
async fn split_arkoor(
	srv: &Captaind, wallet: &Wallet, input: &Vtxo<Full>, policies: &[&dyn Fn(PublicKey) -> VtxoPolicy],
) -> protos::ArkoorPackageCosignRequest {
	let key = wallet.get_vtxo_key(input).await.unwrap();
	let amount = input.amount() / policies.len() as u64;
	let outputs = policies.iter()
		.map(|policy| ArkoorDestination { total_amount: amount, policy: policy(key.public_key()) })
		.collect();
	let builder = ArkoorPackageBuilder::new_with_checkpoints([input.clone()], outputs).unwrap()
		.generate_user_nonces(&[key]).unwrap();
	bind_to_wallets(srv, &[wallet], builder.cosign_request().into()).await
}

/// A payout server co-signs only arkoor outputs with a pubkey policy, and
/// the HTLC-send outputs of a Lightning send. An HTLC output from any other
/// arkoor has no Lightning payment that resolves it, so it would hold the
/// payout of its whole tree. A server without expiry payouts co-signs these
/// outputs.
#[tokio::test]
async fn expiry_payout_arkoor_outputs_need_a_pubkey_policy() {
	let ctx = TestContext::new("server/expiry_payout_arkoor_outputs_need_a_pubkey_policy").await;
	for payouts in [true, false] {
		let name = if payouts { "payout" } else { "upstream" };
		let srv = ctx.captaind(name).no_vtxo_pool().cfg(move |cfg| cfg.expiry_payouts = payouts).create().await;
		let wallet = ctx.bark_sdk(&format!("{name}_sender"), &srv)
			.boarded(sat(100_000)).boarded(sat(100_000)).boarded(sat(100_000)).boarded(sat(100_000))
			.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
		let inputs = full_vtxos(&wallet).await;
		let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
		let deadline = tip + srv.config().htlc_send_expiry_delta;
		let delta = srv.config().htlc_expiry_delta;
		let htlc_send = |key| VtxoPolicy::new_server_htlc_send(key, Preimage::random().compute_payment_hash(), deadline);
		let htlc_recv = |key| VtxoPolicy::new_server_htlc_recv(
			key, Preimage::random().compute_payment_hash(), deadline, delta,
		);
		let lightning = |request: protos::ArkoorPackageCosignRequest| {
			protos::LightningPayHtlcCosignRequest { parts: request.parts }
		};
		let mut rpc = srv.get_public_rpc().await;

		let send = split_arkoor(&srv, &wallet, &inputs[0], &[&htlc_send]).await;
		rpc.request_lightning_pay_htlc_cosign(lightning(send)).await
			.expect("a Lightning send with HTLC-send outputs is co-signed");

		let plain_recv = split_arkoor(&srv, &wallet, &inputs[1], &[&htlc_recv]).await;
		let plain_send = split_arkoor(&srv, &wallet, &inputs[2], &[&htlc_send]).await;
		let mixed_send = split_arkoor(&srv, &wallet, &inputs[3], &[&htlc_send, &htlc_recv]).await;
		let results = [
			("an arkoor to an HTLC-recv output", rpc.request_arkoor_cosign(plain_recv).await),
			("an arkoor to an HTLC-send output", rpc.request_arkoor_cosign(plain_send).await),
			("a Lightning send with an HTLC-recv output",
				rpc.request_lightning_pay_htlc_cosign(lightning(mixed_send)).await),
		];
		for (what, result) in results {
			if payouts {
				let error = result.expect_err(what);
				assert_eq!(error.code(), tonic::Code::InvalidArgument, "{what}: {error}");
				assert!(error.message().contains("policy"), "{what}: {error}");
			} else {
				result.unwrap_or_else(|e| panic!("{what} is refused without expiry payouts: {e}"));
			}
		}
	}
}

async fn server_with_watchman(ctx: &TestContext, lifetime: BlockDelta) -> Arc<Captaind> {
	let srv = ctx.captaind("server").no_vtxo_pool().watchmand()
		.cfg(move |cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = lifetime; }).create().await;
	fund_watchman(ctx, &srv, sat(100_000)).await;
	srv
}

/// Board 100,000 sats for `owner` through the public board protocol and
/// return the co-signed board and its funding transaction, not yet
/// broadcast. With `retry`, a repeated request is answered again and one
/// with another mailbox is refused.
async fn cosign_board(ctx: &TestContext, srv: &Captaind, owner: &Owner, key: Keypair, retry: bool)
	-> (Vtxo<Full>, Transaction)
{
	let address = ctx.bitcoind().get_new_address();
	let txid = ctx.bitcoind().fund_addr(&address, sat(200_000)).await;
	let previous = ctx.bitcoind().await_transaction(txid).await;
	let vout = previous.output.iter().position(|output| output.script_pubkey == address.script_pubkey()).unwrap();
	let tip = mine(ctx, srv, 6).await;
	let info = srv.ark_info().await;
	let expiry = tip + info.vtxo_lifetime;
	let builder = ark::board::BoardBuilder::new(key.public_key(), expiry, info.server_pubkey, info.vtxo_exit_delta)
		.unwrap();
	let unsigned = Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::absolute::LockTime::ZERO,
		input: vec![bitcoin::TxIn {
			previous_output: OutPoint::new(txid, vout as u32),
			script_sig: Default::default(),
			sequence: bitcoin::Sequence::MAX,
			witness: bitcoin::Witness::new(),
		}],
		output: vec![
			TxOut { value: sat(100_000), script_pubkey: builder.funding_script_pubkey() },
			TxOut { value: sat(99_000), script_pubkey: ctx.bitcoind().get_new_address().script_pubkey() },
		],
	};
	let funding = ctx.bitcoind().sync_client().sign_raw_transaction_with_wallet(&unsigned, None, None).unwrap()
		.transaction().unwrap();
	let point = OutPoint::new(funding.compute_txid(), 0);
	let builder = builder.set_funding_details(sat(100_000), Amount::ZERO, point).unwrap().generate_user_nonces();
	let mut rpc = srv.get_public_rpc().await;
	let request = protos::BoardCosignRequest {
		owner_mailbox: Some(owner.mailbox_id().serialize()),
		amount: 100_000,
		utxo: serialize(&point),
		expiry_height: expiry.into(),
		user_pubkey: key.public_key().serialize().to_vec(),
		pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		funding_tx: serialize(&funding),
	};
	let cosign: ark::board::BoardCosignResponse = rpc.request_board_cosign(request.clone())
		.await.unwrap().into_inner().try_into().unwrap();
	if retry {
		let again: ark::board::BoardCosignResponse = rpc.request_board_cosign(request.clone())
			.await.unwrap().into_inner().try_into().unwrap();
		assert!(builder.verify_cosign_response(&again));
		let mut conflicting = request;
		conflicting.owner_mailbox = Some(MailboxIdentifier::from_pubkey(owner.key(2).public_key()).serialize());
		let error = rpc.request_board_cosign(conflicting).await.expect_err("the board mailbox cannot change");
		assert_eq!(error.code(), tonic::Code::InvalidArgument);
	}
	let vtxo = builder.build_vtxo(&cosign, &key).unwrap();
	vtxo.validate(&funding).unwrap();
	(vtxo, funding)
}

/// Broadcast and confirm the funding of a co-signed board, and register the
/// board if `register`.
async fn confirm_board(ctx: &TestContext, srv: &Captaind, vtxo: &Vtxo<Full>, funding: &Transaction, register: bool) {
	ctx.bitcoind().sync_client().send_raw_transaction(funding).unwrap();
	mine(ctx, srv, BOARD_CONFIRMATIONS).await;
	if register {
		srv.get_public_rpc().await.register_board_vtxo(protos::BoardVtxoRequest { board_vtxo: vtxo.serialize() })
			.await.unwrap();
	}
}

async fn board(ctx: &TestContext, srv: &Captaind, owner: &Owner, key: Keypair) -> Vtxo<Full> {
	let (vtxo, funding) = cosign_board(ctx, srv, owner, key, false).await;
	confirm_board(ctx, srv, &vtxo, &funding, true).await;
	vtxo
}

/// Wait for the payout of `vtxo` and check that it pays its 100,000 sats
/// minus the fee to `owner`.
async fn assert_paid_to_owner(ctx: &TestContext, srv: &Captaind, owner: &Owner, vtxo: VtxoId) {
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let payout = mine_until_payout(ctx, srv, &db, vtxo).await;
	assert_paid(ctx, srv, &payout, &owner.script, sat(98_000)).await;
	let share = current_share(&db, vtxo).await.unwrap();
	assert_eq!((share.owner, share.gross, share.fee, share.payout),
		(Some(owner.mailbox.public_key().to_string()), sat(100_000), sat(2_000), sat(98_000)));
}

/// A board the holder never registers is paid to the mailbox it gave when
/// the server co-signed, also after a server crash.
#[tokio::test]
async fn expiry_payout_unregistered_board_is_paid_to_its_mailbox() {
	let ctx = TestContext::new("server/expiry_payout_unregistered_board_is_paid_to_its_mailbox").await;
	let srv = server_with_watchman(&ctx, BlockDelta::new(24)).await;
	let owner = Owner::new(&[117; 64]);
	let (vtxo, funding) = cosign_board(&ctx, &srv, &owner, owner.key(1), true).await;
	confirm_board(&ctx, &srv, &vtxo, &funding, false).await;
	let root = VtxoId::from(vtxo.chain_anchor());
	let status = async |key: &Keypair| srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: vtxo.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(vtxo.id(), key).serialize(),
	}).await;
	let pending = status(&owner.key(1)).await.unwrap().into_inner();
	assert_eq!(pending.spend_state, protos::VtxoSpendState::Unregistered as i32);
	assert_eq!(pending.owner_mailbox, owner.mailbox.public_key().serialize());
	assert!(pending.expiry_payout.is_none());
	assert!(status(&owner.key(2)).await.is_err(), "another key cannot read the status");

	srv.watchmand().stop().await.unwrap();
	srv.crash_stop().await.unwrap();
	srv.start().await.unwrap();
	srv.watchmand().start().await.unwrap();
	let after_restart = status(&owner.key(1)).await.unwrap().into_inner();
	assert_eq!(after_restart, pending);

	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	assert_paid_to_owner(&ctx, &srv, &owner, root).await;
	let paid = status(&owner.key(1)).await.unwrap().into_inner();
	assert_eq!(paid.spend_state, protos::VtxoSpendState::Spent as i32);
	assert_eq!(paid.owner_mailbox, owner.mailbox.public_key().serialize());
	assert_eq!(paid.expiry_payout.map(|p| p.state), Some(protos::ExpiryPayoutState::Paid as i32));
}

/// A co-signed board is on the frontier from co-sign. If its funding never
/// confirms, the watchman drops it once it expired. A holder who confirms
/// and registers it later is still paid.
#[tokio::test]
async fn expiry_payout_unconfirmed_board_leaves_the_frontier() {
	let ctx = TestContext::new("server/expiry_payout_unconfirmed_board_leaves_the_frontier").await;
	let srv = server_with_watchman(&ctx, BlockDelta::new(24)).await;
	let owner = Owner::new(&[117; 64]);
	let (vtxo, funding) = cosign_board(&ctx, &srv, &owner, owner.key(1), false).await;
	let root = VtxoId::from(vtxo.chain_anchor());
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let tracked = async || db.read(async |t| t.get_frontier().await).await.unwrap().contains_key(&root);
	assert!(tracked().await);
	// The board can still confirm before its expiry.
	mine_past(&ctx, &srv, BlockHeight::new(vtxo.expiry_height().to_u32() - 2)).await;
	srv.watchmand().trigger_sweep().await;
	// The sweep must not drop it; there is no event for that, so give it time.
	tokio::time::sleep(Duration::from_millis(500)).await;
	assert!(tracked().await);
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	async {
		while tracked().await {
			srv.watchmand().trigger_sweep().await;
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	confirm_board(&ctx, &srv, &vtxo, &funding, true).await;
	assert!(tracked().await, "registration puts the board back on the frontier");
	assert_paid_to_owner(&ctx, &srv, &owner, vtxo.id()).await;
}

/// A refund of an HTLC-send VTXO that is never registered is paid to the
/// owner of the HTLC.
#[tokio::test]
async fn expiry_payout_pays_an_unregistered_htlc_refund() {
	let ctx = TestContext::new("server/expiry_payout_pays_an_unregistered_htlc_refund").await;
	// The tree must outlive the HTLC deadline.
	let srv = server_with_watchman(&ctx, BlockDelta::new(400)).await;
	let owner = Owner::new(&[117; 64]);
	let input = board(&ctx, &srv, &owner, owner.key(1)).await;
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let deadline = tip + srv.config().htlc_send_expiry_delta + BlockDelta::new(2);
	let htlc_key = owner.key(500);
	let policy = VtxoPolicy::new_server_htlc_send(htlc_key.public_key(), PaymentHash::from([19; 32]), deadline);
	let builder = ArkoorPackageBuilder::new_with_checkpoints([input.clone()], vec![
		ArkoorDestination { total_amount: sat(100_000), policy },
	]).unwrap().generate_user_nonces(&[owner.key(1)]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut request, &htlc_key, owner.mailbox_id()).await;
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_lightning_pay_htlc_cosign(protos::LightningPayHtlcCosignRequest {
		parts: request.parts,
	}).await.unwrap().into_inner();
	let htlc = builder.user_cosign(&[owner.key(1)], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos().remove(0);
	rpc.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest { vtxos: vec![htlc.serialize()] })
		.await.unwrap();

	// The refund goes to a key the server has never seen, and stays local.
	let refund_key = Owner::new(&[118; 64]).key(1);
	let revoke = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		[htlc.clone()], VtxoPolicy::new_pubkey(refund_key.public_key()),
	).unwrap().generate_user_nonces(&[htlc_key]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(revoke.cosign_request());
	bind_outputs(&srv, &mut request, &refund_key, owner.mailbox_id()).await;
	let response = rpc.request_lightning_pay_htlc_revocation(request).await.unwrap().into_inner();
	let refund = revoke.user_cosign(&[htlc_key], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos().remove(0);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let stored = db.read(async |t| t.get_bare_vtxo_by_id(refund.id()).await).await.unwrap();
	assert_eq!(stored.spend_state, SpendState::Unregistered);

	mine_past(&ctx, &srv, deadline.max(refund.expiry_height())).await;
	assert_paid_to_owner(&ctx, &srv, &owner, refund.id()).await;
}

/// An arkoor output never registered by expiry is paid to the sender's
/// mailbox. Its recipient learns only that the VTXO is spent.
#[tokio::test]
async fn expiry_payout_pays_an_unregistered_arkoor_to_its_sender() {
	let ctx = TestContext::new("server/expiry_payout_pays_an_unregistered_arkoor_to_its_sender").await;
	let srv = server_with_watchman(&ctx, BlockDelta::new(24)).await;
	let owner = Owner::new(&[117; 64]);
	let input = board(&ctx, &srv, &owner, owner.key(1)).await;
	let recipient = Owner::new(&[119; 64]);
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints(
		[input], VtxoPolicy::new_pubkey(recipient.key(1).public_key()),
	).unwrap().generate_user_nonces(&[owner.key(1)]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	bind_outputs(&srv, &mut request, &recipient.key(1), recipient.mailbox_id()).await;
	let mut rpc = srv.get_public_rpc().await;
	let response = rpc.request_arkoor_cosign(request).await.unwrap().into_inner();
	let vtxo = builder.user_cosign(&[owner.key(1)], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos().remove(0);

	// The recipient holds the signed VTXO but never registers it.
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	assert_paid_to_owner(&ctx, &srv, &owner, vtxo.id()).await;
	let status = rpc.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: vtxo.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(vtxo.id(), &recipient.key(1)).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.spend_state, protos::VtxoSpendState::Spent as i32);
	assert_eq!(status.owner_mailbox, recipient.mailbox.public_key().serialize());
	assert!(status.expiry_payout.is_none(), "the sender's refund is not the recipient's payout");
}

/// An arkoor output with the key of round padding that is never registered
/// by expiry is paid to the sender's mailbox, as any other unregistered
/// arkoor output. Only round padding goes to the operator.
#[tokio::test]
async fn expiry_payout_pays_an_unregistered_padding_key_arkoor_to_its_sender() {
	let ctx = TestContext::new("server/expiry_payout_pays_an_unregistered_padding_key_arkoor_to_its_sender").await;
	let srv = server_with_watchman(&ctx, BlockDelta::new(24)).await;
	let owner = Owner::new(&[117; 64]);
	let input = board(&ctx, &srv, &owner, owner.key(1)).await;
	let builder = ArkoorPackageBuilder::new_claim_all_with_checkpoints([input], padding_policy()).unwrap()
		.generate_user_nonces(&[owner.key(1)]).unwrap();
	let mut request = protos::ArkoorPackageCosignRequest::from(builder.cosign_request());
	// Nobody holds the padding key, so the output binds to an unknown mailbox.
	bind_outputs(&srv, &mut request, &owner.key(2), owner.mailbox_id()).await;
	let response = srv.get_public_rpc().await.request_arkoor_cosign(request).await.unwrap().into_inner();
	let vtxo = builder.user_cosign(&[owner.key(1)], ArkoorPackageCosignResponse::try_from(response).unwrap())
		.unwrap().build_signed_vtxos().remove(0);

	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	assert_paid_to_owner(&ctx, &srv, &owner, vtxo.id()).await;
}

/// Two mailbox points with the same payout script are still two owners: a
/// post for one cannot use the delivery slot of the other.
#[tokio::test]
async fn expiry_payout_mailbox_post_needs_the_bound_mailbox() {
	let ctx = TestContext::new("server/expiry_payout_mailbox_post_needs_the_bound_mailbox").await;
	let srv = ctx.captaind("server").cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let owner = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let mailbox = MailboxIdentifier::from_pubkey(Keypair::new(&SECP, &mut bip39::rand::thread_rng()).public_key());
	let (_, vtxo) = DummyTestVtxoSpec { user_keypair: owner, ..Default::default() }.build();
	db.write(async |t| t.execute_vtxo_tree_update(VtxoTreeUpdate::new()
		.insert_spendable_vtxos([ServerVtxo::from(vtxo.clone())])
		.bind_owner_mailboxes([(vtxo.id(), mailbox.as_pubkey())])?).await).await.unwrap();

	let negated = MailboxIdentifier::from_pubkey(mailbox.as_pubkey().negate(&SECP));
	assert_eq!(ark::expiry_payout::payout_script(negated.as_pubkey()),
		ark::expiry_payout::payout_script(mailbox.as_pubkey()));
	let mut rpc = srv.get_mailbox_public_rpc().await;
	let post = async |mailbox: MailboxIdentifier| protos::mailbox_server::PostArkoorMessageRequest {
		blinded_id: blinded_mailbox(&srv, &owner, mailbox).await,
		vtxos: vec![vtxo.serialize()],
	};
	let error = rpc.post_arkoor_message(post(negated).await).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument);
	assert!(db.read(async |t| t.get_mailbox_entries(negated, 0, 100).await).await.unwrap().is_empty());

	rpc.post_arkoor_message(post(mailbox).await).await.unwrap();
	assert_eq!(db.read(async |t| t.get_mailbox_entries(mailbox, 0, 100).await).await.unwrap().len(), 1);
}

/// In payout mode a recipient does not credit an arkoor output that was
/// never registered, here because the sender exited its input, and still
/// credits a registered one.
#[tokio::test]
async fn expiry_payout_unregistered_arkoor_is_not_credited() {
	let ctx = TestContext::new("server/expiry_payout_unregistered_arkoor_is_not_credited").await;
	let srv = ctx.captaind("server").funded(btc(10)).no_vtxo_pool().watchmand()
		.cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let sender = ctx.bark("sender", &srv).funded(sat(500_000)).create().await;
	sender.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&sender]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	sender.sync().await;
	let stale = sender.full_clone("stale_sender").await;
	let receiver = ctx.bark("receiver", &srv).create().await;
	let proxy = srv.start_proxy_no_mailbox(DropRegistration).await;
	sender.set_ark_url(&proxy.address).await;
	sender.send_oor(receiver.address().await, sat(50_000)).await;
	stale.start_exit_all().await;
	complete_exit(&ctx, &stale).await;
	stale.claim_all_exits(stale.get_onchain_address().await).await;
	let tip = ctx.generate_blocks(1).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	receiver.sync().await;
	let received = receiver.vtxo_ids_no_sync().await;
	assert_eq!(received.len(), 1);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	assert_eq!(db.read(async |t| t.get_user_vtxo_by_id(received[0]).await).await.unwrap().spend_state,
		SpendState::Unregistered);
	assert_eq!(receiver.spendable_balance_no_sync().await, Amount::ZERO);
	assert!(receiver.history().await.is_empty());

	let honest = ctx.bark("honest", &srv).funded(sat(100_000)).create().await;
	honest.board_and_confirm_and_register(&ctx, sat(80_000)).await;
	honest.send_oor(receiver.address().await, sat(20_000)).await;
	receiver.sync().await;
	assert_eq!(receiver.spendable_balance_no_sync().await, sat(20_000));
	assert_eq!(receiver.history().await.len(), 1);
}

/// The policy of round padding. The server records no owner for it and
/// pays its value to the operator at expiry.
fn padding_policy() -> VtxoPolicy {
	VtxoPolicy::new_pubkey("02dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c".parse().unwrap())
}

/// A payout server refuses a round output with the key of round padding, in
/// a delegated and in an interactive participation: it could not bind that
/// output to the mailbox of the participation. Rounds go on.
#[tokio::test]
async fn expiry_payout_round_output_with_the_padding_key_is_refused() {
	let ctx = TestContext::new("server/expiry_payout_round_output_with_the_padding_key_is_refused").await;
	let srv = ctx.captaind("server").funded(btc(1)).no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let wallet = ctx.bark_sdk("participant", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = full_vtxos(&wallet).await.pop().unwrap();
	let key = wallet.get_vtxo_key(&input).await.unwrap();
	let mailbox = wallet.mailbox_identifier().serialize();
	let output = VtxoRequest { policy: padding_policy(), amount: sat(90_000) };
	let mut rpc = srv.get_public_rpc().await;

	let attestation = DelegatedRoundParticipationAttestation::new(input.id(), &[output.clone()], &key);
	let error = rpc.submit_round_participation(protos::RoundParticipationRequest {
		input_vtxos: vec![protos::InputVtxo {
			vtxo_id: input.id().to_bytes().to_vec(),
			attestation: attestation.serialize(),
		}],
		vtxo_requests: vec![protos::VtxoRequest::from(&output)],
		unblinded_mailbox_id: Some(mailbox.clone()),
		scheduled_height: None,
	}).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert!(error.message().contains("padding"), "{error}");

	let mut events = rpc.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();
	srv.trigger_round().await;
	let challenge = async {
		loop {
			let event = RoundEvent::try_from(events.next().await.unwrap().unwrap()).unwrap();
			if let RoundEvent::Attempt(attempt) = event {
				break attempt.challenge;
			}
		}
	}.wait_millis(10_000).await;
	let cosign_key = Keypair::new(&SECP, &mut bip39::rand::thread_rng());
	let nonces = (0..srv.config().nb_round_nonces).map(|_| musig::nonce_pair(&cosign_key).1).collect();
	let request = SignedVtxoRequest { vtxo: output, cosign_pubkey: cosign_key.public_key(), nonces };
	let attestation = RoundAttemptAttestation::new(challenge, input.id(), &[request.clone()], &key);
	let error = rpc.submit_payment(protos::SubmitPaymentRequest {
		input_vtxos: vec![protos::InputVtxo {
			vtxo_id: input.id().to_bytes().to_vec(),
			attestation: attestation.serialize(),
		}],
		vtxo_requests: vec![request.into()],
		#[allow(deprecated)]
		offboard_requests: vec![],
		unblinded_mailbox_id: Some(mailbox),
	}).await.unwrap_err();
	assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error}");
	assert!(error.message().contains("padding"), "{error}");

	let mut finished = srv.subscribe_log::<RoundFinished>();
	wallet.refresh_vtxos_delegated(vec![input.id()]).await.unwrap().expect("refresh joined");
	srv.trigger_round().await;
	let round = finished.recv().wait_millis(30_000).await.unwrap();
	assert_eq!(round.nb_input_vtxos, 1);
}

/// A stored delegated participation with an output that the server cannot
/// bind to an owner mailbox is dropped when a round takes it up. That round
/// finishes without it, and the owner of its input can refresh the input.
#[tokio::test]
async fn expiry_payout_unbound_round_output_is_dropped() {
	let ctx = TestContext::new("server/expiry_payout_unbound_round_output_is_dropped").await;
	let srv = ctx.captaind("server").funded(btc(1)).no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let wallet = ctx.bark_sdk("participant", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let other = ctx.bark_sdk("other", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let input = full_vtxos(&wallet).await.pop().unwrap();
	let other_input = full_vtxos(&other).await.pop().unwrap();
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let tip = BlockHeight::new(ctx.bitcoind().get_block_count().await as u32);
	let output = StoredRoundOutput {
		vtxo_request: VtxoRequest { policy: padding_policy(), amount: sat(90_000) },
		unblinded_mailbox_id: Some(wallet.mailbox_identifier()),
	};
	let preimage: UnlockPreimage = rand::random();
	db.write(async |t| t.try_store_round_participation(
		tip, preimage, &[input.id()], [&output], None, None,
	).await).await.unwrap();

	let mut finished = srv.subscribe_log::<RoundFinished>();
	other.refresh_vtxos_delegated(vec![other_input.id()]).await.unwrap().expect("refresh joined");
	srv.trigger_round().await;
	let round = finished.recv().wait_millis(30_000).await.unwrap();
	assert_eq!(round.nb_input_vtxos, 1);
	let stored = db.read(async |t| t.unlock_hash_exists(UnlockHash::hash(&preimage)).await).await.unwrap();
	assert!(!stored, "the round drops the participation");

	wallet.refresh_vtxos_delegated(vec![input.id()]).await.unwrap().expect("refresh joined");
	srv.trigger_round().await;
	let round = finished.recv().wait_millis(30_000).await.unwrap();
	assert_eq!(round.nb_input_vtxos, 1);
}
