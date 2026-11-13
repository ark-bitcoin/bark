use bitcoin::Amount;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Keypair;
use bitcoin_ext::BlockHeight;

use futures::StreamExt;

use ark::{
	musig, ProtocolEncoding, SECP, ServerVtxo, SignedVtxoRequest, Vtxo, VtxoId, VtxoPolicy, VtxoRequest,
};
use ark::arkoor::package::ArkoorPackageBuilder;
use ark::attestations::DelegatedRoundParticipationAttestation;
use ark::mailbox::{MailboxIdentifier, MailboxType};
use ark::rounds::{RoundAttemptAttestation, RoundEvent};
use ark::test_util::dummy::DummyTestVtxoSpec;
use ark::tree::signed::{UnlockHash, UnlockPreimage};
use ark::vtxo::Full;
use bark::Wallet;
use server::database::{Db, MailboxPayload, SpendState};
use server::database::rounds::StoredRoundOutput;
use server::database::tree::VtxoTreeUpdate;
use server_log::RoundFinished;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;
use ark_testing::exit::complete_exit;
use ark_testing::util::FutureExt;

use crate::registration::DropRegistration;
use super::{bind_outputs, blinded_mailbox, full_vtxos};

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

/// A wallet with a delegated and an interactive participation in one round
/// reads its mailbox after the round. The server posts the round result
/// only to the mailbox of the delegated participation, as an upstream
/// server does.
#[tokio::test]
async fn expiry_payout_two_participations_in_a_round_keep_the_mailbox() {
	let ctx = TestContext::new("server/expiry_payout_two_participations_in_a_round_keep_the_mailbox").await;
	let srv = ctx.captaind("server").funded(btc(1)).no_vtxo_pool().cfg(|cfg| cfg.expiry_payouts = true).create().await;
	let wallet = ctx.bark_sdk("participant", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let other = ctx.bark_sdk("other", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let delegated = full_vtxos(&wallet).await.pop().unwrap();
	other.send_arkoor_payment(&wallet.new_address().await.unwrap(), sat(40_000)).await.unwrap();
	wallet.sync_mailbox().await.unwrap();
	let interactive = full_vtxos(&wallet).await.into_iter().find(|vtxo| vtxo.id() != delegated.id())
		.expect("the wallet received the arkoor");

	let mut finished = srv.subscribe_log::<RoundFinished>();
	wallet.refresh_vtxos_delegated(vec![delegated.id()]).await.unwrap().expect("refresh joined");
	let (refresh, _) = tokio::join!(wallet.refresh_vtxos(vec![interactive.id()]), srv.trigger_round());
	refresh.unwrap().expect("refresh joined");
	let round = finished.recv().wait_millis(30_000).await.unwrap();
	assert_eq!(round.nb_input_vtxos, 2, "one round takes both participations");

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mailbox = wallet.mailbox_identifier();
	let entries = db.read(async |t| t.get_mailbox_messages(mailbox, 0, 100).await).await
		.expect("the mailbox stays readable");
	let results = entries.iter()
		.filter(|entry| matches!(entry.payload, MailboxPayload::RoundParticipationCompleted { .. })).count();
	assert_eq!(results, 1, "only the delegated participation has a round result in the mailbox");
	wallet.sync_mailbox().await.unwrap();
}
