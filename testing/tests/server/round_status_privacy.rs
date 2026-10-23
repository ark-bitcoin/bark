use std::collections::HashSet;
use std::time::Duration;

use bitcoin::secp256k1::{Keypair, rand::thread_rng};

use ark::{ProtocolEncoding, SECP};
use ark::attestations::RoundParticipationStatusAttestation;
use ark::tree::signed::VtxoTreeSpec;
use server::database::Db;
use server_rpc::protos;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::ROUND_CONFIRMATIONS;

/// With `round_status_attestation_required`, the unlock hashes in the public
/// round broadcast don't let anyone else read a participation's status.
#[tokio::test]
async fn broadcast_hashes_do_not_authorize_round_status_queries() {
	let ctx = TestContext::new("server/broadcast_hashes_do_not_authorize_round_status_queries").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.round_submit_time = Duration::from_secs(1);
		cfg.round_status_attestation_required = true;
	}).create().await;
	let victim = ctx.bark("victim", &srv).funded(sat(1_000_000)).create().await;
	victim.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let private_inputs = victim.vtxo_ids().await.into_iter()
		.map(|id| id.to_bytes().to_vec()).collect::<Vec<_>>();
	assert!(!private_inputs.is_empty());

	let mut observer = srv.get_public_rpc().await;
	let mut events = observer.subscribe_rounds(protos::Empty {}).await.unwrap().into_inner();
	victim.refresh_all_delegated_no_sync().await;
	srv.trigger_round().await;

	let hashes = tokio::time::timeout(Duration::from_secs(30), async {
		let mut hashes = HashSet::new();
		loop {
			let event = events.message().await.unwrap().expect("event stream closed");
			match event.event {
				Some(protos::round_event::Event::VtxoProposal(proposal)) => {
					let spec = VtxoTreeSpec::deserialize(&proposal.vtxos_spec).unwrap();
					hashes.extend(spec.vtxos.into_iter().map(|leaf| leaf.unlock_hash));
				},
				Some(protos::round_event::Event::Finished(_)) => break hashes,
				Some(protos::round_event::Event::Failed(_)) => panic!("round failed"),
				_ => {},
			}
		}
	}).await.expect("round did not finish");
	assert!(!hashes.is_empty());

	let other_mailbox = Keypair::new(&SECP, &mut thread_rng());
	for hash in hashes {
		let foreign = RoundParticipationStatusAttestation::new(hash, &other_mailbox).serialize();
		for attestation in [vec![], foreign] {
			let status = observer.round_participation_status(protos::RoundParticipationStatusRequest {
				unlock_hash: hash.serialize(),
				attestation,
			}).await.expect_err("status without the owner's attestation");
			assert_eq!(status.code(), tonic::Code::NotFound, "{status}");
			assert!(private_inputs.iter().all(|id| !status.message().as_bytes()
				.windows(id.len()).any(|w| w == id.as_slice())));
		}
	}

	// the owner still completes its delegated refresh, sending its attestation
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	victim.sync().await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let unforfeited = db.read(async |t| {
		let row = t.query_one(
			"SELECT count(*) FROM round_participation \
			WHERE round_id IS NOT NULL AND forfeited_at IS NULL", &[],
		).await?;
		Ok(row.get::<_, i64>(0))
	}).await.unwrap();
	assert_eq!(unforfeited, 0);
	assert!(victim.vtxo_ids().await.iter().all(|id| !private_inputs.contains(&id.to_bytes().to_vec())));
}

/// With `round_status_attestation_required`, a delegated participation without
/// a mailbox id could never be queried, so it is refused at registration.
#[tokio::test]
async fn delegated_participation_without_mailbox_id_is_refused() {
	let ctx = TestContext::new("server/delegated_participation_without_mailbox_id_is_refused").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.round_status_attestation_required = true;
	}).create().await;

	let status = srv.get_public_rpc().await
		.submit_round_participation(protos::RoundParticipationRequest {
			input_vtxos: vec![],
			vtxo_requests: vec![],
			unblinded_mailbox_id: None,
			scheduled_height: None,
		}).await.expect_err("participation without mailbox id");
	assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status}");
	assert!(status.message().contains("unblinded mailbox id"), "{status}");
}
