//! An offboard takes two gRPC calls:
//!
//! - `prepare_offboard`: the client sends the request and its input vtxos, with an
//!   attestation per input. The server locks the vtxos and some wallet coins, and
//!   returns the unsigned offboard tx and its forfeit nonces.
//! - `finish_offboard`: the client sends its forfeit signatures. The server signs
//!   the offboard tx, broadcasts it and returns it.
//!
//! A session that is never finished times out and releases its locks.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::{Amount, FeeRate, SignedAmount, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use server_rpc::{protos, TryFromBytes};

use ark::{ProtocolEncoding, SECP};
use ark::attestations::OffboardRequestAttestation;
use ark::musig;
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use bark::WalletVtxo;
use bark::movement::MovementStatus;

use bitcoin_ext::rpc::RpcApi;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind::{self, ArkClient};


/// The error [AbandonOffboardProxy] fails prepare_offboard with.
const ABANDON_ERROR: &str = "proxy: abandoning the offboard session";

/// Forwards prepare_offboard upstream, so the server creates its pending
/// session, but reports [ABANDON_ERROR] to the client, which abandons the
/// offboard. Server-side errors pass through untouched. Every forwarded
/// request is recorded so the test can re-send it directly.
#[derive(Clone)]
struct AbandonOffboardProxy {
	requests: Arc<Mutex<Vec<protos::PrepareOffboardRequest>>>,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for AbandonOffboardProxy {
	async fn prepare_offboard(
		&self, upstream: &mut ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		self.requests.lock().unwrap().push(req.clone());
		upstream.prepare_offboard(req).await?;
		Err(tonic::Status::invalid_argument(ABANDON_ERROR))
	}
}

#[tokio::test]
async fn offboard_validates_requests_and_replays_retries() {
	let ctx = TestContext::new("server/offboard_validates_requests_and_replays_retries").await;
	// Every fee rate is 1 sat/vB, so the request can use a fixed fee.
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.fee_estimator.fallback_fee_rate_fast = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_slow = FeeRate::from_sat_per_vb_u32(1);
		cfg.max_offboard_amount = Some(sat(900_000));
	}).create().await;
	// The server prices an offboard in one of two ways, so each vtxo has one job:
	// - offboard_vtxo (800_000 sat): the whole vtxo goes onchain, the server takes its fee
	//   out of the vtxo (deduct_fees_from_gross_amount = true). bark's offboard.
	// - send_vtxo (500_000 sat): an exact amount goes onchain, the fee comes on top
	//   (deduct_fees_from_gross_amount = false). bark's send-onchain.
	// - dust_vtxo (400 sat): less than dust once the fee is taken out.
	// - large_vtxo (1_000_000 sat): more than the 900_000 sat max_offboard_amount.
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(sat(800_000))
		.boarded(sat(500_000))
		.boarded(sat(1_000_000))
		.create().await;
	// Boards have a 20_000 sat minimum, so the dust vtxo arrives by arkoor.
	let dust_source = ctx.bark_sdk("dust_source", &srv).boarded(sat(100_000)).create().await;
	dust_source.send_arkoor_payment(&wallet.new_address().await.unwrap(), sat(400)).await.unwrap();
	wallet.sync().await;
	let mut rpc = srv.get_public_rpc().await;

	// The wallet only provides the vtxos and their keys; the test talks to the server itself.
	let vtxos = wallet.spendable_vtxos().await.unwrap();
	let find_vtxo = |amount| vtxos.iter().find(|v| v.amount() == amount).unwrap().clone();
	let offboard_vtxo = find_vtxo(sat(800_000));
	let send_vtxo = find_vtxo(sat(500_000));
	let dust_vtxo = find_vtxo(sat(400));
	let large_vtxo = find_vtxo(sat(1_000_000));
	let prepare = async |req: &OffboardRequest, vtxo: &WalletVtxo| {
		let key = wallet.get_vtxo_key(vtxo).await.unwrap();
		protos::PrepareOffboardRequest {
			offboard: Some(req.into()),
			input_vtxo_ids: vec![vtxo.id().to_bytes().to_vec()],
			attestation: vec![OffboardRequestAttestation::new(req, &[vtxo.id()], &key).serialize()],
		}
	};
	let destination = ctx.bitcoind().get_new_address();
	let script_pubkey = destination.script_pubkey();

	// Using offboard_vtxo
	{
		// 799_000 sat onchain, 1_000 sat fee taken from the vtxo.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(799_000),
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};
		// Signs the forfeits against the server's nonces, with fresh nonces of our own on every call.
		let full_vtxo = wallet.get_full_vtxo(offboard_vtxo.id()).await.unwrap();
		let key = wallet.get_vtxo_key(&offboard_vtxo).await.unwrap();
		let sign = |prepared: &protos::PrepareOffboardResponse| {
			let offboard_tx = bitcoin::consensus::deserialize::<Transaction>(&prepared.offboard_tx).unwrap();
			let server_nonces = prepared.forfeit_cosign_nonces.iter()
				.map(|n| musig::PublicNonce::from_bytes(n).unwrap())
				.collect::<Vec<_>>();
			let sigs = OffboardForfeitContext::new(&[full_vtxo.clone()], &offboard_tx).unwrap()
				.user_sign_forfeits(&[key], &server_nonces).unwrap();
			protos::FinishOffboardRequest {
				offboard_txid: offboard_tx.compute_txid().to_byte_array().to_vec(),
				user_nonces: sigs.public_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
				partial_signatures: sigs.partial_signatures.iter().map(|s| s.serialize().to_vec()).collect(),
			}
		};

		// Leaves too little for the fee
		let bad = OffboardRequest { net_amount: sat(799_999), ..req.clone() };
		let err = rpc.prepare_offboard(prepare(&bad, &offboard_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("net amount does not match"), "{err}");

		// Fee rate below the server's minimum
		let bad = OffboardRequest { fee_rate: FeeRate::from_sat_per_kwu(1), ..req.clone() };
		let err = rpc.prepare_offboard(prepare(&bad, &offboard_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("fee rate too low"), "{err}");

		// Fee rate above any rate the server has seen
		let bad = OffboardRequest { fee_rate: FeeRate::from_sat_per_vb_u32(100), ..req.clone() };
		let err = rpc.prepare_offboard(prepare(&bad, &offboard_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("fee rate is no longer valid"), "{err}");

		// Attestation signed by someone who doesn't own the vtxo
		let stranger = Keypair::new(&SECP, &mut thread_rng());
		let bad = protos::PrepareOffboardRequest {
			attestation: vec![OffboardRequestAttestation::new(&req, &[offboard_vtxo.id()], &stranger).serialize()],
			..prepare(&req, &offboard_vtxo).await
		};
		let err = rpc.prepare_offboard(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("invalid attestations"), "{err}");

		// A client that lost the first response sends the same prepare_offboard again.
		let prepared = rpc.prepare_offboard(prepare(&req, &offboard_vtxo).await).await.unwrap().into_inner();
		let retry = rpc.prepare_offboard(prepare(&req, &offboard_vtxo).await).await.unwrap().into_inner();
		// The retry gets the same unsigned offboard tx and forfeit nonces.
		assert_eq!(prepared, retry);
		let finish = sign(&prepared);

		// Finish for a session the server never prepared
		let bad = protos::FinishOffboardRequest {
			offboard_txid: Txid::all_zeros().to_byte_array().to_vec(),
			..finish.clone()
		};
		let err = rpc.finish_offboard(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("unknown offboard txid"), "{err}");

		// Finish with the wrong number of signatures fails the session
		let bad = protos::FinishOffboardRequest { partial_signatures: vec![], ..finish.clone() };
		let err = rpc.finish_offboard(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("incorrect number of partial signatures"), "{err}");
		// A session has one signing chance, so the correct finish is refused as well.
		let err = rpc.finish_offboard(finish.clone()).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("unknown offboard txid"), "{err}");
		let stale_sigs = finish.partial_signatures;

		// The failed session released the vtxo, so a new prepare starts a new session.
		let prepared = rpc.prepare_offboard(prepare(&req, &offboard_vtxo).await).await.unwrap().into_inner();
		let finish = sign(&prepared);

		// Signatures from the failed session don't verify against the new session's nonces
		let bad = protos::FinishOffboardRequest {
			partial_signatures: stale_sigs,
			..finish.clone()
		};
		let err = rpc.finish_offboard(bad).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("invalid partial forfeit signatures"), "{err}");

		// A third session finishes.
		let prepared = rpc.prepare_offboard(prepare(&req, &offboard_vtxo).await).await.unwrap().into_inner();
		let finish = sign(&prepared);
		// The server broadcasts the offboard tx only after the forfeits are signed.
		let offboard_txid = bitcoin::consensus::deserialize::<Transaction>(&prepared.offboard_tx)
			.unwrap().compute_txid();
		let mempool = srv.bitcoind().sync_client().get_raw_mempool().unwrap();
		assert!(!mempool.contains(&offboard_txid));
		let first = rpc.finish_offboard(finish.clone()).await.unwrap().into_inner();
		let mempool = srv.bitcoind().sync_client().get_raw_mempool().unwrap();
		assert!(mempool.contains(&offboard_txid));

		// A client that lost the first response sends the same finish_offboard again.
		let retry = rpc.finish_offboard(finish).await.unwrap().into_inner();
		assert_eq!(first, retry);
		// bark signs with fresh nonces on every attempt, so its retry carries different signatures.
		let resigned = rpc.finish_offboard(sign(&prepared)).await.unwrap().into_inner();
		// Both retries get the same signed offboard tx.
		assert_eq!(first, resigned);

		// The signed offboard tx confirms and pays the destination.
		ctx.bitcoind().await_transaction(offboard_txid).await;
		ctx.bitcoind().generate(1).await;
		assert_eq!(ctx.bitcoind().get_received_by_address(&destination), sat(799_000));
	}

	// Using send_vtxo
	{
		// 499_000 sat onchain, 1_000 sat fee on top of the amount.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(499_000),
			deduct_fees_from_gross_amount: false,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};

		// Amount plus fee is more than the vtxo
		let bad = OffboardRequest { net_amount: sat(499_999), ..req.clone() };
		let err = rpc.prepare_offboard(prepare(&bad, &send_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("gross amount does not match"), "{err}");

		// Sends a dust amount
		let bad = OffboardRequest { net_amount: sat(100), ..req.clone() };
		let err = rpc.prepare_offboard(prepare(&bad, &send_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("invalid offboard request"), "{err}");

		// The send is accepted. It runs after the offboard finished, because a pending
		// session locks the server's only wallet coin.
		rpc.prepare_offboard(prepare(&req, &send_vtxo).await).await.unwrap();
	}

	// Using dust_vtxo
	{
		// Asks for exactly the dust limit, so only the fee pushes it below.
		let req = OffboardRequest {
			net_amount: script_pubkey.minimal_non_dust(),
			script_pubkey: script_pubkey.clone(),
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};
		let err = rpc.prepare_offboard(prepare(&req, &dust_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("below dust limit"), "{err}");
	}

	// Using large_vtxo
	{
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(999_000),
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};

		// Over max_offboard_amount
		let err = rpc.prepare_offboard(prepare(&req, &large_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("offboard amount exceeds limit of 0.00900000 BTC"), "{err}");

		// A max_offboard_amount of zero disables offboards entirely
		srv.stop().await.unwrap();
		srv.config_mut().max_offboard_amount = Some(Amount::ZERO);
		srv.start().await.unwrap();
		// A restart reserves new ports, so connect again.
		let mut rpc = srv.get_public_rpc().await;
		let err = rpc.prepare_offboard(prepare(&req, &large_vtxo).await).await.unwrap_err();
		assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
		assert!(err.message().contains("offboard is temporarily disabled"), "{err}");
	}
}

/// An abandoned offboard session must release the wallet UTXOs it locked
/// once it expires, so that pending offboards cannot starve the rounds
/// wallet (and with it round funding) until a restart.
///
/// Each 6btc offboard needs more than half of the rounds wallet's coins
/// (asserted below), so while the abandoned session for the first vtxo is
/// pending, offboarding the second vtxo fails on the server for lack of
/// funds — the starvation itself. Once the session expires, that same
/// offboard must be accepted. It shares no vtxos with the abandoned
/// session, only wallet funding, so its acceptance is only possible if the
/// expired session released the wallet UTXOs it had locked.
#[tokio::test]
async fn utxos_unlock_after_pending_offboard_expiry() {
	const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

	let ctx = TestContext::new("server/utxos_unlock_after_pending_offboard_expiry").await;
	let srv = ctx.captaind("server")
		.no_vtxo_pool()
		.funded(btc(10))
		.cfg(|c| c.offboard_session_timeout = SESSION_TIMEOUT)
		.create().await;

	let requests = Arc::new(Mutex::new(Vec::new()));
	let proxy = srv.start_proxy_no_mailbox(AbandonOffboardProxy {
		requests: requests.clone(),
	}).await;

	let wallet = ctx.bark_sdk("bark", &proxy)
		.boarded(btc(6))
		.boarded(btc(6))
		.create().await;

	// Premise: the 10btc rounds wallet cannot fund two 6btc offboard txs at
	// the same time.
	let status = srv.wallet_status().await;
	assert!(status.rounds.trusted_balance < btc(11),
		"rounds wallet is rich enough to fund two offboards, breaking the \
		test's premise: {}", status.rounds.trusted_balance,
	);

	let [vtxo1, vtxo2] = wallet.spendable_vtxos().await.expect("list vtxos")
		.try_into().expect("should have two boarded vtxos");

	// Offboard the first vtxo; the proxy abandons the session right after
	// the server has created it.
	let address = ctx.bitcoind().get_new_address();
	let err = wallet.offboard_vtxos([vtxo1.id()], address.clone()).await
		.expect_err("the proxy should have failed the first offboard");
	assert!(format!("{err:#}").contains(ABANDON_ERROR), "unexpected error: {err:#}");

	// The rejected offboard leaves a failed movement recording the intent,
	// with a zero effective balance: its vtxos went back to spendable, so
	// the wallet's balance never actually changed.
	let movements = wallet.history().await.expect("list movements").into_iter()
		.filter(|m| m.subsystem.name == "bark.offboard")
		.collect::<Vec<_>>();
	assert_eq!(movements.len(), 1);
	assert_eq!(movements[0].status, MovementStatus::Failed);
	assert_ne!(movements[0].intended_balance, SignedAmount::ZERO);
	assert_eq!(movements[0].effective_balance, SignedAmount::ZERO);

	// While the session is pending it keeps its wallet UTXOs locked, so
	// the server cannot fund an offboard of the second vtxo: this is the
	// starvation. Note this error comes from the server, not the proxy.
	let err = wallet.offboard_vtxos([vtxo2.id()], address).await
		.expect_err("the second offboard should fail while the wallet UTXOs are locked");
	let err = format!("{err:#}");
	assert!(err.contains("failed to build offboard tx"), "unexpected error: {err}");
	// The lock leaves nothing to select. The build must fail because the
	// wallet has no coins, not for another reason.
	assert!(err.contains("Insufficient funds"), "unexpected error: {err}");
	assert!(!err.contains(ABANDON_ERROR), "the error should come from the server: {err}");

	// Once the abandoned session expires, the same offboard must be
	// accepted again.
	let req = requests.lock().unwrap().last().cloned()
		.expect("the second prepare_offboard request should have been recorded");
	let mut direct = srv.get_public_rpc().await;
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		tokio::time::sleep(SESSION_TIMEOUT).await;
		match direct.prepare_offboard(req.clone()).await {
			Ok(_) => break,
			Err(e) => assert!(Instant::now() < deadline,
				"expired offboard session did not release its wallet UTXOs: {e}"),
		}
	}
}

/// Abandoned offboard sessions keep their wallet UTXOs locked until they
/// expire. Together they may lock only part of the rounds wallet, so tiny
/// abandoned offboards cannot take the coins rounds and other users need.
#[tokio::test]
async fn abandoned_offboards_lock_at_most_part_of_the_wallet() {
	let ctx = TestContext::new("server/abandoned_offboards_lock_at_most_part_of_the_wallet").await;
	let srv = ctx.captaind("server")
		.no_vtxo_pool()
		.funded(btc(1))
		.cfg(|c| c.offboard_max_locked_percent = 25)
		.create().await;
	for _ in 0..7 {
		ctx.fund_captaind(&srv, btc(1)).await;
	}
	let status = srv.wallet_status().await;
	assert_eq!(status.rounds.confirmed_utxos.len(), 8);
	assert_eq!(status.rounds.trusted_balance, btc(8));

	let requests = Arc::new(Mutex::new(Vec::new()));
	let proxy = srv.start_proxy_no_mailbox(AbandonOffboardProxy {
		requests: requests.clone(),
	}).await;
	let attacker = ctx.bark_sdk("attacker", &proxy)
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.create().await;
	let [vtxo1, vtxo2, vtxo3] = attacker.spendable_vtxos().await.expect("list vtxos")
		.try_into().expect("should have three boarded vtxos");

	// Each tiny offboard locks a whole 1btc coin. Two of them reach the 2btc cap.
	let address = ctx.bitcoind().get_new_address();
	for vtxo in [vtxo1, vtxo2] {
		let err = attacker.offboard_vtxos([vtxo.id()], address.clone()).await
			.expect_err("the proxy abandons the session");
		assert!(format!("{err:#}").contains(ABANDON_ERROR), "unexpected error: {err:#}");
	}

	let err = attacker.offboard_vtxos([vtxo3.id()], address).await
		.expect_err("a third session would lock more than the cap");
	let err = format!("{err:#}");
	assert!(err.contains("too many pending offboards"), "unexpected error: {err}");
	assert!(!err.contains(ABANDON_ERROR), "the error should come from the server: {err}");

	// Being full is not the client's fault, so tell it to retry later.
	let req = requests.lock().unwrap().last().cloned()
		.expect("the third prepare_offboard request should have been recorded");
	let status = srv.get_public_rpc().await.prepare_offboard(req).await
		.expect_err("the cap should still refuse the third session");
	assert_eq!(status.code(), tonic::Code::Unavailable, "unexpected status: {status}");
}
