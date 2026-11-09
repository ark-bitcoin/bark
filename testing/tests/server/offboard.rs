//! An offboard takes two gRPC calls:
//!
//! - `prepare_offboard`: the client sends the request and its input vtxos, with an
//!   attestation per input. The server locks the vtxos and some wallet coins, and
//!   returns the unsigned offboard tx and its forfeit nonces.
//! - `finish_offboard`: the client sends its forfeit signatures. The server signs
//!   the offboard tx, broadcasts it and returns it.
//!
//! A session that is never finished times out and releases its locks.

use std::collections::HashSet;
use std::time::Duration;

use bitcoin::{Amount, FeeRate, Transaction, Txid};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use server_rpc::{protos, TryFromBytes};
use server_log::{ClaimBroadcast, OffboardSessionTimeout, ProgressBroadcast};

use ark::{ProtocolEncoding, VtxoId, SECP};
use ark::attestations::OffboardRequestAttestation;
use ark::musig;
use ark::offboard::{OffboardForfeitContext, OffboardRequest};
use bark::WalletVtxo;

use bitcoin_ext::{BlockDelta, BlockHeight};
use bitcoin_ext::rpc::RpcApi;

use ark_testing::{btc, sat, TestContext};

#[tokio::test]
async fn offboard_validates_requests_and_replays_retries() {
	let ctx = TestContext::new("server/offboard_validates_requests_and_replays_retries").await;
	// Every fee rate is 1 sat/vB, so the request can use a fixed fee.
	let srv = ctx.captaind("server").funded(btc(1)).cfg(|cfg| {
		cfg.fee_estimator.fallback_fee_rate_fast = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_slow = FeeRate::from_sat_per_vb_u32(1);
		cfg.max_offboard_amount = Some(sat(900_000));
		// The cap on locked coins is tested elsewhere.
		cfg.offboard_max_locked_percent = 100;
		// Short, so the vtxos expire after few blocks.
		cfg.vtxo_lifetime = BlockDelta::new(144);
	}).watchmand_cfg(|cfg| {
		// The watchman only acts when the test triggers it.
		cfg.watchman.reaction_interval = Duration::from_secs(3600);
		cfg.watchman.sweep_interval = Duration::from_secs(3600);
		// It waits 2 blocks after an exit confirms before it applies the forfeit.
		cfg.watchman.progress_grace_period = BlockDelta::new(2);
	}).create().await;
	// A pending session locks a whole coin, so give the server more than one.
	for _ in 0..7 {
		ctx.fund_captaind(&srv, btc(1)).await;
	}
	let wm = srv.watchmand();
	// The watchman pays the fees of the txs it broadcasts.
	ctx.bitcoind().fund_addr(wm.wait_wallet_address().await, sat(1_000_000)).await;
	// Each block below boards the vtxos it needs from this wallet. The wallet only
	// provides the vtxos and their keys; the test talks to the server itself.
	// Manual sync stops the wallet from spending its coins on CPFPs for the exits the test mines.
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(btc(5))
		.create().await;
	let mut rpc = srv.get_public_rpc().await;

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

	// Offboard a single vtxo
	Box::pin(async {
		// A vtxo of 800_000 sat.
		let [offboard_vtxo] = ctx.board(&wallet, &[sat(800_000)]).await.try_into().unwrap();
		// 799_000 sat onchain and 1_000 sat in fees.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(799_000),
			// The fee comes out of the vtxo, like bark's offboard.
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

		// The user exits the offboarded vtxo anyway.
		let exit_txs = full_vtxo.transactions().map(|item| item.tx).collect::<Vec<_>>();
		ctx.mine(&exit_txs).await;
		let exit_point = offboard_vtxo.id().to_point();
		let client = ctx.bitcoind().sync_client();
		assert!(client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_some());

		// After the grace period, the watchman applies the forfeit, which spends the exit
		// output and the connector.
		ctx.bitcoind().generate(2).await;
		let tip = ctx.bitcoind().get_block_count().await;
		wm.wait_for_sync_height(BlockHeight::new(u32::try_from(tip).unwrap())).await;
		let mut progress = wm.subscribe_log::<ProgressBroadcast>();
		wm.trigger_sweep().await;
		let forfeit = progress.recv().await.unwrap();
		assert_eq!(forfeit.vtxo_id, offboard_vtxo.id());
		ctx.bitcoind().await_transaction(forfeit.cpfp_txid).await;
		ctx.bitcoind().generate(1).await;
		assert!(client.get_tx_out(&exit_point.txid, exit_point.vout, Some(true)).unwrap().is_none());
	}).await;

	// Offboard two vtxos together, then exit them one at a time
	Box::pin(async {
		// Offboarded together, so their forfeits share one connector output that a fanout tx splits.
		let [multi_a, multi_b] = ctx.board(&wallet, &[sat(300_000), sat(310_000)]).await
			.try_into().unwrap();
		// 609_000 sat onchain and 1_000 sat in fees.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(609_000),
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};
		let ids = [multi_a.id(), multi_b.id()];
		let keys = [
			wallet.get_vtxo_key(&multi_a).await.unwrap(),
			wallet.get_vtxo_key(&multi_b).await.unwrap(),
		];
		let full_vtxos = [
			wallet.get_full_vtxo(multi_a.id()).await.unwrap(),
			wallet.get_full_vtxo(multi_b.id()).await.unwrap(),
		];
		let prepared = rpc.prepare_offboard(protos::PrepareOffboardRequest {
			offboard: Some((&req).into()),
			input_vtxo_ids: ids.iter().map(|id| id.to_bytes().to_vec()).collect(),
			attestation: keys.iter()
				.map(|key| OffboardRequestAttestation::new(&req, &ids, key).serialize())
				.collect(),
		}).await.unwrap().into_inner();
		let offboard_tx = bitcoin::consensus::deserialize::<Transaction>(&prepared.offboard_tx).unwrap();
		let server_nonces = prepared.forfeit_cosign_nonces.iter()
			.map(|n| musig::PublicNonce::from_bytes(n).unwrap())
			.collect::<Vec<_>>();
		let sigs = OffboardForfeitContext::new(&full_vtxos, &offboard_tx).unwrap()
			.user_sign_forfeits(&keys, &server_nonces).unwrap();
		rpc.finish_offboard(protos::FinishOffboardRequest {
			offboard_txid: offboard_tx.compute_txid().to_byte_array().to_vec(),
			user_nonces: sigs.public_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
			partial_signatures: sigs.partial_signatures.iter().map(|s| s.serialize().to_vec()).collect(),
		}).await.unwrap();
		ctx.bitcoind().await_transaction(offboard_tx.compute_txid()).await;
		ctx.bitcoind().generate(1).await;

		// The forfeits share one connector output, but the watchman applies each one on its own.
		let [full_a, full_b] = full_vtxos;
		let client = ctx.bitcoind().sync_client();
		let mut progress = wm.subscribe_log::<ProgressBroadcast>();

		// The user exits multi_a.
		let exit_txs = full_a.transactions().map(|item| item.tx).collect::<Vec<_>>();
		ctx.mine(&exit_txs).await;
		let exit_a = multi_a.id().to_point();
		assert!(client.get_tx_out(&exit_a.txid, exit_a.vout, Some(true)).unwrap().is_some());

		// After the grace period, the watchman first broadcasts the fanout tx, which splits
		// the connector output into one connector per forfeit.
		ctx.bitcoind().generate(2).await;
		let tip = ctx.bitcoind().get_block_count().await;
		wm.wait_for_sync_height(BlockHeight::new(u32::try_from(tip).unwrap())).await;
		wm.trigger_sweep().await;
		let fanout = progress.recv().await.unwrap();
		assert_eq!(fanout.vtxo_id, multi_a.id());
		ctx.bitcoind().await_transaction(fanout.cpfp_txid).await;
		ctx.bitcoind().generate(1).await;
		let tip = ctx.bitcoind().get_block_count().await;
		wm.wait_for_sync_height(BlockHeight::new(u32::try_from(tip).unwrap())).await;

		// Once the fanout tx confirms, it applies the forfeit of multi_a.
		wm.trigger_sweep().await;
		let forfeit = progress.recv().await.unwrap();
		assert_eq!(forfeit.vtxo_id, multi_a.id());
		ctx.bitcoind().await_transaction(forfeit.cpfp_txid).await;
		ctx.bitcoind().generate(1).await;
		assert!(client.get_tx_out(&exit_a.txid, exit_a.vout, Some(true)).unwrap().is_none());

		// The user exits multi_b later.
		let exit_txs = full_b.transactions().map(|item| item.tx).collect::<Vec<_>>();
		ctx.mine(&exit_txs).await;
		let exit_b = multi_b.id().to_point();
		assert!(client.get_tx_out(&exit_b.txid, exit_b.vout, Some(true)).unwrap().is_some());

		// The fanout tx is already onchain, so after the grace period the watchman applies
		// the forfeit of multi_b right away.
		ctx.bitcoind().generate(2).await;
		let tip = ctx.bitcoind().get_block_count().await;
		wm.wait_for_sync_height(BlockHeight::new(u32::try_from(tip).unwrap())).await;
		wm.trigger_sweep().await;
		let forfeit = progress.recv().await.unwrap();
		assert_eq!(forfeit.vtxo_id, multi_b.id());
		assert_ne!(forfeit.txid, fanout.txid);
		ctx.bitcoind().await_transaction(forfeit.cpfp_txid).await;
		ctx.bitcoind().generate(1).await;
		assert!(client.get_tx_out(&exit_b.txid, exit_b.vout, Some(true)).unwrap().is_none());
	}).await;

	// Send an exact amount onchain
	Box::pin(async {
		// A vtxo of 500_000 sat.
		let [send_vtxo] = ctx.board(&wallet, &[sat(500_000)]).await.try_into().unwrap();
		// 499_000 sat onchain and 1_000 sat in fees.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(499_000),
			// The fee comes on top of the amount, like bark's send-onchain.
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

		// The send is accepted. Its session stays pending and locks one wallet coin.
		rpc.prepare_offboard(prepare(&req, &send_vtxo).await).await.unwrap();
	}).await;

	// Offboard a vtxo that is dust once the fee is taken out
	Box::pin(async {
		// Boards have a 20_000 sat minimum, so the 400 sat vtxo arrives by arkoor.
		let dust_source = ctx.bark_sdk("dust_source", &srv).boarded(sat(100_000)).create().await;
		dust_source.send_arkoor_payment(&wallet.new_address().await.unwrap(), sat(400)).await.unwrap();
		wallet.sync().await;
		let dust_vtxo = wallet.spendable_vtxos().await.unwrap().into_iter()
			.find(|v| v.amount() == sat(400)).unwrap();

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
	}).await;

	// Offboard vtxos that expire at different heights, and never exit them
	Box::pin(async {
		// The late vtxos are boarded 10 blocks after the early ones, so they expire later.
		// None of them exits, so the connector of their offboard stays unspent. Four inputs
		// make it 4 * 330 sat, enough to pay for its own sweep.
		let [early_a, early_b] = ctx.board(&wallet, &[sat(200_000), sat(210_000)]).await
			.try_into().unwrap();
		ctx.bitcoind().generate(10).await;
		let [late_a, late_b] = ctx.board(&wallet, &[sat(220_000), sat(230_000)]).await
			.try_into().unwrap();
		let early_expiry = early_a.expiry_height().max(early_b.expiry_height());
		let late_expiry = late_a.expiry_height().max(late_b.expiry_height());
		assert!(late_a.expiry_height().min(late_b.expiry_height()) > early_expiry);

		// 859_000 sat onchain and 1_000 sat in fees.
		let req = OffboardRequest {
			script_pubkey: script_pubkey.clone(),
			net_amount: sat(859_000),
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};
		let inputs = [&early_a, &early_b, &late_a, &late_b];
		let ids = inputs.map(|v| v.id());
		let mut keys = Vec::new();
		let mut full_vtxos = Vec::new();
		for vtxo in inputs {
			keys.push(wallet.get_vtxo_key(vtxo).await.unwrap());
			full_vtxos.push(wallet.get_full_vtxo(vtxo.id()).await.unwrap());
		}
		let prepared = rpc.prepare_offboard(protos::PrepareOffboardRequest {
			offboard: Some((&req).into()),
			input_vtxo_ids: ids.iter().map(|id| id.to_bytes().to_vec()).collect(),
			attestation: keys.iter()
				.map(|key| OffboardRequestAttestation::new(&req, &ids, key).serialize())
				.collect(),
		}).await.unwrap().into_inner();
		let offboard_tx = bitcoin::consensus::deserialize::<Transaction>(&prepared.offboard_tx).unwrap();
		let server_nonces = prepared.forfeit_cosign_nonces.iter()
			.map(|n| musig::PublicNonce::from_bytes(n).unwrap())
			.collect::<Vec<_>>();
		let sigs = OffboardForfeitContext::new(&full_vtxos, &offboard_tx).unwrap()
			.user_sign_forfeits(&keys, &server_nonces).unwrap();
		rpc.finish_offboard(protos::FinishOffboardRequest {
			offboard_txid: offboard_tx.compute_txid().to_byte_array().to_vec(),
			user_nonces: sigs.public_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
			partial_signatures: sigs.partial_signatures.iter().map(|s| s.serialize().to_vec()).collect(),
		}).await.unwrap();
		ctx.bitcoind().await_transaction(offboard_tx.compute_txid()).await;
		ctx.bitcoind().generate(1).await;
		// The offboard tx pays the connector of all four forfeits to its second output.
		let connector = bitcoin::OutPoint::new(offboard_tx.compute_txid(), 1);
		let boards = full_vtxos.iter().map(|v| v.chain_anchor()).collect::<Vec<_>>();
		let (early_boards, late_boards) = boards.split_at(2);
		let mut claims = wm.subscribe_log::<ClaimBroadcast>();

		// When the early vtxos expire, the watchman sweeps their board outputs. It keeps
		// the connector, because a forfeit of a late vtxo might still need it.
		ctx.bitcoind().generate(early_expiry.to_u32()
			.checked_sub(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap()).unwrap()).await;
		wm.wait_for_sync_height(early_expiry).await;
		wm.trigger_sweep().await;
		let sweep = claims.recv().await.unwrap();
		let swept = sweep.vtxo_ids.iter().map(|id| id.to_point()).collect::<HashSet<_>>();
		assert!(early_boards.iter().all(|b| swept.contains(b)), "{sweep:?}");
		assert!(!late_boards.iter().any(|b| swept.contains(b)), "{sweep:?}");
		assert!(!swept.contains(&connector), "{sweep:?}");
		ctx.bitcoind().await_transaction(sweep.txid).await;

		// When the late vtxos expire, the watchman sweeps their board outputs, and still
		// keeps the connector.
		ctx.bitcoind().generate(late_expiry.to_u32()
			.checked_sub(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap()).unwrap()).await;
		wm.wait_for_sync_height(late_expiry).await;
		wm.trigger_sweep().await;
		let sweep = claims.recv().await.unwrap();
		let swept = sweep.vtxo_ids.iter().map(|id| id.to_point()).collect::<HashSet<_>>();
		assert!(late_boards.iter().all(|b| swept.contains(b)), "{sweep:?}");
		assert!(!swept.contains(&connector), "{sweep:?}");
		ctx.bitcoind().await_transaction(sweep.txid).await;

		// 144 blocks after the latest expiry, the watchman sweeps the connector into the
		// rounds wallet.
		let connector_expiry = late_expiry + BlockDelta::new(144);
		ctx.bitcoind().generate(connector_expiry.to_u32()
			.checked_sub(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap()).unwrap()).await;
		wm.wait_for_sync_height(connector_expiry).await;
		srv.wait_for_sync_height(connector_expiry).await;
		let rounds_balance = srv.wallet_status().await.rounds.total_balance;
		wm.trigger_sweep().await;
		let sweep = claims.recv().await.unwrap();
		assert_eq!(sweep.vtxo_ids.iter().map(|id| id.to_point()).collect::<Vec<_>>(), vec![connector]);
		ctx.bitcoind().await_transaction(sweep.txid).await;
		ctx.bitcoind().generate(1).await;
		let tip = BlockHeight::new(u32::try_from(ctx.bitcoind().get_block_count().await).unwrap());
		srv.wait_for_sync_height(tip).await;
		let client = ctx.bitcoind().sync_client();
		assert!(client.get_tx_out(&connector.txid, connector.vout, Some(true)).unwrap().is_none());
		assert_eq!(srv.wallet_status().await.rounds.total_balance, rounds_balance + sweep.total_output_value);
	}).await;

	// Offboard more than max_offboard_amount
	Box::pin(async {
		// A vtxo of 1_000_000 sat, more than the 900_000 sat max_offboard_amount.
		let [large_vtxo] = ctx.board(&wallet, &[sat(1_000_000)]).await.try_into().unwrap();
		// 999_000 sat onchain and 1_000 sat in fees.
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
	}).await;
}

/// A prepared offboard keeps its wallet UTXOs locked until the session fails or times out.
/// Together, pending sessions lock at most offboard_max_locked_percent of the
/// rounds wallet.
#[tokio::test]
async fn pending_offboards_lock_at_most_part_of_the_wallet() {
	let ctx = TestContext::new("server/pending_offboards_lock_at_most_part_of_the_wallet").await;
	// Every fee rate is 1 sat/vB, so the request can use a fixed fee.
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).cfg(|cfg| {
		cfg.fee_estimator.fallback_fee_rate_fast = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_slow = FeeRate::from_sat_per_vb_u32(1);
		cfg.offboard_max_locked_percent = 25;
		// Short, so the test doesn't wait long. Long enough that the first two sessions
		// are still pending when the third is refused.
		cfg.offboard_session_timeout = Duration::from_secs(3);
	}).create().await;
	for _ in 0..7 {
		ctx.fund_captaind(&srv, btc(1)).await;
	}
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.boarded(sat(200_000))
		.create().await;
	let mut rpc = srv.get_public_rpc().await;

	let prepare = |req: &OffboardRequest, vtxo_id: VtxoId, key: &Keypair| protos::PrepareOffboardRequest {
		offboard: Some(req.into()),
		input_vtxo_ids: vec![vtxo_id.to_bytes().to_vec()],
		attestation: vec![OffboardRequestAttestation::new(req, &[vtxo_id], key).serialize()],
	};
	// Offboard a 200_000 sat vtxo to a fresh address, paying 1_000 sat in fees.
	let req = OffboardRequest {
		script_pubkey: ctx.bitcoind().get_new_address().script_pubkey(),
		net_amount: sat(199_000),
		deduct_fees_from_gross_amount: true,
		fee_rate: FeeRate::from_sat_per_vb_u32(1),
	};
	let mut vtxos = Vec::new();
	for v in wallet.spendable_vtxos().await.unwrap() {
		vtxos.push((v.id(), wallet.get_vtxo_key(&v).await.unwrap()));
	}
	let [(vtxo1, key1), (vtxo2, key2), (vtxo3, key3)] = vtxos.try_into().unwrap();

	// The rounds wallet holds 8 coins of 1 btc, so each prepared offboard locks a whole coin.
	// Two sessions lock 2 btc, which is the 25% cap.
	let mut timeouts = srv.subscribe_log::<OffboardSessionTimeout>();
	let first = rpc.prepare_offboard(prepare(&req, vtxo1, &key1)).await.unwrap().into_inner();
	rpc.prepare_offboard(prepare(&req, vtxo2, &key2)).await.unwrap();

	// A third session would lock more than the cap. The client should retry later.
	let err = rpc.prepare_offboard(prepare(&req, vtxo3, &key3)).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");
	assert!(err.message().contains("too many pending offboards"), "{err}");

	// A finish without signatures fails the first session, which frees its coin.
	let first_tx = bitcoin::consensus::deserialize::<Transaction>(&first.offboard_tx).unwrap();
	let err = rpc.finish_offboard(protos::FinishOffboardRequest {
		offboard_txid: first_tx.compute_txid().to_byte_array().to_vec(),
		user_nonces: vec![],
		partial_signatures: vec![],
	}).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
	assert!(err.message().contains("incorrect number of public nonces"), "{err}");
	rpc.prepare_offboard(prepare(&req, vtxo3, &key3)).await.unwrap();

	// Sessions that are never finished time out, which frees their coins and vtxos.
	let first = timeouts.recv().await.unwrap();
	let second = timeouts.recv().await.unwrap();
	let expired = first.vtxos.into_iter().chain(second.vtxos).collect::<HashSet<_>>();
	assert_eq!(expired, HashSet::from([vtxo2, vtxo3]));
	rpc.prepare_offboard(prepare(&req, vtxo1, &key1)).await.unwrap();
	rpc.prepare_offboard(prepare(&req, vtxo2, &key2)).await.unwrap();
}

/// A vtxo is in one place at a time. The server refuses to spend a vtxo that
/// is in an offboard session, and to offboard a vtxo that is spent or exited
/// onchain. A vtxo scheduled for a delegated round can still be offboarded.
#[tokio::test]
async fn offboard_refuses_vtxos_used_elsewhere() {
	let ctx = TestContext::new("server/offboard_refuses_vtxos_used_elsewhere").await;
	// Every fee rate is 1 sat/vB, so the request can use a fixed fee.
	let srv = ctx.captaind("server").no_vtxo_pool().funded(btc(1)).watchmand().cfg(|cfg| {
		cfg.fee_estimator.fallback_fee_rate_fast = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_slow = FeeRate::from_sat_per_vb_u32(1);
		// The cap on locked coins is tested elsewhere.
		cfg.offboard_max_locked_percent = 100;
		// No round starts unless the test triggers it.
		cfg.round_interval = Duration::from_secs(3600);
	}).create().await;
	// Each session locks a whole 1 btc coin, so give the server more than one.
	for _ in 0..7 {
		ctx.fund_captaind(&srv, btc(1)).await;
	}
	// Each vtxo has one job:
	// - vtxo_a, vtxo_b: in an offboard session. They are the only vtxos of `locker`,
	//   so any arkoor or round spend from `locker` has to use them.
	// - vtxo_c: shares vtxo_b with a second offboard session
	// - round_vtxo: scheduled for a delegated round
	// - exited_vtxo: its exit tx is confirmed onchain
	// - spent_vtxo: spent by an arkoor
	let locker = ctx.bark_sdk("locker", &srv)
		.boarded(sat(100_000))
		.boarded(sat(110_000))
		.create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(sat(120_000))
		.boarded(sat(130_000))
		.boarded(sat(140_000))
		.create().await;
	let spender = ctx.bark_sdk("spender", &srv).boarded(sat(150_000)).create().await;
	let mut rpc = srv.get_public_rpc().await;

	let find_vtxo = async |wallet: &bark::Wallet, amount| {
		let vtxo = wallet.spendable_vtxos().await.unwrap().into_iter()
			.find(|v| v.amount() == amount).unwrap();
		(vtxo.id(), wallet.get_vtxo_key(&vtxo).await.unwrap())
	};
	let (vtxo_a, key_a) = find_vtxo(&locker, sat(100_000)).await;
	let (vtxo_b, key_b) = find_vtxo(&locker, sat(110_000)).await;
	let (vtxo_c, key_c) = find_vtxo(&wallet, sat(120_000)).await;
	let (round_vtxo, round_key) = find_vtxo(&wallet, sat(130_000)).await;
	let (exited_vtxo, exited_key) = find_vtxo(&wallet, sat(140_000)).await;
	let (spent_vtxo, spent_key) = find_vtxo(&spender, sat(150_000)).await;

	let prepare = |net_amount: Amount, inputs: &[(VtxoId, &Keypair)]| {
		// Offboard the inputs to a fresh address, paying 1_000 sat in fees.
		let req = OffboardRequest {
			script_pubkey: ctx.bitcoind().get_new_address().script_pubkey(),
			net_amount,
			deduct_fees_from_gross_amount: true,
			fee_rate: FeeRate::from_sat_per_vb_u32(1),
		};
		let ids = inputs.iter().map(|(id, _)| *id).collect::<Vec<_>>();
		protos::PrepareOffboardRequest {
			offboard: Some((&req).into()),
			input_vtxo_ids: ids.iter().map(|id| id.to_bytes().to_vec()).collect(),
			attestation: inputs.iter()
				.map(|(_, key)| OffboardRequestAttestation::new(&req, &ids, key).serialize())
				.collect(),
		}
	};

	// vtxo_a + vtxo_b start a session.
	rpc.prepare_offboard(prepare(sat(209_000), &[(vtxo_a, &key_a), (vtxo_b, &key_b)])).await.unwrap();

	// vtxo_b + vtxo_c cannot start a new session, because vtxo_b is in the first one.
	let err = rpc.prepare_offboard(prepare(sat(229_000), &[(vtxo_b, &key_b), (vtxo_c, &key_c)])).await
		.unwrap_err();
	// The client may retry: the lock goes away when the first session ends.
	assert_eq!(err.code(), tonic::Code::Internal, "{err}");
	assert!(err.message().contains("already locked"), "{err}");
	// The refused request left vtxo_c free.
	rpc.prepare_offboard(prepare(sat(119_000), &[(vtxo_c, &key_c)])).await.unwrap();

	// The session's vtxos can't be spent by an arkoor
	let address = wallet.new_address().await.unwrap();
	let err = locker.send_arkoor_payment(&address, sat(50_000)).await.unwrap_err();
	assert!(format!("{err:#}").contains("already locked"), "{err:#}");

	// The session's vtxos can't join a round
	let err = locker.refresh_vtxos_delegated([vtxo_a]).await.err().expect("vtxo_a is in a session");
	assert!(format!("{err:#}").contains("in flight"), "{err:#}");

	// A spent vtxo can't be offboarded
	spender.send_arkoor_payment(&address, sat(50_000)).await.unwrap();
	let err = rpc.prepare_offboard(prepare(sat(149_000), &[(spent_vtxo, &spent_key)])).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
	assert!(err.message().contains("is not spendable"), "{err}");

	// A vtxo scheduled for a delegated round can still be offboarded.
	wallet.refresh_vtxos_delegated([round_vtxo]).await.unwrap();
	rpc.prepare_offboard(prepare(sat(129_000), &[(round_vtxo, &round_key)])).await.unwrap();

	// An exited vtxo can't be offboarded.
	let full = wallet.get_full_vtxo(exited_vtxo).await.unwrap();
	let exit_txs = full.transactions().map(|item| item.tx).collect::<Vec<_>>();
	let tip = ctx.mine(&exit_txs).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	let err = rpc.prepare_offboard(prepare(sat(139_000), &[(exited_vtxo, &exited_key)])).await.unwrap_err();
	assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
	assert!(err.message().contains("has exited onchain"), "{err}");
}
