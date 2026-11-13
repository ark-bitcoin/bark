use std::time::Duration;

use bitcoin::{Amount, FeeRate, OutPoint};
use bitcoin_ext::{BlockDelta, BlockHeight, TxOutExt};
use bitcoin_ext::rpc::RpcApi;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::attestations::VtxoStatusAttestation;
use ark::fees::{BoardFees, PpmFeeRate};
use ark::lightning::PaymentHash;
use ark::vtxo::Full;
use bark::vtxo::{ExpiryPayoutState, VtxoState};
use server::database::Db;
use server_log::ExpiryHoldObserved;
use server_rpc::protos;

use ark_testing::{btc, sat, Captaind, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::payout_wallet::PayoutWallet;
use ark_testing::util::{poll_interval, FutureExt};

use super::{
	assert_paid, current_share, fund_watchman, htlc_send, input_allocations, miner_fee, mine,
	mine_past, mine_until_payout, operator_script, payout_attempts, payout_output, payout_shares,
	wait_decided, wait_payout,
};

/// The watchman pays an expired board to the payout script of its owner,
/// minus the fee. The board paid a board fee, and the payout needs a
/// watchman input for its mining fee. A wallet restored from the owner's
/// seed alone spends the payout.
#[tokio::test]
async fn expiry_payout_can_be_spent_from_the_seed() {
	let ctx = TestContext::new("server/expiry_payout_can_be_spent_from_the_seed").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| {
			cfg.expiry_payouts = true;
			cfg.vtxo_lifetime = BlockDelta::new(24);
			cfg.fees.board = BoardFees { min_fee: sat(330), base_fee: sat(0), ppm: PpmFeeRate::ZERO };
		})
		// At this feerate the payout fee needs a watchman input.
		.watchmand_cfg(|cfg| cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb(30).unwrap())
		.create().await;
	let mnemonic = bip39::Mnemonic::generate(12).unwrap();
	let wallet = ctx.bark_sdk("owner", &srv).mnemonic(mnemonic.clone()).funded(sat(200_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	// The payout key does not depend on the index of the VTXO key.
	for _ in 0..20 {
		wallet.new_address().await.unwrap();
	}
	let board = ctx.board(&wallet, &[sat(100_000)]).await.remove(0);
	assert_eq!(board.amount(), sat(100_000) - sat(330));
	let script = wallet.payout_script();
	drop(wallet);

	let fee_input = fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, board.vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (_, payout) = wait_payout(&db, board.id()).await;
	assert!(payout.input.iter().any(|input| input.previous_output == board.vtxo.chain_anchor()));
	assert!(payout.input.iter().any(|input| input.previous_output == fee_input));
	let amount = board.amount() - sat(2_000);
	let point = payout_output(&payout, &script, amount);
	let operator = operator_script(&srv);
	assert!(payout.output.iter().all(|output| output.script_pubkey == script || output.script_pubkey == operator));
	assert_paid(&ctx, &srv, &payout, &script, amount).await;

	let mut restored = PayoutWallet::restore(&mnemonic.to_seed(""), bitcoin::Network::Regtest).unwrap();
	assert_eq!(restored.script(), &script);
	restored.rescan(ctx.bitcoind()).unwrap();
	let destination = ctx.bitcoind().get_new_address();
	let spend = restored.spend(ctx.bitcoind(), point, &destination, FeeRate::from_sat_per_vb(2).unwrap()).unwrap();
	ctx.bitcoind().await_transaction(spend).await;
	ctx.generate_blocks(1).await;
	assert!(ctx.bitcoind().get_received_by_address(&destination) > sat(0));
	assert!(ctx.bitcoind().sync_client().get_tx_out(&point.txid, point.vout, Some(true)).unwrap().is_none());
}

/// Watchman inputs may pay the mining fee of a payout, never an owner. An
/// allocation whose owner outputs exceed its root is refused when the payout
/// is stored, even when the watchman could build it.
#[tokio::test]
async fn expiry_payout_never_pays_owners_more_than_the_root() {
	let ctx = TestContext::new("server/expiry_payout_never_pays_owners_more_than_the_root").await;
	// At this feerate the fee cannot come from the payout alone, so nothing
	// is paid until the watchman is funded.
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand_cfg(|cfg| cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb(30).unwrap())
		.create().await;
	let (vtxo, script, _) = super::idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	let root = ctx.bitcoind().await_transaction(vtxo.chain_anchor().txid).await
		.output[vtxo.chain_anchor().vout as usize].value;
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let decided = wait_decided(&db, vtxo.id()).await;
	assert!(payout_attempts(&db, decided.allocation).await.is_empty(), "an unfunded payout is not signed");

	// Make the stored owner amount exceed the root, then fund the watchman.
	let set_payout = async |payout: Amount| db.write(async |t| Ok(t.execute("
		UPDATE expiry_payout_vtxo SET payout_sat = $2, gross_sat = $2 + fee_sat
		WHERE expiry_payout_id = $1 AND disposition = 'owner'
	", &[&decided.allocation, &(payout.to_sat() as i64)]).await?)).await.unwrap();
	assert_eq!(set_payout(root + sat(1_000)).await, 1);
	fund_watchman(&ctx, &srv, sat(1_000_000)).await;
	for _ in 0..4 {
		mine(&ctx, &srv, 1).await;
		srv.watchmand().trigger_sweep().await;
		// Give the sweep time to run: it must not sign anything.
		tokio::time::sleep(Duration::from_millis(500)).await;
		assert!(payout_attempts(&db, decided.allocation).await.is_empty(), "a payout above its root was signed");
	}

	// With the decided amount back, the owner is paid.
	assert_eq!(set_payout(decided.payout).await, 1);
	srv.watchmand().trigger_sweep().await;
	let (_, payout) = wait_payout(&db, vtxo.id()).await;
	payout_output(&payout, &script, sat(98_000));
}

/// Two roots of one owner that expire at the same height, and the owner's
/// wallet. Both boards confirm in the same block.
async fn same_expiry_boards(ctx: &TestContext, srv: &Captaind) -> (Vec<Vtxo<Full>>, bark::Wallet) {
	let owner = ctx.bark("owner", srv).funded(sat(500_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	let boards = [owner.board(sat(100_000)).await, owner.board(sat(100_000)).await];
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	owner.sync().await;
	let wallet = owner.client().await;
	let mut vtxos = Vec::new();
	for board in &boards {
		vtxos.push(wallet.get_full_vtxo(board.vtxos[0]).await.unwrap());
	}
	assert_ne!(vtxos[0].chain_anchor(), vtxos[1].chain_anchor());
	assert_eq!(vtxos[0].expiry_height(), vtxos[1].expiry_height());
	(vtxos, wallet)
}

async fn payout_server(ctx: &TestContext) -> std::sync::Arc<Captaind> {
	ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(24);
	}).create().await
}

/// Two roots expire at the same height. One holds an HTLC-send VTXO whose
/// payment never started: it is held, and reported, until its HTLC deadline,
/// while the other root is paid. After the deadline the HTLC-send VTXO is
/// paid to its owner.
#[tokio::test]
async fn expiry_payout_ready_root_does_not_wait_for_a_held_root() {
	let ctx = TestContext::new("server/expiry_payout_ready_root_does_not_wait_for_a_held_root").await;
	let srv = payout_server(&ctx).await;
	let mut alarms = srv.watchmand().subscribe_log::<ExpiryHoldObserved>();
	let (mut vtxos, wallet) = same_expiry_boards(&ctx, &srv).await;
	let script = wallet.payout_script();
	let held_input = vtxos.pop().unwrap();
	let ready = vtxos.pop().unwrap();
	let held_root = held_input.chain_anchor();
	let (htlc, _) = htlc_send(&ctx, &srv, &wallet, held_input, PaymentHash::from([83; 32])).await;
	drop(wallet);
	let deadline = htlc.policy().as_server_htlc_send().unwrap().htlc_expiry;
	assert!(deadline > ready.expiry_height() + BlockDelta::new(7));
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, ready.expiry_height()).await;

	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (_, payout) = wait_payout(&db, ready.id()).await;
	assert_eq!(payout.input.iter().map(|input| input.previous_output).collect::<Vec<_>>(), [ready.chain_anchor()]);
	async {
		loop {
			let alarm = alarms.recv().await.unwrap();
			if alarm.vtxo_id == htlc.id() {
				assert_eq!(alarm.reason, "lightning settlement pending");
				break;
			}
		}
	}.wait_millis(30_000).await;
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	async {
		while current_share(&db, ready.id()).await.unwrap().status != "confirmed" {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(payout_shares(&db, htlc.id()).await.is_empty(), "the held VTXO is decided before its deadline");
	assert!(ctx.bitcoind().sync_client().get_tx_out(&held_root.txid, held_root.vout, Some(true))
		.unwrap().is_some(), "the held root is unspent");

	mine_past(&ctx, &srv, deadline).await;
	let (_, payout) = wait_payout(&db, htlc.id()).await;
	payout_output(&payout, &script, sat(98_000));
	let state = db.read(async |t| server::database::htlc_vtxo::get_htlc_vtxo(t, htlc.id()).await)
		.await.unwrap().unwrap();
	assert_eq!(state.htlc.resolution(), None, "an expiry payout does not settle the HTLC");
}

/// Two boards of one owner that expire at the same height are two
/// allocations and two payouts, each charging its own fee.
#[tokio::test]
async fn expiry_payout_fee_is_charged_once_per_root() {
	let ctx = TestContext::new("server/expiry_payout_fee_is_charged_once_per_root").await;
	let srv = payout_server(&ctx).await;
	let (vtxos, wallet) = same_expiry_boards(&ctx, &srv).await;
	let script = wallet.payout_script();
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, vtxos[0].expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let mut allocations = Vec::new();
	for (vtxo, other) in [(&vtxos[0], &vtxos[1]), (&vtxos[1], &vtxos[0])] {
		let (allocation, payout) = wait_payout(&db, vtxo.id()).await;
		assert!(payout.input.iter().any(|input| input.previous_output == vtxo.chain_anchor()));
		assert!(payout.input.iter().all(|input| input.previous_output != other.chain_anchor()));
		payout_output(&payout, &script, vtxo.amount() - sat(2_000));
		allocations.push(allocation);
	}
	assert_ne!(allocations[0], allocations[1]);
}

/// An error while deciding one root holds only that root. The root after it
/// at the same height is still decided and paid.
#[tokio::test]
async fn expiry_payout_error_on_one_root_does_not_stop_the_pass() {
	let ctx = TestContext::new("server/expiry_payout_error_on_one_root_does_not_stop_the_pass").await;
	let srv = payout_server(&ctx).await;
	let (mut vtxos, wallet) = same_expiry_boards(&ctx, &srv).await;
	let script = wallet.payout_script();
	// The pass visits same-height roots in id order. Break the first one:
	// storing its decision fails on every pass. If that error stopped the
	// pass, the other root would never be decided.
	vtxos.sort_by_key(|vtxo| VtxoId::from(vtxo.chain_anchor()));
	let (broken, ready) = (&vtxos[0], &vtxos[1]);
	let broken_root = VtxoId::from(broken.chain_anchor());
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	db.write(async |t| Ok(t.batch_execute(&format!("
		CREATE SEQUENCE test_refused_decisions;
		CREATE FUNCTION test_refuse_decision() RETURNS trigger AS $$
		BEGIN
			IF NEW.vtxo_id = '{broken_root}' THEN
				PERFORM nextval('test_refused_decisions');
				RAISE EXCEPTION 'decision refused';
			END IF;
			RETURN NEW;
		END; $$ LANGUAGE plpgsql;
		CREATE TRIGGER test_refuse_decision BEFORE INSERT ON expiry_payout_input
			FOR EACH ROW EXECUTE FUNCTION test_refuse_decision();
	")).await?)).await.unwrap();
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, ready.expiry_height()).await;

	let (_, payout) = wait_payout(&db, ready.id()).await;
	// Every pass tries the broken root again, until its decision is refused.
	async {
		while !db.read(async |t| Ok(t.query_one("SELECT is_called FROM test_refused_decisions", &[]).await?
			.get::<_, bool>(0))).await.unwrap() {
			srv.watchmand().trigger_sweep().await;
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(payout.input.iter().all(|input| input.previous_output != broken.chain_anchor()));
	payout_output(&payout, &script, ready.amount() - sat(2_000));
	assert!(input_allocations(&db, broken_root).await.is_empty());
}

/// One root holds arkoor outputs of four recipients and the change of their
/// sender. The fee takes a 1,500-sat VTXO whole, and leaves 329, 330 and 331
/// sats of the others. A remainder below the 330-sat dust limit cannot be
/// paid, so its owner forfeits it. The sender's change is paid in one output
/// and charged one fee. Every wallet then reports its VTXOs paid or
/// forfeited, with no new movement.
#[tokio::test]
async fn expiry_payout_fee_boundaries_and_one_fee_per_owner() {
	let ctx = TestContext::new("server/expiry_payout_fee_boundaries_and_one_fee_per_owner").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand().cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(40);
		cfg.vtxo_exit_delta = BlockDelta::new(2);
	}).create().await;
	let sender = ctx.bark_sdk("sender", &srv).boarded(sat(100_000))
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	sender.stop_daemon_wait().await.unwrap();
	let amounts = [1_500, 2_329, 2_330, 2_331].map(sat);
	let mut recipients = Vec::new();
	for (index, amount) in amounts.iter().enumerate() {
		let recipient = ctx.bark_sdk(format!("recipient{index}"), &srv)
			.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
		recipient.stop_daemon_wait().await.unwrap();
		sender.send_arkoor_payment(&recipient.new_address().await.unwrap(), *amount).await.unwrap();
		recipient.sync_mailbox().await.unwrap();
		let mut leaf = super::full_vtxos(&recipient).await;
		assert_eq!(leaf.len(), 1);
		recipients.push((recipient, leaf.remove(0)));
	}
	let change = super::full_vtxos(&sender).await;
	let change_total = change.iter().map(|vtxo| vtxo.amount()).sum::<Amount>();
	assert_eq!(change_total + amounts.iter().copied().sum::<Amount>(), sat(100_000));
	let mut history = Vec::new();
	for wallet in std::iter::once(&sender).chain(recipients.iter().map(|(wallet, _)| wallet)) {
		history.push(wallet.history().await.unwrap());
	}

	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, change[0].expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let payout = mine_until_payout(&ctx, &srv, &db, change[0].id()).await;
	for vtxo in change.iter().chain(recipients.iter().map(|(_, vtxo)| vtxo)) {
		let share = current_share(&db, vtxo.id()).await.expect("every VTXO of the root is decided");
		assert_eq!(share.tx.as_ref(), Some(&payout), "one payout pays the whole root");
	}
	let dust = sat(330);
	// The VTXOs that leave nothing or 329 sats have no output.
	let expected = [None, None, Some(dust), Some(dust + sat(1))];
	for ((wallet, vtxo), expected) in recipients.iter().zip(expected) {
		let script = wallet.payout_script();
		match expected {
			Some(amount) => { payout_output(&payout, &script, amount); },
			None => assert!(payout.output.iter().all(|output| output.script_pubkey != script)),
		}
		let share = current_share(&db, vtxo.id()).await.unwrap();
		let fee = if expected.is_some() { sat(2_000) } else { vtxo.amount() };
		assert_eq!(share.fee, fee);
	}
	payout_output(&payout, &sender.payout_script(), change_total - sat(2_000));
	let mut change_fee = Amount::ZERO;
	for vtxo in &change {
		change_fee += current_share(&db, vtxo.id()).await.unwrap().fee;
	}
	assert_eq!(change_fee, sat(2_000), "one fee for all VTXOs of one owner in one root");
	let operator = operator_script(&srv);
	let remainder = payout.output.iter().filter(|output| output.script_pubkey == operator)
		.map(|output| output.value).sum::<Amount>();
	assert_eq!(remainder + miner_fee(&ctx, &payout).await, sat(1_500 + 2_329 + 2 * 2_000 + 2_000));
	mine(&ctx, &srv, 6).await;
	async {
		while current_share(&db, change[0].id()).await.unwrap().status != "confirmed" {
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;

	let (forfeited, leaf) = &recipients[0];
	let key = forfeited.get_vtxo_key(leaf).await.unwrap();
	let status = srv.get_public_rpc().await.get_vtxo_status(protos::GetVtxoStatusRequest {
		vtxo_id: leaf.id().to_bytes().to_vec(),
		attestation: VtxoStatusAttestation::new(leaf.id(), &key).serialize(),
	}).await.unwrap().into_inner();
	assert_eq!(status.expiry_payout, Some(protos::ExpiryPayout {
		state: protos::ExpiryPayoutState::Forfeited as i32, gross_sat: 1_500, fee_sat: 1_500, payout_sat: 0,
	}));
	let leaves = std::iter::once((&sender, change.clone()))
		.chain(recipients.iter().map(|(wallet, vtxo)| (wallet, vec![vtxo.clone()])));
	for ((wallet, vtxos), history) in leaves.zip(history) {
		wallet.sync_expiry_payouts().await.unwrap();
		for vtxo in vtxos {
			let state = wallet.get_vtxo_by_id(vtxo.id()).await.unwrap();
			let expected = if vtxo.amount() < sat(2_000) + dust { ExpiryPayoutState::Forfeited } else { ExpiryPayoutState::Paid };
			assert_eq!((state.state, state.expiry_payout_state), (VtxoState::Spent, Some(expected)));
		}
		assert_eq!(wallet.balance().await.unwrap().total(), Amount::ZERO);
		assert_eq!(wallet.history().await.unwrap(), history, "a payout is not an Ark movement");
	}
	let payout = forfeited.expiry_payout(leaf.id()).await.unwrap().unwrap();
	assert_eq!((payout.status, payout.gross, payout.fee, payout.payout),
		(ExpiryPayoutState::Forfeited, sat(1_500), sat(1_500), Amount::ZERO));
}

/// Two owners in one round root are each paid once, in one payout.
#[tokio::test]
async fn expiry_payout_pays_each_owner_of_a_round_root() {
	let ctx = TestContext::new("server/expiry_payout_pays_each_owner_of_a_round_root").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(48);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	let alice = ctx.bark("alice", &srv).funded(sat(300_000)).create().await;
	let bob = ctx.bark("bob", &srv).funded(sat(300_000)).create().await;
	alice.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	bob.board_and_confirm_and_register(&ctx, sat(200_000)).await;
	ctx.refresh_all(&srv, &[&alice, &bob]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let mut owners = Vec::new();
	for bark in [&alice, &bob] {
		bark.sync().await;
		let client = bark.client().await;
		let vtxos = client.vtxos().await.unwrap();
		assert_eq!(vtxos.len(), 1);
		owners.push((client.get_full_vtxo(vtxos[0].id()).await.unwrap(), client.payout_script()));
	}
	assert_eq!(owners[0].0.chain_anchor(), owners[1].0.chain_anchor());
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, owners[0].0.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, payout) = wait_payout(&db, owners[0].0.id()).await;
	assert_eq!(wait_payout(&db, owners[1].0.id()).await.0, allocation);
	assert_eq!(payout.input.iter().filter(|input| input.previous_output == owners[0].0.chain_anchor()).count(), 1);
	let operator = operator_script(&srv);
	assert!(payout.output.iter().all(|out| owners.iter().any(|(_, script)| *script == out.script_pubkey)
		|| out.script_pubkey == operator));
	payout_output(&payout, &owners[0].1, sat(198_000));
	assert_paid(&ctx, &srv, &payout, &owners[1].1, sat(198_000)).await;
}

/// An offboard connector is swept to the operator after its own expiry,
/// with a watchman input, since it is too small to pay its own fee.
#[tokio::test]
async fn expiry_payout_sweeps_offboard_connectors() {
	let ctx = TestContext::new("server/expiry_payout_sweeps_offboard_connectors").await;
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.expiry_payouts = true;
		cfg.vtxo_lifetime = BlockDelta::new(24);
		cfg.vtxopool.vtxo_targets = vec![];
	}).watchmand_cfg(|cfg| {
		cfg.watchman.reaction_interval = Duration::from_secs(15 * 60);
		cfg.watchman.sweep_interval = Duration::from_secs(15 * 60);
	}).create().await;
	fund_watchman(&ctx, &srv, sat(20_000)).await;
	let wallet = ctx.bark_sdk("bark", &srv).boarded(sat(100_000)).boarded(sat(100_000)).create().await;
	let offboard = wallet.offboard_all(ctx.bitcoind().get_new_address()).await.unwrap().txid;
	ctx.generate_blocks(1).await;
	let connector = OutPoint::new(offboard, 1);
	assert_eq!(ctx.bitcoind().await_transaction(offboard).await.output[1].value, sat(660));
	let connector_id = VtxoId::from(connector);
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let expiry = db.read(async |t| t.get_bare_vtxo_by_id(connector_id).await).await.unwrap()
		.vtxo.expiry_height();

	mine_past(&ctx, &srv, BlockHeight::new(expiry.to_u32() - 2)).await;
	srv.watchmand().trigger_sweep().await;
	assert!(input_allocations(&db, connector_id).await.is_empty(), "the connector waits for its own expiry");

	mine(&ctx, &srv, 2).await;
	srv.watchmand().trigger_sweep().await;
	let (allocation, payout) = async {
		loop {
			if let Some(allocation) = input_allocations(&db, connector_id).await.pop() {
				let share = current_share(&db, connector_id).await.unwrap();
				if share.published {
					assert_eq!(share.allocation, allocation);
					break (allocation, share.tx.unwrap());
				}
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(payout.input.iter().any(|input| input.previous_output == connector));
	assert!(payout.input.len() >= 2, "the connector needs a watchman input");
	assert_eq!(payout.output.len(), 1);
	assert_eq!(payout.output[0].script_pubkey, operator_script(&srv));
	assert!(!payout.output[0].is_p2a_fee_anchor());
	let share = current_share(&db, connector_id).await.unwrap();
	assert_eq!((share.owner, share.gross, share.payout), (None, sat(660), Amount::ZERO));
	assert_eq!(payout_attempts(&db, allocation).await[&payout.compute_txid()], miner_fee(&ctx, &payout).await);
	mine(&ctx, &srv, 6).await;
	assert!(ctx.bitcoind().sync_client().get_tx_out(&connector.txid, connector.vout, Some(true)).unwrap().is_none());
}
