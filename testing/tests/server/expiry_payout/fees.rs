use std::time::Duration;

use bitcoin::FeeRate;
use bitcoin_ext::{BlockDelta, TxOutExt};
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};

use server::database::Db;

use ark_testing::{sat, TestContext};
use ark_testing::util::{poll_interval, FutureExt};

use super::{
	idle_board, assert_paid, current_share, fund_watchman, miner_fee, mine, mine_past,
	payout_attempts, payout_output, wait_decided, wait_for_confirmation, wait_payout,
};

/// When the feerate rises, the watchman replaces the payout with one that
/// pays the same owner output and records both signed transactions.
#[tokio::test]
async fn expiry_payout_fee_bump_keeps_the_owner_output() {
	let ctx = TestContext::new("server/expiry_payout_fee_bump_keeps_the_owner_output").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool().watchmand()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); }).create().await;
	let (vtxo, script, _) = idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	// Confirmed watchman inputs can pay the higher fee of the replacement.
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	fund_watchman(&ctx, &srv, sat(100_000)).await;
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let (allocation, first) = wait_payout(&db, vtxo.id()).await;
	let owner_output = payout_output(&first, &script, sat(98_000));
	let target = FeeRate::from_sat_per_vb(100).unwrap();
	assert!(miner_fee(&ctx, &first).await < target * first.weight());

	srv.watchmand().stop().await.unwrap();
	{
		let mut config = srv.watchmand().config_mut();
		config.fee_estimator.fallback_fee_rate_fast = target;
		config.fee_estimator.fallback_fee_rate_regular = target;
		config.fee_estimator.fallback_fee_rate_slow = target;
	}
	srv.watchmand().start().await.unwrap();
	let core = ctx.bitcoind().sync_client();
	let replacement = async {
		loop {
			let share = current_share(&db, vtxo.id()).await.unwrap();
			let tx = share.tx.unwrap();
			if tx != first && core.get_raw_mempool().unwrap().contains(&tx.compute_txid()) {
				break tx;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(30_000).await;
	assert!(!core.get_raw_mempool().unwrap().contains(&first.compute_txid()));
	assert_eq!(replacement.output[payout_output(&replacement, &script, sat(98_000)).vout as usize],
		first.output[owner_output.vout as usize]);
	let fee = miner_fee(&ctx, &replacement).await;
	assert!(fee >= target * replacement.weight());
	let attempts = payout_attempts(&db, allocation).await;
	assert_eq!(attempts.len(), 2, "both signed transactions are kept");
	assert_eq!(attempts[&replacement.compute_txid()], fee);

	assert_paid(&ctx, &srv, &replacement, &script, sat(98_000)).await;
	let tip = server::bitcoind::tip(&ctx.bitcoind().async_client()).await.unwrap();
	let block = core.custom_get_raw_transaction_info(replacement.compute_txid(), None).unwrap().unwrap()
		.blockhash.unwrap();
	wait_for_confirmation(&db, allocation, tip, block).await;
}

/// A feerate estimate above the configured ceiling stops the payout.
/// Raising the ceiling lets the same decision pay.
#[tokio::test]
async fn expiry_payout_above_the_feerate_ceiling_is_held() {
	let ctx = TestContext::new("server/expiry_payout_above_the_feerate_ceiling_is_held").await;
	let ceiling = FeeRate::from_sat_per_vb(5).unwrap();
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		// The regular feerate estimate of the test watchman is 7 sat/vB.
		.watchmand_cfg(move |cfg| cfg.watchman.expiry_payout_max_fee_rate = ceiling).create().await;
	let (vtxo, script, _) = idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let allocation = wait_decided(&db, vtxo.id()).await.allocation;
	// Several sweep passes run in this time, and none may sign a payout.
	tokio::time::sleep(Duration::from_secs(5)).await;
	assert!(payout_attempts(&db, allocation).await.is_empty(), "a payout above the ceiling was signed");

	srv.watchmand().stop().await.unwrap();
	srv.watchmand().config_mut().watchman.expiry_payout_max_fee_rate = FeeRate::from_sat_per_vb(1000).unwrap();
	srv.watchmand().start().await.unwrap();
	let (paid, payout) = wait_payout(&db, vtxo.id()).await;
	assert_eq!(paid, allocation);
	assert!(miner_fee(&ctx, &payout).await > ceiling * payout.weight());
	payout_output(&payout, &script, sat(98_000));
}

/// A decision that cannot be paid yet survives a watchman crash. A payout
/// whose fee needs a watchman input waits until that input is trusted.
#[tokio::test]
async fn expiry_payout_waits_for_a_trusted_fee_input() {
	let ctx = TestContext::new("server/expiry_payout_waits_for_a_trusted_fee_input").await;
	let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc()).no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand_cfg(|cfg| {
			cfg.min_trusted_confs = 2;
			cfg.watchman.sweep_interval = Duration::from_secs(1);
			cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb(30).unwrap();
		}).create().await;
	let (vtxo, script, _) = idle_board(&ctx, &srv, "owner", sat(100_000)).await;
	mine_past(&ctx, &srv, vtxo.expiry_height()).await;
	let db = Db::connect(&srv.config().postgres).await.unwrap();
	let decided = wait_decided(&db, vtxo.id()).await;
	assert_eq!(decided.status, "pending");
	assert!(!decided.published);

	srv.watchmand().crash_stop().await.unwrap();
	srv.watchmand().start().await.unwrap();
	let address = srv.watchmand().wait_wallet_address().await;
	let txid = ctx.bitcoind().fund_addr(&address, sat(100_000)).await;
	let deposit = ctx.bitcoind().await_transaction(txid).await;
	let fee_input = bitcoin::OutPoint::new(txid,
		deposit.output.iter().position(|out| out.script_pubkey == address.script_pubkey()).unwrap() as u32);
	mine(&ctx, &srv, 1).await;
	srv.watchmand().trigger_sweep().await;
	// One confirmation is not trusted, so no sweep pass may pay yet.
	tokio::time::sleep(Duration::from_secs(2)).await;
	assert_eq!(current_share(&db, vtxo.id()).await.unwrap(), decided);

	mine(&ctx, &srv, 1).await;
	let (allocation, payout) = wait_payout(&db, vtxo.id()).await;
	assert_eq!(allocation, decided.allocation);
	assert!(payout.input.iter().any(|input| input.previous_output == vtxo.chain_anchor()));
	assert!(payout.input.iter().any(|input| input.previous_output == fee_input));
	assert!(payout.output.iter().all(|out| !out.is_p2a_fee_anchor()));
	let fee = miner_fee(&ctx, &payout).await;
	assert!(fee > sat(2_000));
	assert_eq!(payout_attempts(&db, allocation).await.into_values().collect::<Vec<_>>(), vec![fee]);
	assert_paid(&ctx, &srv, &payout, &script, sat(98_000)).await;
	let share = current_share(&db, vtxo.id()).await.unwrap();
	assert_eq!((share.status.as_str(), share.fee, share.payout), ("confirmed", sat(2_000), sat(98_000)));
}
