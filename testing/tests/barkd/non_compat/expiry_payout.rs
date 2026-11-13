use bitcoin::{Amount, Network};
use bitcoin_ext::BlockDelta;
use bitcoin_ext::rpc::{BitcoinRpcExt, RpcApi};

use bark_json::primitives::{ExpiryPayoutStateInfo, VtxoStateInfo};

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::barkd::Barkd;
use ark_testing::util::{poll_interval, FutureExt};

async fn mailbox(barkd: &Barkd) -> bitcoin::secp256k1::PublicKey {
	let config = barkd.client_config();
	let info: bark_json::cli::DebugInfo = config.client
		.get(format!("{}/api/v1/wallet/debug-info", config.base_path)).send().await.unwrap()
		.error_for_status().unwrap().json().await.unwrap();
	assert_eq!(info.network, Network::Regtest);
	info.mailbox_id
}

/// A barkd that was stopped while its board expired and was paid out
/// reports the VTXO as paid when it comes back, with no new movement. A
/// barkd restored from the same seed reports the same.
#[tokio::test]
async fn expiry_payout_is_reported_after_restart_and_restore() {
	let ctx = TestContext::new("barkd/expiry_payout_is_reported_after_restart_and_restore").await;
	let srv = ctx.captaind("server").no_vtxo_pool()
		.cfg(|cfg| { cfg.expiry_payouts = true; cfg.vtxo_lifetime = BlockDelta::new(24); })
		.watchmand().create().await;
	let mnemonic = bip39::Mnemonic::from_entropy(&[43; 32]).unwrap().to_string();
	let barkd = ctx.barkd("wallet", &srv).mnemonic(mnemonic.clone())
		.cfg(|cfg| cfg.daemon_manual_sync = true).funded(sat(200_000)).create().await;
	let script = ark::expiry_payout::payout_script(mailbox(&barkd).await);
	barkd.onchain_sync().await;
	let board = barkd.board_amount(sat(100_000)).await;
	ctx.await_transaction(board.funding_tx.txid).await;
	let tip = ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	srv.wait_for_sync_height(tip).await;
	barkd.sync().await;
	let vtxo = barkd.vtxos(None).await.remove(0).vtxo;
	let id = vtxo.id.to_string();
	let amount = vtxo.amount - sat(2_000);

	barkd.stop().await.unwrap();
	ctx.bitcoind().fund_addr(srv.watchmand().wait_wallet_address().await, sat(100_000)).await;
	ctx.generate_blocks(2).await;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	let expired = ctx.generate_blocks(vtxo.expiry_height.to_u32() + 1 - tip).await;
	srv.wait_for_sync_height(expired).await;
	srv.watchmand().wait_for_sync_height(expired).await;
	let core = ctx.bitcoind().sync_client();
	let payout = async {
		loop {
			let paying = core.get_raw_mempool().unwrap().into_iter()
				.filter_map(|txid| core.get_raw_transaction(&txid, None).ok())
				.find(|tx| tx.output.iter().any(|output| output.script_pubkey == script && output.value == amount));
			if let Some(tx) = paying {
				break tx;
			}
			tokio::time::sleep(poll_interval()).await;
		}
	}.wait_millis(60_000).await;
	let tip = ctx.generate_blocks(6).await;
	srv.wait_for_sync_height(tip).await;
	srv.watchmand().wait_for_sync_height(tip).await;
	assert!(core.custom_get_raw_transaction_info(payout.compute_txid(), None).unwrap().unwrap()
		.confirmations.unwrap() >= 6);

	barkd.start().await.unwrap();
	let history = barkd.history(None, None).await;
	barkd.sync().await;
	let paid = barkd.get_vtxo(&id).await;
	assert_eq!((paid.state, paid.expiry_payout), (VtxoStateInfo::Spent, Some(ExpiryPayoutStateInfo::Paid)));
	assert_eq!(barkd.history(None, None).await, history, "a payout is not an Ark movement");
	assert_eq!(barkd.bark_balance().await.spendable, Amount::ZERO);
	barkd.stop().await.unwrap();

	let restored = ctx.barkd("restored", &srv).mnemonic(mnemonic)
		.cfg(|cfg| cfg.daemon_manual_sync = true).create().await;
	restored.sync().await;
	assert_eq!(ark::expiry_payout::payout_script(mailbox(&restored).await), script);
	let vtxo = restored.vtxos(Some(true)).await.into_iter().find(|v| v.vtxo.id.to_string() == id)
		.expect("the restored wallet knows the paid VTXO");
	assert_eq!((vtxo.state, vtxo.expiry_payout), (VtxoStateInfo::Spent, Some(ExpiryPayoutStateInfo::Paid)));
}
