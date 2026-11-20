use std::collections::HashMap;

use bitcoin::{Address, Amount};
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::json::CreateRawTransactionInput;

use ark_testing::{btc, sat, TestContext};
use ark_testing::daemon::captaind;
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::ToAltString;
use server_log::WalletReceivedBlockedAddress;
use server_rpc::protos;

/// Blocks the offboard destination once the offboard is prepared, so its
/// finish meets the updated blocklist.
#[derive(Clone)]
struct BlockAfterPrepare {
	blocklist_path: std::path::PathBuf,
	destination: Address,
	blocklist_rpc: captaind::BlocklistAdminClient,
}

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for BlockAfterPrepare {
	async fn prepare_offboard(
		&self, upstream: &mut captaind::ArkClient, req: protos::PrepareOffboardRequest,
	) -> Result<protos::PrepareOffboardResponse, tonic::Status> {
		let res = upstream.prepare_offboard(req).await?.into_inner();
		let mut list = tokio::fs::read_to_string(&self.blocklist_path).await.unwrap();
		list.push_str(&format!("{}\n", self.destination));
		tokio::fs::write(&self.blocklist_path, list).await.unwrap();
		self.blocklist_rpc.clone().reload_blocklist(protos::Empty {}).await?;
		Ok(res)
	}
}

/// Reject offboard requests targeting a blocked address, also when it was
/// blocked after the offboard was prepared.
#[tokio::test]
async fn blocklist_offboard_rejected() {
	let ctx = TestContext::new("server/blocklist_offboard_rejected").await;

	let blocked_addr = ctx.bitcoind().get_new_address();
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, format!("{}\n", blocked_addr)).await.unwrap();

	let cfg_path = blocklist_path.clone();
	let srv = ctx.captaind("server").cfg(move |cfg| {
		cfg.bitcoin_address_blocklist = Some(cfg_path);
	}).funded(btc(1)).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let err = bark.try_offboard_all(&blocked_addr).await.unwrap_err().to_alt_string();
	assert!(err.contains("blocked"), "err: {err}");

	let destination = ctx.bitcoind().get_new_address();
	let proxy = srv.start_proxy_no_mailbox(BlockAfterPrepare {
		blocklist_path,
		destination: destination.clone(),
		blocklist_rpc: srv.get_blocklist_rpc().await,
	}).await;
	bark.set_ark_url(&proxy.address).await;
	let err = bark.try_offboard_all(&destination).await.unwrap_err().to_alt_string();
	assert!(err.contains("blocked"), "err: {err}");
	assert!(!err.contains("could not complete yet"), "err: {err}");
}

/// Server wallet does not persistently accept funds sent from a blocked address.
///
/// BDK applies the incoming tx to the in-memory wallet during block processing,
/// but the server removes it from the changeset before persisting. After a
/// restart the wallet reloads from the clean persisted state, so the blocked
/// funds are never available.
///
/// Verified by attempting an offboard that would succeed if the blocked UTXO
/// were spendable but fails with only the small clean balance — both before and
/// after a server restart.
#[tokio::test]
async fn blocklist_server_wallet_ignores_blocked_funds() {
	let ctx = TestContext::new("server/blocklist_server_wallet_ignores_blocked_funds").await;

	let blocked_addr = ctx.bitcoind().get_new_address();
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, format!("{}\n", blocked_addr)).await.unwrap();

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.bitcoin_address_blocklist = Some(blocklist_path);
	}).create().await;

	// Set up a bark user with VTXOs so we can attempt offboards later.
	// The user boards 100_000 sats; the server will need to fund the offboard
	// tx from its rounds wallet, which will only have 20_000 sats of clean funds.
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.fund_captaind(&srv, sat(20_000)).await;
	bark.sync().await;

	// Fund the blocked address so we have a UTXO to spend from it.
	ctx.bitcoind().fund_addr(&blocked_addr, btc(1)).await;
	ctx.generate_blocks(1).await;

	// Build a raw transaction that spends from the blocked address to the
	// server's rounds wallet so we can control which input is used.
	let client = ctx.bitcoind().sync_client();
	let utxos = client.list_unspent(Some(1), None, Some(&[&blocked_addr]), None, None).unwrap();
	let utxo = utxos.into_iter().next()
		.expect("blocked address should have a confirmed UTXO");

	let server_addr = srv.get_rounds_funding_address().await;
	let fee = Amount::from_sat(2_000);
	let send_amount = utxo.amount - fee;
	let inputs = vec![CreateRawTransactionInput {
		txid: utxo.txid,
		vout: utxo.vout,
		sequence: None,
	}];
	let mut outputs = HashMap::new();
	outputs.insert(server_addr.to_string(), send_amount);

	let raw_tx = client.create_raw_transaction(&inputs, &outputs, None, None).unwrap();
	let signed_tx = client.sign_raw_transaction_with_wallet(&raw_tx, None, None)
		.unwrap().transaction().unwrap();
	let blocked_txid = client.send_raw_transaction(&signed_tx).unwrap();

	// Subscribe to the log BEFORE mining so we don't miss the event.
	let mut blocked_log_rx = srv.subscribe_log::<WalletReceivedBlockedAddress>();

	// Mine and wait for the server to process the block.
	let height = ctx.generate_blocks(2).await;
	srv.wait_for_sync_height(height).await;

	let log = blocked_log_rx.recv().await
		.expect("server should have emitted WalletReceivedBlockedAddress");
	assert_eq!(log.txid, blocked_txid);

	// Offboard attempt: the user's VTXO is 100_000 sats. The server has only
	// 20_000 sats of clean funds — not enough to fund the offboard tx. The
	// ~1 BTC blocked UTXO would cover it, but it is locked and must not be used.
	let dest = ctx.bitcoind().get_new_address();
	bark.try_offboard_all(&dest).await.unwrap_err();

	// Restart: the blocked tx was removed from the changeset before persisting,
	// so after reload the wallet has no record of those funds.
	srv.stop().await.unwrap();
	srv.start().await.unwrap();
	bark.sync().await;

	// Offboard still fails after restart — blocked funds were never persisted.
	bark.try_offboard_all(&dest).await.unwrap_err();

	// Only the blocked funds disappear after restart; the clean 20_000 sats persist.
	assert_eq!(srv.wallet_status().await.rounds.total_balance, sat(20_000));
}

/// The admin reload replaces the list from the file, removals included.
#[tokio::test]
async fn blocklist_admin_reload() {
	let ctx = TestContext::new("server/blocklist_admin_reload").await;

	let addr_a = ctx.bitcoind().get_new_address();
	let addr_b = ctx.bitcoind().get_new_address();
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, format!("{}\n", addr_a)).await.unwrap();

	let cfg_path = blocklist_path.clone();
	let wm_cfg_path = blocklist_path.clone();
	let srv = ctx.captaind("server").cfg(move |cfg| {
		cfg.bitcoin_address_blocklist = Some(cfg_path);
	}).watchmand_cfg(move |cfg| {
		cfg.bitcoin_address_blocklist = Some(wm_cfg_path);
	}).create().await;
	let mut rpc = srv.get_blocklist_rpc().await;
	let mut wm_rpc = srv.watchmand().get_blocklist_rpc().await;

	tokio::fs::write(&blocklist_path, format!("{}\n{}\n", addr_a, addr_b)).await.unwrap();
	let res = rpc.reload_blocklist(protos::Empty {}).await.unwrap().into_inner();
	assert_eq!((res.total, res.added, res.removed), (2, 1, 0));
	let res = wm_rpc.reload_blocklist(protos::Empty {}).await.unwrap().into_inner();
	assert_eq!((res.total, res.added, res.removed), (2, 1, 0));

	tokio::fs::write(&blocklist_path, format!("{}\n", addr_b)).await.unwrap();
	let res = rpc.reload_blocklist(protos::Empty {}).await.unwrap().into_inner();
	assert_eq!((res.total, res.added, res.removed), (1, 0, 1));

	tokio::fs::write(&blocklist_path, "").await.unwrap();
	let err = rpc.reload_blocklist(protos::Empty {}).await.unwrap_err();
	assert!(err.message().contains("no valid addresses"), "err: {err}");
}
