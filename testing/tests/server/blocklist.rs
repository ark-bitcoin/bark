use std::collections::HashMap;

use bitcoin::{Address, Amount, Network, OutPoint};
use bitcoin::secp256k1::{Keypair, rand::thread_rng};
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::json::CreateRawTransactionInput;

use ark::{ProtocolEncoding, SECP};
use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::ToAltString;
use server_log::WalletReceivedBlockedAddress;
use server_rpc::protos;

/// Reject board registration when the funding tx spends from a blocked address.
#[tokio::test]
async fn blocklist_board_register_rejected() {
	let ctx = TestContext::new("server/blocklist_board_register_rejected").await;

	let blocked_addr = ctx.bitcoind().get_new_address();
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, format!("{}\n", blocked_addr)).await.unwrap();

	// Share the bitcoind so the server can look up txs via get_raw_transaction_info.
	let bitcoind = ctx.bitcoind_arc();
	let srv = ctx.captaind("server").bitcoind(bitcoind).cfg(|cfg| {
		cfg.bitcoin_address_blocklist = Some(blocklist_path);
	}).create().await;

	// Fund the blocked address and confirm it so we have a UTXO to spend.
	ctx.bitcoind().fund_addr(&blocked_addr, btc(1)).await;
	ctx.generate_blocks(1).await;

	let ark_info = srv.ark_info().await;
	let tip_height = ctx.bitcoind().get_block_count().await as u32;
	let expiry_height = tip_height + ark_info.vtxo_expiry_delta as u32;

	let user_key = Keypair::new(&SECP, &mut thread_rng());
	let board_fee = Amount::ZERO;
	let board_builder = ark::board::BoardBuilder::new(
		user_key.public_key(),
		expiry_height,
		ark_info.server_pubkey,
		ark_info.vtxo_exit_delta,
	);

	// Build a funding tx that spends from the blocked address to the board's funding script.
	let client = ctx.bitcoind().sync_client();
	let utxos = client.list_unspent(Some(1), None, Some(&[&blocked_addr]), None, None).unwrap();
	let utxo = utxos.into_iter().next()
		.expect("blocked address should have a confirmed UTXO");

	let funding_script = board_builder.funding_script_pubkey();
	let funding_address = Address::from_script(&funding_script, Network::Regtest).unwrap();
	let fee = Amount::from_sat(2_000);
	let board_amount = utxo.amount - fee;

	let inputs = vec![CreateRawTransactionInput {
		txid: utxo.txid,
		vout: utxo.vout,
		sequence: None,
	}];
	let mut outputs = HashMap::new();
	outputs.insert(funding_address.to_string(), board_amount);

	let raw_tx = client.create_raw_transaction(&inputs, &outputs, None, None).unwrap();
	let signed_tx = client.sign_raw_transaction_with_wallet(&raw_tx, None, None)
		.unwrap().transaction().unwrap();
	let funding_txid = client.send_raw_transaction(&signed_tx).unwrap();

	// Mine enough blocks to satisfy required_board_confirmations.
	let height = ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	srv.bitcoind().wait_for_blockheight(height).await;

	let funding_tx = ctx.bitcoind().await_transaction(funding_txid).await;
	let vout = funding_tx.output.iter().position(|o| o.script_pubkey == funding_script).unwrap();
	let board_utxo = OutPoint::new(funding_txid, vout as u32);

	// The cosign step has no blocklist check — it should succeed.
	let board_builder = board_builder
		.set_funding_details(board_amount, board_fee, board_utxo).unwrap()
		.generate_user_nonces();

	let mut rpc = srv.get_public_rpc().await;
	let cosign_response = rpc.request_board_cosign(protos::BoardCosignRequest {
		amount: board_amount.to_sat(),
		utxo: board_utxo.serialize(),
		expiry_height,
		user_pubkey: user_key.public_key().serialize().to_vec(),
		pub_nonce: board_builder.user_pub_nonce().serialize().to_vec(),
	}).await.unwrap().into_inner();

	let board_cosign: ark::board::BoardCosignResponse = cosign_response.try_into().unwrap();
	let vtxo = board_builder.build_vtxo(&board_cosign, &user_key).unwrap();

	// Registration must be rejected because the funding tx spends from a blocked address.
	let err = rpc.register_board_vtxo(protos::BoardVtxoRequest {
		board_vtxo: vtxo.serialize(),
	}).await.unwrap_err();

	assert_eq!(err.code(), tonic::Code::InvalidArgument, "err: {err}");
	assert!(err.message().contains("blocked"), "err: {err}");
}

/// Reject offboard requests targeting a blocked address.
#[tokio::test]
async fn blocklist_offboard_rejected() {
	let ctx = TestContext::new("server/blocklist_offboard_rejected").await;

	let blocked_addr = ctx.bitcoind().get_new_address();
	let blocklist_path = ctx.datadir.join("blocklist.txt");
	tokio::fs::write(&blocklist_path, format!("{}\n", blocked_addr)).await.unwrap();

	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.bitcoin_address_blocklist = Some(blocklist_path);
	}).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	let err = bark.try_offboard_all(&blocked_addr).await.unwrap_err().to_alt_string();
	assert!(err.contains("blocked"), "err: {err}");
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
