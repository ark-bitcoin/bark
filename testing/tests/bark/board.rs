use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};

use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Txid};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin_ext::P2TR_DUST_SAT;

use bark::onchain::{ChainSync, PreparePsbt, SignPsbt};
use bark_json::primitives::VtxoStateInfo;
use server_rpc::protos;

use ark_testing::{btc, require_bark_version, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::util::{action_drive_factor, ToAltString};

#[tokio::test]
async fn board_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_bark").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let board = bark1.board(sat(BOARD_AMOUNT)).await;

	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT), bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_twice_bark() {
	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_twice_bark").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	let board_a = bark1.board(sat(BOARD_AMOUNT)).await;
	let board_b = bark1.board(sat(BOARD_AMOUNT)).await;

	let vtxos = bark1.vtxos().await;
	assert_eq!(vtxos.len(), 2, "should have 2 board vtxos");
	assert!(vtxos.iter().any(|v| v.id == board_a.vtxos[0]));
	assert!(vtxos.iter().any(|v| v.id == board_b.vtxos[0]));
	assert!(vtxos.iter().all(|v| matches!(v.state, VtxoStateInfo::Locked { .. })));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT) * 2, bark1.spendable_balance().await);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn board_all_bark() {
	let ctx = TestContext::new("bark/board_all_bark").await;

	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).create().await;

	// Get the bark-address and fund it
	ctx.fund_bark(&bark1, sat(100_000)).await;
	assert_eq!(bark1.onchain_balance().await, sat(100_000));

	let board = bark1.board_all().await;
	let [vtxo] = bark1.vtxos().await.try_into().expect("should have board vtxo");
	assert_eq!(board.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Check that we emptied our onchain balance
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	// Check if the boarding tx's output value is the same as our off-chain balance
	let board_tx = ctx.bitcoind().await_transaction(board.funding_tx.txid).await;
	assert_eq!(
		bark1.spendable_balance().await,
		board_tx.output.last().unwrap().value,
	);
	assert_eq!(bark1.onchain_balance().await, Amount::ZERO);

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO, "balance should be reset to zero");
}

#[tokio::test]
async fn bark_rejects_boarding_subdust_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_subdust_amount").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;

	let board_amount = sat(P2TR_DUST_SAT - 1);
	let res = bark1.try_board(board_amount).await;

	// This is taken care by BDK
	assert!(res.unwrap_err().to_alt_string().contains(&format!("Output below the dust limit: 0")));
}

#[tokio::test]
async fn bark_rejects_boarding_below_minimum_board_amount() {
	let ctx = TestContext::new("bark/bark_rejects_boarding_below_minimum_board_amount").await;
	// Set up server with `min_board_amount` of 30 000 sats
	const MIN_BOARD_AMOUNT_SATS: u64 = 30_000;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.min_board_amount = sat(MIN_BOARD_AMOUNT_SATS);
	}).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;

	let board_amount = sat(MIN_BOARD_AMOUNT_SATS - 1);
	let res = bark1.try_board(board_amount).await;

	assert!(res.unwrap_err().to_alt_string().contains(&format!(
		"board amount of 0.00029999 BTC is less than minimum board amount required by server (0.00030000 BTC)",
	)));
}

#[tokio::test]
async fn bark_recover_unregistered_board() {
	let ctx = TestContext::new("bark/recover_unregistered_board").await;

	// Set up the server.
	// The server misbehaves and drops the first request to register_board_vtxo
	let srv = ctx.captaind("server").funded(btc(1)).create().await;

	/// This proxy drops the first `action_drive_factor()` requests to
	/// register_board (2 under the double-drive reentrancy mode, which runs
	/// each advance step twice, 1 otherwise), so the first maintenance cycle
	/// always leaves the board unregistered.
	#[derive(Clone)]
	struct Proxy(Arc<AtomicUsize>);

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn register_board_vtxo(
			&self, upstream: &mut ArkClient, req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			let dropped = self.0.fetch_update(
				atomic::Ordering::Relaxed, atomic::Ordering::Relaxed, |n| n.checked_sub(1),
			).is_ok();
			if dropped {
				Err(tonic::Status::from_error(
					"Nope! I do not register on the first attempt!".into(),
				))
			} else {
				Ok(upstream.register_board_vtxo(req).await?.into_inner())
			}
		}
	}

	let proxy = srv.start_proxy_no_mailbox(
		Proxy(Arc::new(AtomicUsize::new(action_drive_factor()))),
	).await;

	let bark = ctx.bark("bark", &proxy.address).funded(sat(1_000_00)).create().await;
	// Only asks server to cosign, not register a board.
	bark.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	// Triggers maintenance under the hood
	//
	// The board registration should have failed and the pending board balance should still be greater than 0.
	assert!(bark.pending_board_balance().await > Amount::ZERO);
	assert_eq!(bark.vtxos().await.len(), 1);

	ctx.generate_blocks(12).await;
	// The board registration will succeed during maintenance her and the pending board balance should be 0.
	assert_eq!(bark.pending_board_balance().await, Amount::ZERO);
}

#[tokio::test]
async fn board_tx_rejects_wrong_funding_address() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("bark/board_tx_rejects_wrong_funding_address").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let wallet = bark1.client().await;
	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (_, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();

	// Build a PSBT that pays to an arbitrary script instead of the board funding address
	let wrong_script = ScriptBuf::new_op_return(&[0u8; 20]);

	let board_amount = sat(90_000);
	// The input is not valid but it doesn't matter since validation fails before it's used.
	let fake_input = TxIn {
		previous_output: OutPoint::new(Txid::all_zeros(), 0),
		..Default::default()
	};
	let psbt = Psbt::from_unsigned_tx(Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![fake_input],
		output: vec![TxOut {
			script_pubkey: wrong_script,
			value: board_amount,
		}],
	}).unwrap();

	let err = wallet.board_tx(psbt, keypair, expiry_height).await.unwrap_err().to_alt_string();
	assert!(
		err.contains("does not pay to the expected board funding address"),
		"unexpected error: {err}",
	);
}

#[tokio::test]
async fn board_tx_rejects_wrong_expiry_height() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("bark/board_tx_rejects_wrong_expiry_height").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();

	let board_amount = sat(90_000);
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(board_addr, board_amount)], fee_rate).unwrap();
	let signed_psbt = onchain.finish_psbt(psbt).await.unwrap();

	let err = wallet
		.board_tx(signed_psbt, keypair, expiry_height + 1)
		.await
		.unwrap_err()
		.to_alt_string();
	assert!(
		err.contains("does not pay to the expected board funding address"),
		"unexpected error: {err}",
	);
}

#[tokio::test]
async fn board_tx_rejects_dust_amount() {
	require_bark_version!(> "0.1.4");

	let ctx = TestContext::new("bark/board_tx_rejects_dust_amount").await;
	let srv = ctx.captaind("server").cfg(|cfg| {
		cfg.min_board_amount = Amount::ZERO;
	}).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let wallet = bark1.client().await;
	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();

	// Build a PSBT that pays to the correct address but with a sub-dust amount
	let dust_amount = sat(P2TR_DUST_SAT - 1);
	// The input is not valid but it doesn't matter since validation fails before it's used.
	let fake_input = TxIn {
		previous_output: OutPoint::new(Txid::all_zeros(), 0),
		..Default::default()
	};
	let psbt = Psbt::from_unsigned_tx(Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: LockTime::ZERO,
		input: vec![fake_input],
		output: vec![TxOut {
			script_pubkey: board_addr.script_pubkey(),
			value: dust_amount,
		}],
	}).unwrap();

	let err = wallet.board_tx(psbt, keypair, expiry_height).await.unwrap_err().to_alt_string();
	assert!(
		err.contains("board amount must be at least"),
		"unexpected error: {err}",
	);
}

/// Tests the full boarding flow using [Wallet::board_tx] directl.
/// Uses an [OnchainWallet] to build and sign the funding PSBT.
/// This will be workflow will be replicated by external wallets
#[tokio::test]
async fn board_tx_full_flow() {
	// Boarding through the library `board_tx` persists a `Board` wallet-action
	// checkpoint. Pre-0.3.0 binaries don't know that checkpoint variant and abort
	// their sync when they read it, so this new-library-writes / old-cli-reads
	// flow only works from 0.3.0 on. The test still runs against the current build
	// in the normal (non-compat) job.
	require_bark_version!(>= "0.3.0");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_tx_full_flow").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;

	// Sync the onchain wallet so it sees the funded UTXOs
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();

	// Build and sign the funding PSBT using the onchain wallet
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let board_psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).unwrap();
	let signed_psbt = onchain.finish_psbt(board_psbt).await.unwrap();

	let board = wallet.board_tx(signed_psbt, keypair, expiry_height).await.unwrap();
	assert_eq!(board.vtxos.len(), 1, "board should produce one vtxo");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(bark1.spendable_balance().await, sat(BOARD_AMOUNT));
}
