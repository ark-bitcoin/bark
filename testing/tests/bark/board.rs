use std::sync::Arc;
use std::sync::atomic::{self, AtomicUsize};

use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, SignedAmount, Transaction, TxIn, TxOut, Txid};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin_ext::P2TR_DUST_SAT;

use bark::onchain::OnchainWalletTrait;
use bark_json::movements::MovementStatus;
use bark_json::primitives::VtxoStateInfo;
use bitcoin_ext::rpc::RpcApi;
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

/// A board whose funding tx input is spent by a confirmed conflicting tx can
/// never confirm: the board action must fail the board (vtxo dropped, movement
/// failed) instead of re-broadcasting and retrying forever.
#[tokio::test]
async fn board_fails_when_funding_tx_double_spent() {
	require_bark_version!(> "0.5.0");

	let ctx = TestContext::new("bark/board_fails_when_funding_tx_double_spent").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	// Build a conflicting tx spending the wallet's only utxo before boarding,
	// so it necessarily double-spends the board funding input. Sign via the
	// inner in-memory bdk wallet so the conflict is never persisted to the
	// wallet db, which would make the board below refuse the utxo.
	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let conflict_addr = ctx.bitcoind().get_new_address();
	let mut conflict_psbt = onchain.prepare_drain_tx(conflict_addr, fee_rate).await.unwrap();
	// Not onchain.finish_psbt(): that persists the signed tx to the wallet db.
	#[allow(deprecated)]
	let opts = bdk_wallet::SignOptions { trust_witness_utxo: true, ..Default::default() };
	assert!(onchain.inner.sign(&mut conflict_psbt, opts).unwrap(), "conflict psbt must finalize");
	let conflict_tx = conflict_psbt.extract_tx().unwrap();
	drop(onchain);

	let board = bark1.board(sat(90_000)).await;

	// Mine the conflicting tx directly into a block, bypassing mempool
	// policy, which evicts the funding tx. Then bury it deep enough for the
	// wallet to consider the conflict irreversible.
	let mining_addr = ctx.bitcoind().get_new_address();
	ctx.bitcoind().sync_client().call::<serde_json::Value>("generateblock", &[
		mining_addr.to_string().into(),
		serde_json::json!([bitcoin::consensus::encode::serialize_hex(&conflict_tx)]),
	]).expect("failed to mine the conflicting tx");
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Maintenance drives the board action, which should observe the
	// confirmed double-spend and tear the board down.
	bark1.maintain().await;

	assert_eq!(bark1.pending_board_balance().await, Amount::ZERO);
	assert_eq!(bark1.spendable_balance().await, Amount::ZERO);
	assert!(bark1.vtxos().await.is_empty(), "double-spent board vtxo should be gone");

	let history = bark1.history().await;
	let movement = history.iter()
		.find(|m| m.subsystem.name == "bark.board")
		.expect("board movement should exist");
	assert_eq!(movement.status, MovementStatus::Failed);
	assert_eq!(movement.output_vtxos, board.vtxos);
	// The failed board must not leave its vtxo amount counted towards the
	// wallet balance: the effective balance is reset to zero on teardown.
	assert_eq!(movement.effective_balance, SignedAmount::ZERO);

	// The action checkpoint is removed, so nothing is left to retry.
	assert!(wallet.pending_boards().await.unwrap().is_empty());

	// The onchain BDK wallet must not still hold the dead funding tx: once it
	// syncs and observes the confirmed conflict, the evicted funding tx is
	// canonicalized out of the wallet.
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();
	assert!(
		!onchain.list_transactions().iter().any(|tx| tx.compute_txid() == board.funding_tx.txid),
		"onchain wallet should have dropped the double-spent board funding tx",
	);
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
async fn board_psbt_rejects_wrong_funding_address() {
	let ctx = TestContext::new("bark/board_psbt_rejects_wrong_funding_address").await;
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

	let err = wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap_err().to_alt_string();
	assert!(
		err.contains("does not pay to the expected board funding address"),
		"unexpected error: {err}",
	);
}

#[tokio::test]
async fn board_psbt_rejects_wrong_expiry_height() {
	let ctx = TestContext::new("bark/board_psbt_rejects_wrong_expiry_height").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(100_000)).create().await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();

	let board_amount = sat(90_000);
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(board_addr, board_amount)], fee_rate).await.unwrap();
	let signed_psbt = onchain.finish_psbt(psbt).await.unwrap();

	let err = wallet
		.board_psbt(signed_psbt, keypair, expiry_height + 1)
		.await
		.unwrap_err()
		.to_alt_string();
	assert!(
		err.contains("does not pay to the expected board funding address"),
		"unexpected error: {err}",
	);
}

#[tokio::test]
async fn board_psbt_rejects_dust_amount() {
	let ctx = TestContext::new("bark/board_psbt_rejects_dust_amount").await;
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

	let err = wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap_err().to_alt_string();
	assert!(
		err.contains("board amount must be at least"),
		"unexpected error: {err}",
	);
}

/// Tests the full boarding flow using [Wallet::board_psbt] directl.
/// Uses an [OnchainWallet] to build and sign the funding PSBT.
/// This will be workflow will be replicated by external wallets
///
/// Version-gated because the checkpoint it writes carries `funding_psbt`, which a
/// bark predating that field cannot deserialise — and the compat suite drives this
/// wallet with the older binary afterwards.
#[tokio::test]
async fn board_psbt_full_flow() {
	require_bark_version!(> "0.6.1");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_psbt_full_flow").await;
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
	let board_psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).await.unwrap();
	let signed_psbt = onchain.finish_psbt(board_psbt).await.unwrap();

	let board = wallet.board_psbt(signed_psbt, keypair, expiry_height).await.unwrap();
	assert_eq!(board.vtxos.len(), 1, "board should produce one vtxo");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(bark1.spendable_balance().await, sat(BOARD_AMOUNT));
}

// Boarding from a funding transaction bark did not build and may not finalise.
//
// The boarding party publishes a board funding address and is handed a PSBT built
// by someone else, so the board output sits at an arbitrary index among outputs it
// did not choose and the missing signatures may belong to whoever broadcasts. A
// BIP-77 payjoin receiver is the motivating case; nothing below is specific to it.
//
// bark's own on-chain wallet supplies the inputs throughout, standing in for the
// other party's signer. That models holding an unfinalised proposal, but not a
// transaction carrying a foreign wallet's inputs: bark cannot contribute or sign an
// input of a proposal it is handed.

/// Move the output paying `script` to the end of the output list, as a
/// transaction built by another party may.
fn move_board_output_last(psbt: &mut Psbt, script: &ScriptBuf) {
	let idx = psbt
		.unsigned_tx
		.output
		.iter()
		.position(|o| &o.script_pubkey == script)
		.expect("psbt must pay to the board address");
	let out = psbt.unsigned_tx.output.remove(idx);
	psbt.unsigned_tx.output.push(out);
	let meta = psbt.outputs.remove(idx);
	psbt.outputs.push(meta);
}

fn in_mempool(ctx: &TestContext, txid: Txid) -> bool {
	ctx.bitcoind()
		.sync_client()
		.call::<Vec<String>>("getrawmempool", &[])
		.expect("getrawmempool")
		.iter()
		.any(|t| t == &txid.to_string())
}

/// The board output is found by script-pubkey, so it need not sit at vout 0.
#[tokio::test]
async fn board_psbt_output_at_any_index() {
	require_bark_version!(> "0.6.1");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_psbt_output_at_any_index").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(300_000)).create().await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();
	let board_script = board_addr.script_pubkey();

	// Two outputs, board last, so another output sits in front of the board.
	let other = ctx.bitcoind().get_new_address();
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let mut psbt = onchain
		.prepare_tx(&[(other, sat(20_000)), (board_addr, sat(BOARD_AMOUNT))], fee_rate)
		.await
		.unwrap();
	move_board_output_last(&mut psbt, &board_script);

	let board_vout = psbt
		.unsigned_tx
		.output
		.iter()
		.position(|o| o.script_pubkey == board_script)
		.unwrap();
	assert_ne!(board_vout, 0, "test is meaningless if the board output is at vout 0");

	let pending = wallet
		.board_psbt(psbt, keypair, expiry_height)
		.await
		.expect("board should cosign regardless of output index");

	let [vtxo] = bark1.vtxos().await.try_into().expect("should have one board vtxo");
	assert_eq!(pending.vtxos[0], vtxo.id);
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));
}

/// bark never puts a funding transaction it cannot complete on-chain, neither when
/// the board is created nor on any later drive: the `Confirming` double-spend probe
/// re-broadcasts, and has to be skipped without the signatures.
#[tokio::test]
async fn board_psbt_unfinalized_is_not_broadcast() {
	require_bark_version!(> "0.6.1");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_psbt_unfinalized_is_not_broadcast").await;
	let srv = ctx.captaind("server").create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(200_000)).create().await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();
	let fee_rate = wallet.chain().fee_rates().await.regular;
	// Deliberately not finished: this is the proposal as it is handed over.
	let psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).await.unwrap();
	let txid = psbt.unsigned_tx.compute_txid();

	wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap();
	assert!(!in_mempool(&ctx, txid), "cosigning must not broadcast");

	// The vtxo exists and is locked, so the board is durable even though nothing
	// is on-chain yet.
	let [vtxo] = bark1.vtxos().await.try_into().expect("should have one board vtxo");
	assert!(matches!(vtxo.state, VtxoStateInfo::Locked { .. }));

	// Drive the board repeatedly while the other party stays silent.
	for _ in 0..3 {
		ctx.generate_blocks(1).await;
		let _ = wallet.sync_pending_boards().await;
	}
	assert!(!in_mempool(&ctx, txid), "no drive may broadcast it either");
}

/// Once the other party broadcasts, the `Confirming` machinery takes over.
///
/// Two inputs, which is both the amount-obscuring shape and the case where the
/// conflict probe has more than one outpoint to check.
#[tokio::test]
async fn board_psbt_confirms_when_other_party_broadcasts() {
	require_bark_version!(> "0.6.2");

	const BOARD_AMOUNT: u64 = 120_000;
	let ctx = TestContext::new("bark/board_psbt_confirms_when_other_party_broadcasts").await;
	let srv = ctx.captaind("server").create().await;
	// Two funded utxos so the transaction genuinely needs two inputs.
	let bark1 = ctx.bark("bark1", &srv).create().await;
	ctx.fund_bark(&bark1, sat(70_000)).await;
	ctx.fund_bark(&bark1, sat(70_000)).await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).await.unwrap();
	assert!(
		psbt.unsigned_tx.input.len() >= 2,
		"expected the board to need both utxos, got {} input(s)",
		psbt.unsigned_tx.input.len(),
	);

	// The other party's finalised copy. Under segwit it has the same txid as the
	// unfinalised one bark cosigned against.
	let tx = onchain.finish_psbt(psbt.clone()).await.unwrap().extract_tx().unwrap();
	assert_eq!(tx.compute_txid(), psbt.unsigned_tx.compute_txid());

	wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap();

	// Nothing has moved on-chain, so the board does not count yet: the other party
	// holds the signatures and may never send it.
	assert_eq!(Amount::ZERO, bark1.pending_board_balance().await);

	// The other party broadcasts, not us.
	ctx.bitcoind().sync_client().send_raw_transaction(&tx).unwrap();
	ctx.await_transaction(tx.compute_txid()).await;

	// On the network now, so the board leaves `Broadcasting` and starts counting.
	bark1.maintain().await;
	assert_eq!(sat(BOARD_AMOUNT), bark1.pending_board_balance().await);

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	assert_eq!(sat(BOARD_AMOUNT), bark1.spendable_balance().await);
	assert_eq!(
		bark1.pending_board_balance().await,
		Amount::ZERO,
		"board should have registered once confirmed",
	);
}

/// A board whose funding input is spent by a confirmed transaction is torn down.
///
/// The unfinalised counterpart to `board_fails_when_funding_tx_double_spent`: bark
/// cannot probe by re-broadcasting without the signatures, so the `Confirming` pass
/// checks the inputs for a confirmed spend instead. Same verdict, other route.
#[tokio::test]
async fn board_psbt_unfinalized_fails_when_input_double_spent() {
	require_bark_version!(> "0.6.2");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_psbt_unfinalized_fails_when_input_double_spent").await;
	let srv = ctx.captaind("server").create().await;
	// A single utxo, so the conflicting tx below is forced to spend the same input.
	let bark1 = ctx.bark("bark1", &srv).create().await;
	ctx.fund_bark(&bark1, sat(200_000)).await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();

	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).await.unwrap();
	let board_txid = psbt.unsigned_tx.compute_txid();

	wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap();
	// Not counted as pending: the funding tx has not reached the chain. The vtxo is
	// what says the board exists.
	assert_eq!(Amount::ZERO, bark1.pending_board_balance().await);
	assert_eq!(1, bark1.vtxos().await.len(), "the board vtxo should exist");

	// The funding tx was never broadcast, so its input is still spendable: drain it
	// elsewhere and confirm that, which the board can now never outrace.
	let elsewhere = ctx.bitcoind().get_new_address();
	let conflict = onchain.prepare_drain_tx(elsewhere, fee_rate).await.unwrap();
	let conflict = onchain.finish_psbt(conflict).await.unwrap().extract_tx().unwrap();
	assert_ne!(conflict.compute_txid(), board_txid);
	ctx.bitcoind().sync_client().send_raw_transaction(&conflict).unwrap();
	ctx.generate_blocks(1).await;

	wallet.sync_pending_boards().await.unwrap();

	assert_eq!(
		Amount::ZERO,
		bark1.pending_board_balance().await,
		"a board whose input was spent by a confirmed tx must be torn down",
	);
	assert_eq!(Amount::ZERO, bark1.spendable_balance().await);
}

/// A board bark holds the signatures for dies when its input is already spent.
///
/// The finalised counterpart to the test above, and the mirror of
/// `board_fails_when_funding_tx_double_spent`, which lets the funding tx reach the
/// mempool first. Here the conflict confirms before bark ever pushes, so the push
/// can only fail: classifying before broadcasting is what turns that into a
/// teardown rather than an error retried forever.
#[tokio::test]
async fn board_fails_when_input_double_spent_before_broadcast() {
	require_bark_version!(> "0.6.2");

	const BOARD_AMOUNT: u64 = 90_000;
	let ctx = TestContext::new("bark/board_fails_when_input_double_spent_before_broadcast").await;
	let srv = ctx.captaind("server").create().await;
	// A single utxo, so the conflicting tx below is forced to spend the same input.
	let bark1 = ctx.bark("bark1", &srv).create().await;
	ctx.fund_bark(&bark1, sat(200_000)).await;

	let wallet = bark1.client().await;
	let mut onchain = bark1.onchain_wallet().await;
	onchain.sync(wallet.chain()).await.unwrap();
	let fee_rate = wallet.chain().fee_rates().await.regular;

	// Built before the board and signed in-memory: `finish_psbt` would persist it to
	// the wallet db, leaving the board below with nothing to spend.
	let elsewhere = ctx.bitcoind().get_new_address();
	let mut conflict = onchain.prepare_drain_tx(elsewhere, fee_rate).await.unwrap();
	#[allow(deprecated)]
	let opts = bdk_wallet::SignOptions { trust_witness_utxo: true, ..Default::default() };
	assert!(onchain.inner.sign(&mut conflict, opts).unwrap(), "conflict psbt must finalize");
	let conflict = conflict.extract_tx().unwrap();

	// Finalised, so the funding tx is bark's to broadcast.
	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let (board_addr, expiry_height) = wallet.board_funding_address(&keypair).await.unwrap();
	let psbt = onchain.prepare_tx(&[(board_addr, sat(BOARD_AMOUNT))], fee_rate).await.unwrap();
	let psbt = onchain.finish_psbt(psbt).await.unwrap();
	assert_ne!(psbt.unsigned_tx.compute_txid(), conflict.compute_txid());
	drop(onchain);

	// Confirm the conflict before the board is ever pushed.
	ctx.bitcoind().sync_client().send_raw_transaction(&conflict).unwrap();
	ctx.generate_blocks(1).await;

	wallet.board_psbt(psbt, keypair, expiry_height).await.unwrap();
	wallet.sync_pending_boards().await.unwrap();

	assert_eq!(
		Amount::ZERO,
		bark1.pending_board_balance().await,
		"a board that could never be broadcast must be torn down",
	);
	assert!(bark1.vtxos().await.is_empty(), "the board vtxo must be gone");

	let history = bark1.history().await;
	let movement = history.iter()
		.find(|m| m.subsystem.name == "bark.board")
		.expect("board movement should exist");
	assert_eq!(movement.status, MovementStatus::Failed);
}
