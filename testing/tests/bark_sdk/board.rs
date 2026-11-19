//! Tests for the board flow through the SDK.

use std::any::Any;

use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, SignedAmount, Transaction, TxIn, TxOut, Txid};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin_ext::{BlockDelta, P2TR_DUST_SAT};
use bitcoin_ext::rpc::RpcApi;

use bark::{BoardFundingAddress, Wallet};
use bark::movement::MovementStatus;
use bark::onchain::OnchainWallet;
use bark::subsystem::Subsystem;
use bark::vtxo::VtxoState;

use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

const MIN_BOARD_AMOUNT: Amount = Amount::from_sat(20_000);

/// A board that fails before its checkpoint exists must leave the onchain
/// wallet untouched: the funding proposal is signed before the server is
/// asked to cosign, and a proposal the server never cosigned must not spend
/// any coins, not even after a sync (which rebroadcasts the wallet's
/// unconfirmed transactions).
///
/// The board is made to fail by boarding half the server's minimum amount.
#[tokio::test]
async fn failed_board_leaves_the_onchain_wallet_untouched() {
	let ctx = TestContext::new("bark_sdk/failed_board_leaves_the_onchain_wallet_untouched").await;
	let srv = ctx.captaind("server")
		.cfg(|cfg| cfg.min_board_amount = MIN_BOARD_AMOUNT)
		.create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(MIN_BOARD_AMOUNT)
		.create().await;

	let err = wallet.board_amount(MIN_BOARD_AMOUNT / 2).await
		.expect_err("boarding below the minimum must be refused");
	assert!(format!("{:#}", err).contains("less than minimum board amount"),
		"unexpected board error: {err:#}",
	);

	// The failed board left a signed funding proposal behind; syncing must
	// neither count it as a spend nor hand it to the network.
	wallet.sync_onchain().await.expect("onchain sync");

	let balance = wallet.onchain().expect("onchain wallet").read().await.balance().await;
	assert_eq!(balance, MIN_BOARD_AMOUNT, "no onchain coins may move on a failed board");
	assert!(ctx.bitcoind().sync_client().get_raw_mempool().expect("mempool").is_empty(),
		"a failed board must not broadcast its funding tx",
	);
	assert!(wallet.pending_boards().await.expect("pending boards").is_empty(),
		"a failed board must not linger as pending",
	);

	// The coins are still the wallet's to spend: with enough funds on top,
	// the same wallet boards fine.
	let address = {
		let onchain = wallet.onchain().expect("onchain wallet");
		let mut guard = onchain.write().await;
		guard.address().await.expect("onchain address")
	};
	ctx.bitcoind().fund_addr(address, sat(80_000)).await;
	ctx.generate_blocks(1).await;
	wallet.sync_onchain().await.expect("onchain sync");

	let board = wallet.board_all().await.expect("board with funds above the minimum");
	ctx.await_transaction(board.funding_tx.compute_txid()).await;
	wallet.sync_onchain().await.expect("onchain sync");
	let balance = wallet.onchain().expect("onchain wallet").read().await.balance().await;
	assert_eq!(balance, Amount::ZERO, "the successful board drains the onchain wallet");
}

/// Builds a finalised PSBT paying `funding` from the wallet's own on-chain
/// wallet, standing in for another party such as a payjoin sender.
async fn funding_psbt(wallet: &Wallet, funding: &BoardFundingAddress, amount: Amount) -> Psbt {
	let onchain = wallet.onchain().expect("onchain wallet");
	let mut onchain = onchain.write().await;
	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = onchain.prepare_tx(&[(funding.address().clone(), amount)], fee_rate).await.unwrap();
	onchain.finish_psbt(psbt).await.unwrap()
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

/// A funding address handed out before `BoardFundingAddress` existed can still be
/// boarded from the keypair and expiry height stored alongside it.
#[tokio::test]
#[allow(deprecated)]
async fn board_psbt_legacy_funding_address() {
	let ctx = TestContext::new("bark_sdk/board_psbt_legacy_funding_address").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(100_000))
		.create().await;

	// What a caller of the removed `board_funding_address` stored.
	let (keypair, _) = wallet.derive_store_next_keypair().await.unwrap();
	let expiry_height = wallet.chain().tip().await.unwrap() + BlockDelta::new(100);

	let funding = wallet.legacy_board_funding_address(keypair.public_key(), expiry_height)
		.await.unwrap();
	assert_eq!(funding.expiry_height(), expiry_height);

	let psbt = funding_psbt(&wallet, &funding, sat(90_000)).await;
	wallet.board_psbt(psbt, &funding).await.expect("board a legacy funding address");

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(90_000));
}

/// The board API end to end: a board from the on-chain wallet with a chosen
/// expiry, and one funded by another wallet through a persisted
/// [BoardFundingAddress].
#[tokio::test]
async fn board_with_expiry_and_external_funding() {
	let ctx = TestContext::new("bark_sdk/board_with_expiry_and_external_funding").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(500_000))
		.create().await;

	// Board from the on-chain wallet, expiring 100 blocks from now.
	let expiry_height = wallet.chain().tip().await.unwrap() + BlockDelta::new(100);
	let board = wallet.board()
		.expiry(expiry_height)
		.amount(sat(100_000))
		.build().await
		.expect("board with an expiry");
	let vtxo = wallet.get_vtxo_by_id(board.vtxos[0]).await.unwrap();
	assert_eq!(vtxo.expiry_height(), expiry_height);

	// The board becomes spendable once confirmed and registered.
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(100_000));

	// Board from another wallet, e.g. as a payjoin receiver. The funding address
	// is persisted while waiting for the other party's PSBT.
	let funding = wallet.board().funding_address().await.expect("funding address");
	let stored = serde_json::to_string(&funding).unwrap();
	let funding = serde_json::from_str::<BoardFundingAddress>(&stored).unwrap();

	// Spends the confirmed change of the board above: the server refuses funding
	// inputs it can't find on-chain.
	wallet.sync_onchain().await.unwrap();
	let psbt = funding_psbt(&wallet, &funding, sat(150_000)).await;
	let external = wallet.board_psbt(psbt, &funding).await.expect("board an external PSBT");
	let vtxo = wallet.get_vtxo_by_id(external.vtxos[0]).await.unwrap();
	assert_eq!(vtxo.expiry_height(), funding.expiry_height());

	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wallet.sync_pending_boards().await.unwrap();
	assert_eq!(wallet.balance().await.unwrap().spendable, sat(250_000));
}

/// A funding address too close to its expiry to confirm and register in time is
/// refused, rather than cosigning a board the server could sweep.
#[tokio::test]
async fn board_psbt_rejects_nearly_expired_funding_address() {
	let ctx = TestContext::new("bark_sdk/board_psbt_rejects_nearly_expired_funding_address").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv)
		.cfg(|c| c.daemon_manual_sync = true)
		.funded(sat(100_000))
		.create().await;

	// The nearest expiry the builder accepts, so a single block makes it too near.
	let min_lifetime = wallet.config().vtxo_exit_margin.to_u32() + BOARD_CONFIRMATIONS;
	let tip = wallet.chain().tip().await.unwrap();
	let funding = wallet.board()
		.expiry(tip + BlockDelta::try_from(min_lifetime + 1).unwrap())
		.funding_address().await.unwrap();
	let psbt = funding_psbt(&wallet, &funding, sat(90_000)).await;

	ctx.generate_blocks(1).await;

	let err = wallet.board_psbt(psbt, &funding).await.unwrap_err();
	assert!(format!("{err:#}").contains("use a new funding address"), "unexpected error: {err:#}");
}

#[tokio::test]
async fn board_refuses_bad_psbts_and_tears_down_double_spends() {
	let ctx = TestContext::new("bark_sdk/board_refuses_bad_psbts_and_tears_down_double_spends").await;
	// No minimum, so a dust PSBT reaches the dust check.
	let srv = ctx.captaind("server")
		.cfg(|cfg| cfg.min_board_amount = Amount::ZERO)
		.create().await;

	// Tear down a board whose funding tx is double-spent by a confirmed tx
	Box::pin(async {
		let wallet = ctx.bark_sdk("funding_double_spent", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.funded(sat(100_000))
			.create().await;

		// The conflict spends the wallet's only utxo. Signed with sign_psbt, not
		// finish_psbt: finish_psbt persists it and the board would refuse the utxo.
		let conflict_tx = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			let psbt = onchain.prepare_drain_tx(ctx.bitcoind().get_new_address(), fee_rate).await.unwrap();
			onchain.sign_psbt(psbt).await.expect("conflict psbt must finalize").extract_tx().unwrap()
		};

		let board = wallet.board_amount(sat(90_000)).await.unwrap();

		// Mine the conflict directly, bypassing mempool policy, which evicts the funding tx.
		let mining_addr = ctx.bitcoind().get_new_address();
		ctx.bitcoind().sync_client().call::<serde_json::Value>("generateblock", &[
			mining_addr.to_string().into(),
			serde_json::json!([bitcoin::consensus::encode::serialize_hex(&conflict_tx)]),
		]).expect("failed to mine the conflicting tx");
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

		wallet.sync_pending_boards().await.unwrap();

		let balance = wallet.balance().await.unwrap();
		assert_eq!(balance.pending_board, Amount::ZERO);
		assert_eq!(balance.spendable, Amount::ZERO);
		assert!(wallet.vtxos().await.unwrap().is_empty(), "double-spent board vtxo should be gone");

		let history = wallet.history().await.unwrap();
		let movement = history.iter()
			.find(|m| m.subsystem.is_subsystem(Subsystem::BOARD))
			.expect("board movement should exist");
		assert_eq!(movement.status, MovementStatus::Failed);
		assert_eq!(movement.output_vtxos, board.vtxos);
		// The teardown resets the effective balance to zero.
		assert_eq!(movement.effective_balance, SignedAmount::ZERO);

		// The action checkpoint is removed, so nothing is left to retry.
		assert!(wallet.pending_boards().await.unwrap().is_empty());

		// Once synced, the onchain wallet sees the confirmed conflict and drops the funding tx.
		wallet.sync_onchain().await.unwrap();
		let onchain = wallet.onchain().expect("onchain wallet");
		let onchain = onchain.read().await;
		let onchain: &dyn Any = &*onchain;
		let onchain = onchain.downcast_ref::<OnchainWallet>().expect("bdk onchain wallet");
		let funding_txid = board.funding_tx.compute_txid();
		assert!(
			!onchain.list_transactions().iter().any(|tx| tx.compute_txid() == funding_txid),
			"onchain wallet should have dropped the double-spent board funding tx",
		);
	}).await;

	// Refuse a PSBT that pays another script
	Box::pin(async {
		let wallet = ctx.bark_sdk("wrong_funding_address", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.create().await;
		let funding = wallet.board().funding_address().await.unwrap();

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
				script_pubkey: ScriptBuf::new_op_return(&[0u8; 20]),
				value: sat(90_000),
			}],
		}).unwrap();

		let err = wallet.board_psbt(psbt, &funding).await.unwrap_err();
		assert!(
			format!("{err:#}").contains("does not pay to the expected board funding address"),
			"unexpected error: {err:#}",
		);
	}).await;

	// Refuse a PSBT that pays a dust amount to the funding address
	Box::pin(async {
		let wallet = ctx.bark_sdk("dust_amount", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.create().await;
		let funding = wallet.board().funding_address().await.unwrap();

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
				script_pubkey: funding.address().script_pubkey(),
				value: sat(P2TR_DUST_SAT - 1),
			}],
		}).unwrap();

		let err = wallet.board_psbt(psbt, &funding).await.unwrap_err();
		assert!(
			format!("{err:#}").contains("board amount must be at least"),
			"unexpected error: {err:#}",
		);
	}).await;

	// Find the board output at any index, not only vout 0
	Box::pin(async {
		let wallet = ctx.bark_sdk("output_at_any_index", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.funded(sat(300_000))
			.create().await;
		let funding = wallet.board().funding_address().await.unwrap();
		let board_addr = funding.address().clone();
		let board_script = board_addr.script_pubkey();

		// Two outputs, board last, so another output sits in front of the board.
		let mut psbt = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let other = ctx.bitcoind().get_new_address();
			let fee_rate = wallet.chain().fee_rates().await.regular;
			onchain.prepare_tx(&[(other, sat(20_000)), (board_addr, sat(90_000))], fee_rate)
				.await.unwrap()
		};
		move_board_output_last(&mut psbt, &board_script);

		let board_vout = psbt.unsigned_tx.output.iter()
			.position(|o| o.script_pubkey == board_script)
			.unwrap();
		assert_ne!(board_vout, 0, "test is meaningless if the board output is at vout 0");

		let pending = wallet.board_psbt(psbt, &funding).await
			.expect("board should cosign regardless of output index");

		let [vtxo] = wallet.vtxos().await.unwrap().try_into().expect("should have one board vtxo");
		assert_eq!(pending.vtxos[0], vtxo.id());
		assert!(matches!(vtxo.state, VtxoState::Locked { .. }));
	}).await;

	// Never broadcast an unfinalised funding tx, not at cosign nor on a later drive
	Box::pin(async {
		let wallet = ctx.bark_sdk("unfinalized_not_broadcast", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.funded(sat(200_000))
			.create().await;
		let funding = wallet.board().funding_address().await.unwrap();

		// Deliberately not finished: this is the proposal as it is handed over.
		let psbt = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			onchain.prepare_tx(&[(funding.address().clone(), sat(90_000))], fee_rate).await.unwrap()
		};
		let txid = psbt.unsigned_tx.compute_txid();

		wallet.board_psbt(psbt, &funding).await.unwrap();
		assert!(!in_mempool(&ctx, txid), "cosigning must not broadcast");

		// The vtxo exists and is locked, so the board is durable even though nothing
		// is on-chain yet.
		let [vtxo] = wallet.vtxos().await.unwrap().try_into().expect("should have one board vtxo");
		assert!(matches!(vtxo.state, VtxoState::Locked { .. }));

		// Drive the board repeatedly while the other party stays silent.
		for _ in 0..3 {
			ctx.generate_blocks(1).await;
			let _ = wallet.sync_pending_boards().await;
		}
		assert!(!in_mempool(&ctx, txid), "no drive may broadcast it either");
	}).await;

	// Confirm an unfinalised board once the other party broadcasts it
	Box::pin(async {
		let wallet = ctx.bark_sdk("other_party_broadcasts", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.create().await;
		// Two funded utxos so the transaction genuinely needs two inputs, which also
		// gives the conflict probe more than one outpoint to check.
		for _ in 0..2 {
			let address = {
				let onchain = wallet.onchain().expect("onchain wallet");
				let mut onchain = onchain.write().await;
				onchain.address().await.unwrap()
			};
			ctx.bitcoind().fund_addr(address, sat(70_000)).await;
		}
		ctx.generate_blocks(1).await;
		wallet.sync_onchain().await.unwrap();

		let funding = wallet.board().funding_address().await.unwrap();
		let (psbt, tx) = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			let psbt = onchain.prepare_tx(&[(funding.address().clone(), sat(120_000))], fee_rate)
				.await.unwrap();
			// The other party's finalised copy has the same txid as the unfinalised one
			// bark cosigns against.
			let tx = onchain.finish_psbt(psbt.clone()).await.unwrap().extract_tx().unwrap();
			(psbt, tx)
		};
		assert!(
			psbt.unsigned_tx.input.len() >= 2,
			"expected the board to need both utxos, got {} input(s)",
			psbt.unsigned_tx.input.len(),
		);
		assert_eq!(tx.compute_txid(), psbt.unsigned_tx.compute_txid());

		wallet.board_psbt(psbt, &funding).await.unwrap();

		// Nothing has moved on-chain, so the board does not count yet: the other party
		// holds the signatures and may never send it.
		assert_eq!(wallet.balance().await.unwrap().pending_board, Amount::ZERO);

		// The other party broadcasts, not us.
		ctx.bitcoind().sync_client().send_raw_transaction(&tx).unwrap();
		ctx.await_transaction(tx.compute_txid()).await;

		// On the network now, so the board leaves `Broadcasting` and starts counting.
		wallet.sync_pending_boards().await.unwrap();
		assert_eq!(wallet.balance().await.unwrap().pending_board, sat(120_000));

		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		wallet.sync_pending_boards().await.unwrap();

		let balance = wallet.balance().await.unwrap();
		assert_eq!(balance.spendable, sat(120_000));
		assert_eq!(balance.pending_board, Amount::ZERO, "board should have registered once confirmed");
	}).await;

	// Tear down an unfinalised board whose input is spent by a confirmed tx
	Box::pin(async {
		// A single utxo, so the conflicting tx below is forced to spend the same input.
		let wallet = ctx.bark_sdk("unfinalized_input_double_spent", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.funded(sat(200_000))
			.create().await;
		let funding = wallet.board().funding_address().await.unwrap();

		let psbt = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			onchain.prepare_tx(&[(funding.address().clone(), sat(90_000))], fee_rate).await.unwrap()
		};
		let board_txid = psbt.unsigned_tx.compute_txid();

		wallet.board_psbt(psbt, &funding).await.unwrap();
		// Not counted as pending: the funding tx has not reached the chain. The vtxo is
		// what says the board exists.
		assert_eq!(wallet.balance().await.unwrap().pending_board, Amount::ZERO);
		assert_eq!(wallet.vtxos().await.unwrap().len(), 1, "the board vtxo should exist");

		// The funding tx was never broadcast, so its input is still spendable: drain it
		// elsewhere and confirm that, which the board can now never outrace.
		let conflict = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			let psbt = onchain.prepare_drain_tx(ctx.bitcoind().get_new_address(), fee_rate).await.unwrap();
			onchain.finish_psbt(psbt).await.unwrap().extract_tx().unwrap()
		};
		assert_ne!(conflict.compute_txid(), board_txid);
		ctx.bitcoind().sync_client().send_raw_transaction(&conflict).unwrap();
		ctx.generate_blocks(1).await;

		wallet.sync_pending_boards().await.unwrap();

		let balance = wallet.balance().await.unwrap();
		assert_eq!(
			balance.pending_board, Amount::ZERO,
			"a board whose input was spent by a confirmed tx must be torn down",
		);
		assert_eq!(balance.spendable, Amount::ZERO);
	}).await;

	// Tear down a finalised board whose input is spent before bark broadcasts it
	Box::pin(async {
		// A single utxo, so the conflicting tx below is forced to spend the same input.
		let wallet = ctx.bark_sdk("input_double_spent_before_broadcast", &srv)
			.cfg(|c| c.daemon_manual_sync = true)
			.funded(sat(200_000))
			.create().await;

		// Signed with sign_psbt, not finish_psbt: finish_psbt persists it and the
		// board below would have nothing to spend.
		let conflict = {
			let onchain = wallet.onchain().expect("onchain wallet");
			let mut onchain = onchain.write().await;
			let fee_rate = wallet.chain().fee_rates().await.regular;
			let psbt = onchain.prepare_drain_tx(ctx.bitcoind().get_new_address(), fee_rate).await.unwrap();
			onchain.sign_psbt(psbt).await.expect("conflict psbt must finalize").extract_tx().unwrap()
		};

		// Finalised, so the funding tx is bark's to broadcast.
		let funding = wallet.board().funding_address().await.unwrap();
		let psbt = funding_psbt(&wallet, &funding, sat(90_000)).await;
		assert_ne!(psbt.unsigned_tx.compute_txid(), conflict.compute_txid());

		// Confirm the conflict before the board is ever pushed.
		ctx.bitcoind().sync_client().send_raw_transaction(&conflict).unwrap();
		ctx.generate_blocks(1).await;

		wallet.board_psbt(psbt, &funding).await.unwrap();
		wallet.sync_pending_boards().await.unwrap();

		assert_eq!(
			wallet.balance().await.unwrap().pending_board, Amount::ZERO,
			"a board that could never be broadcast must be torn down",
		);
		assert!(wallet.vtxos().await.unwrap().is_empty(), "the board vtxo must be gone");

		let history = wallet.history().await.unwrap();
		let movement = history.iter()
			.find(|m| m.subsystem.is_subsystem(Subsystem::BOARD))
			.expect("board movement should exist");
		assert_eq!(movement.status, MovementStatus::Failed);
	}).await;
}
