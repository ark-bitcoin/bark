use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::{Address, Amount, FeeRate, Network};
use bitcoin::address::NetworkUnchecked;
use bitcoincore_rpc::RpcApi;
use bitcoincore_rpc::json::CreateRawTransactionInput;
use bdk_wallet::Wallet;

use ark_testing::{TestContext, sat};
use bitcoin_ext::bdk::{WalletExt, KEYCHAIN};
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::fee::P2A_SCRIPT;
use bitcoin_ext::rpc::BitcoinRpcExt;

fn build_zero_fee_tx_with_p2a_output(client: &impl RpcApi) -> bitcoin::Transaction {
	let utxo = client.list_unspent(Some(1), None, None, None, None)
		.unwrap().into_iter().next().unwrap();
	let p2a_addr = Address::from_script(&P2A_SCRIPT, Network::Regtest).unwrap();
	let dummy_addr: Address = "bcrt1pv8xe2fc666cds7ep2r4nwrnfcxzrf884uw8jzhs3qajynttr99dqqp32de"
		.parse::<Address<bitcoin::address::NetworkUnchecked>>().unwrap().assume_checked();
	let inputs = vec![CreateRawTransactionInput {
		txid: utxo.txid, vout: utxo.vout, sequence: None,
	}];
	let mut outputs = HashMap::new();
	outputs.insert(p2a_addr.to_string(), Amount::ZERO);
	outputs.insert(dummy_addr.to_string(), utxo.amount);
	let raw_tx = client.create_raw_transaction(&inputs, &outputs, None, None).unwrap();
	client.sign_raw_transaction_with_wallet(&raw_tx, None, None)
		.unwrap().transaction().unwrap()
}

fn create_wallet() -> Wallet {
	let xpriv = bitcoin::bip32::Xpriv::new_master(Network::Regtest, &[0xAB; 32]).unwrap();
	let desc = format!("tr({}/0/*)", xpriv);
	Wallet::create_single(desc)
		.network(Network::Regtest)
		.create_wallet_no_persist()
		.unwrap()
}

fn sync_wallet(wallet: &mut Wallet, bitcoind: &impl RpcApi) {
	let prev_tip = wallet.latest_checkpoint();
	let mut emitter = bdk_bitcoind_rpc::Emitter::new(
		bitcoind, prev_tip.clone(), 0, wallet.unconfirmed_txs(),
	);
	while let Some(em) = emitter.next_block().unwrap() {
		wallet.apply_block_connected_to(
			&em.block, em.block_height(), em.connected_to(),
		).unwrap();
	}
	let mempool = emitter.mempool().unwrap();
	wallet.apply_unconfirmed_txs(mempool.update);
}

#[tokio::test]
async fn is_trusted() {
	let ctx = TestContext::new("bitcoin_ext/is_trusted").await;
	let bitcoind = ctx.bitcoind();
	bitcoind.prepare_funds().await;

	let mut wallet = create_wallet();
	let addr = wallet.peek_address(KEYCHAIN, 0).address;
	let client = bitcoind.sync_client();

	// Fund the wallet from bitcoind (external inputs), don't confirm yet.
	let funding_txid = client.send_to_address(
		&addr, sat(100_000), None, None, None, None, None, None,
	).unwrap();
	sync_wallet(&mut wallet, &client);

	// Unconfirmed external tx (0 confs).
	assert!(wallet.is_trusted_tx(funding_txid, 0));
	assert!(!wallet.is_trusted_tx(funding_txid, 1));
	assert!(!wallet.is_trusted_tx(funding_txid, 2));

	// Confirm with 1 block (1 conf).
	bitcoind.generate(1).await;
	sync_wallet(&mut wallet, &client);

	assert!(wallet.is_trusted_tx(funding_txid, 0));
	assert!(wallet.is_trusted_tx(funding_txid, 1));
	assert!(!wallet.is_trusted_tx(funding_txid, 2));

	// Mine another block (2 confs).
	bitcoind.generate(1).await;
	sync_wallet(&mut wallet, &client);

	assert!(wallet.is_trusted_tx(funding_txid, 0));
	assert!(wallet.is_trusted_tx(funding_txid, 1));
	assert!(wallet.is_trusted_tx(funding_txid, 2));

	// Spend to self → unconfirmed change output.
	let self_addr = wallet.peek_address(KEYCHAIN, 1).address;
	let mut b = wallet.build_tx();
	b.add_recipient(self_addr.script_pubkey(), sat(50_000));
	let mut psbt = b.finish().unwrap();
	wallet.sign(&mut psbt, Default::default()).unwrap();
	let self_tx = psbt.extract_tx().unwrap();
	let self_txid = self_tx.compute_txid();
	client.send_raw_transaction(&self_tx).unwrap();
	sync_wallet(&mut wallet, &client);

	// Self-spend is unconfirmed, but ancestor is confirmed → trusted transitively.
	assert!(wallet.is_trusted_tx(self_txid, 1));

	// Build a chain of 3 more self-spends, all unconfirmed.
	let mut last_txid = self_txid;
	for i in 2..=4 {
		let next_addr = wallet.peek_address(KEYCHAIN, i).address;
		let mut b = wallet.build_tx();
		b.add_recipient(next_addr.script_pubkey(), sat(10_000));
		let mut psbt = b.finish().unwrap();
		wallet.sign(&mut psbt, Default::default()).unwrap();
		let tx = psbt.extract_tx().unwrap();
		last_txid = tx.compute_txid();
		client.send_raw_transaction(&tx).unwrap();
		sync_wallet(&mut wallet, &client);
	}

	// The whole chain is trusted because it roots in the confirmed funding tx.
	assert!(wallet.is_trusted_tx(last_txid, 1));

	bitcoind.generate(1).await;
	sync_wallet(&mut wallet, &client);

	// CPFP: build a parent tx with a P2A output and 0 fee. Our wallet
	// bumps it by spending the anchor. The child should be untrusted
	// because the parent has external inputs.
	let parent_tx = build_zero_fee_tx_with_p2a_output(&client);

	let fees = MakeCpfpFees::Effective(FeeRate::from_sat_per_vb(10).unwrap());
	let child_tx = wallet.make_signed_p2a_cpfp(&parent_tx, fees).unwrap();
	let child_txid = child_tx.compute_txid();
	client.submit_package(&[&parent_tx, &child_tx]).unwrap();
	sync_wallet(&mut wallet, &client);

	// The child spends a P2A from an external parent → untrusted.
	assert!(!wallet.is_trusted_tx(child_txid, 1));
}

/// Repro for the rounds-wallet `balance()` blow-up seen in production
/// (sync_time = 131s while wall-clock between WalletSyncStarting and
/// WalletSyncComplete was ~136ms — the cost is the `prev_balance =
/// self.balance()` call in `sync()` before the start log fires).
///
/// Shape:
///   * one confirmed funding UTXO (root of trust)
///   * a chain of unconfirmed self-spends, depth > 100 — past the
///     `is_trusted_tx_inner` budget so the walk exhausts before
///     reaching the confirmed root, and every UTXO hits the worst case
///   * a single fan-out tip tx producing many unspent outputs, so each
///     output triggers a fresh full-budget walk over the same chain
///     (no memoization across UTXOs, fresh budget per top-level call —
///     `bitcoin-ext/src/bdk.rs:126`)
///
/// We don't broadcast the chain to bitcoind because mempool ancestor
/// limits would cap us at ~25; `apply_unconfirmed_txs` directly seeds
/// the wallet's canonical view, which is what BDK's `list_unspent`
/// reads from.
#[tokio::test]
async fn balance_perf_deep_unconfirmed_fanout() {
	let ctx = TestContext::new("bitcoin_ext/balance_perf").await;
	let bitcoind = ctx.bitcoind();
	bitcoind.prepare_funds().await;

	let mut wallet = create_wallet();
	let client = bitcoind.sync_client();

	// One confirmed funding UTXO — the root of trust the recursion
	// is trying (and failing) to reach.
	let addr = wallet.peek_address(KEYCHAIN, 0).address;
	client.send_to_address(&addr, sat(500_000_000), None, None, None, None, None, None).unwrap();
	bitcoind.generate(1).await;
	sync_wallet(&mut wallet, &client);
	assert_eq!(wallet.balance().total(), sat(500_000_000));

	// Deep unconfirmed self-spend chain. CHAIN_DEPTH > 100 means the
	// budget runs out before we hit the root.
	const CHAIN_DEPTH: u32 = 120;
	for i in 1..=CHAIN_DEPTH {
		let next_addr = wallet.peek_address(KEYCHAIN, i).address;
		let mut b = wallet.build_tx();
		b.drain_wallet();
		b.drain_to(next_addr.script_pubkey());
		b.fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
		let mut psbt = b.finish().unwrap();
		wallet.sign(&mut psbt, Default::default()).unwrap();
		let tx = psbt.extract_tx().unwrap();
		wallet.apply_unconfirmed_txs([(tx, 0)]);
	}

	// Fan-out tip: one tx, many outputs. Each output becomes a UTXO
	// with the same creating txid; `is_trusted_utxo` is still called
	// per-outpoint and dispatches to `is_trusted_tx(txid, ...)` with a
	// fresh budget, so the same chain is walked once per output.
	const FANOUT: u32 = 1000;
	let fanout_addrs: Vec<_> = (0..FANOUT)
		.map(|i| wallet.peek_address(KEYCHAIN, CHAIN_DEPTH + 1 + i).address)
		.collect();
	let mut b = wallet.build_tx();
	for a in &fanout_addrs {
		b.add_recipient(a.script_pubkey(), sat(50_000));
	}
	b.fee_rate(FeeRate::from_sat_per_vb(2).unwrap());
	let mut psbt = b.finish().unwrap();
	wallet.sign(&mut psbt, Default::default()).unwrap();
	let fanout_tx = psbt.extract_tx().unwrap();
	wallet.apply_unconfirmed_txs([(fanout_tx, 0)]);

	let unspent_count = wallet.list_unspent().count();
	println!("unspent count after fanout: {}", unspent_count);

	// Time `trusted_balance(1)` — the call that's blocking sync.
	let start = std::time::Instant::now();
	let bal = wallet.trusted_balance(1);
	let elapsed = start.elapsed();
	println!(
		"trusted_balance(1) over {} unspent took {:?} (trusted={}, untrusted={})",
		unspent_count, elapsed, bal.trusted, bal.untrusted,
	);

	assert!(elapsed < std::time::Duration::from_secs(2),
		"trusted_balance(1) took {:?}, expected < 2s", elapsed);
}

#[tokio::test]
async fn deep_reorg_wallet_sync() {
	let ctx = TestContext::new("bitcoin_ext/deep_reorg").await;
	let bitcoind = ctx.bitcoind();
	bitcoind.prepare_funds().await;

	let mut wallet = create_wallet();
	let client = bitcoind.sync_client();

	// Phase 1: Sync wallet with current chain
	sync_wallet(&mut wallet, &client);
	let start_height = wallet.latest_checkpoint().height();

	// Mine 6 blocks, sync wallet
	bitcoind.generate(6).await;
	sync_wallet(&mut wallet, &client);
	let base_height = wallet.latest_checkpoint().height();
	assert_eq!(base_height, start_height + 6);

	// Phase 2: Fund wallet, confirm, sync
	let addr = wallet.peek_address(KEYCHAIN, 0).address;
	let funding_txid = client.send_to_address(
		&addr, sat(100_000), None, None, None, None, None, None,
	).unwrap();
	bitcoind.generate(5).await;
	sync_wallet(&mut wallet, &client);

	let post_fund_height = wallet.latest_checkpoint().height();
	assert_eq!(post_fund_height, base_height + 5);
	let post_fund_balance = wallet.balance().total();
	assert_eq!(post_fund_balance, sat(100_000));

	// Phase 3: Self-spend, confirm, sync
	let self_addr = wallet.peek_address(KEYCHAIN, 1).address;
	let mut b = wallet.build_tx();
	b.add_recipient(self_addr.script_pubkey(), sat(50_000));
	let mut psbt = b.finish().unwrap();
	wallet.sign(&mut psbt, Default::default()).unwrap();
	let self_tx = psbt.extract_tx().unwrap();
	let self_txid = self_tx.compute_txid();
	client.send_raw_transaction(&self_tx).unwrap();
	bitcoind.generate(5).await;
	sync_wallet(&mut wallet, &client);

	let pre_reorg_tip = wallet.latest_checkpoint().height();
	let pre_reorg_hash = wallet.latest_checkpoint().hash();
	assert_eq!(pre_reorg_tip, base_height + 10);

	// Verify both txs are confirmed before the reorg
	let funding_chain_pos = wallet.get_tx(funding_txid).unwrap().chain_position.clone();
	assert!(funding_chain_pos.is_confirmed(), "funding tx should be confirmed pre-reorg");
	let self_spend_chain_pos = wallet.get_tx(self_txid).unwrap().chain_position.clone();
	assert!(self_spend_chain_pos.is_confirmed(), "self-spend should be confirmed pre-reorg");

	// Record pre-reorg balance (100k minus fee from self-spend)
	let pre_reorg_balance = wallet.balance().total();
	assert!(pre_reorg_balance > Amount::ZERO);
	assert!(pre_reorg_balance < sat(100_000)); // some fee was paid

	// Phase 4: Deep reorg -- invalidate block at base_height + 2
	// This orphans 8 blocks, including the self-spend tx.
	// The funding tx (confirmed at ~base_height+1) survives the reorg.
	let reorg_height = base_height + 2;
	let reorg_hash = client.get_block_hash(reorg_height as u64).unwrap();
	client.invalidate_block(&reorg_hash).unwrap();

	// Verify bitcoind chain rolled back
	let chain_height_after_invalidate = client.get_block_count().unwrap();
	assert_eq!(chain_height_after_invalidate, (reorg_height - 1) as u64);

	// Phase 5: Mine longer replacement chain (surpass old tip)
	let reorg_addr = Address::<NetworkUnchecked>::from_str(
		"bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf"
	).unwrap().assume_checked();
	let blocks_needed = (pre_reorg_tip - reorg_height + 1) + 7; // 9 + 7 = 16
	client.generate_to_address(blocks_needed as u64, &reorg_addr).unwrap();

	let new_chain_height = client.get_block_count().unwrap();
	assert_eq!(new_chain_height, (reorg_height - 1) as u64 + blocks_needed as u64);

	// New chain has different block at the old tip height
	let new_hash_at_old_tip = client.get_block_hash(pre_reorg_tip as u64).unwrap();
	assert_ne!(new_hash_at_old_tip, pre_reorg_hash,
		"block hash at old tip height should differ on new chain");

	// Phase 6: Wallet sync should handle the deep reorg gracefully.
	// Previously, passing prev_tip.height() as start_height caused the Emitter
	// to skip from the agreement point directly to the old tip height on the
	// new chain, producing a gap that BDK could not merge. The fix is to pass
	// start_height=0 so the Emitter walks forward block-by-block from the
	// agreement point.
	sync_wallet(&mut wallet, &client);

	// Wallet checkpoint should now be at the new chain tip
	let new_tip_height = new_chain_height as u32;
	assert_eq!(wallet.latest_checkpoint().height(), new_tip_height,
		"checkpoint should advance to new chain tip");
	assert_ne!(wallet.latest_checkpoint().hash(), pre_reorg_hash,
		"checkpoint hash should differ from pre-reorg hash");

	// The funding tx was confirmed before the reorg point and should
	// still be confirmed on the new chain (it went back to mempool and
	// was re-mined).
	let funding_pos = wallet.get_tx(funding_txid).unwrap().chain_position.clone();
	assert!(funding_pos.is_confirmed(),
		"funding tx should still be confirmed after reorg");

	// Balance should be non-zero (we still have funds)
	assert!(wallet.balance().total() > Amount::ZERO,
		"wallet should still have balance after reorg");
}
