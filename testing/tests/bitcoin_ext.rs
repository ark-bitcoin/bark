use std::collections::HashMap;

use bitcoin::{Address, Amount, FeeRate, Network};
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
		bitcoind, prev_tip.clone(), prev_tip.height(), wallet.unconfirmed_txs(),
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
