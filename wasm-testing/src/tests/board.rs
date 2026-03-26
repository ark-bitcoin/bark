
use wasm_bindgen_test::*;

use bitcoin::Amount;

use bark::onchain::{bdk_wallet, ChainSync, OnchainWallet};
use bark::Wallet;

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_board() {
	let _ = console_log::init_with_level(log::Level::Debug);

	let mnemonic = random_mnemonic();
	let db = open_db("test_board").await;

	let wallet = Wallet::create(
		&mnemonic,
		bitcoin::Network::Regtest,
		test_config(),
		db.clone(),
		test_lock_manager(),
		false,
	).await.expect("failed to create wallet");

	// Create an onchain wallet for boarding.
	let seed = mnemonic.to_seed("");
	let mut onchain = OnchainWallet::load_or_create(
		bitcoin::Network::Regtest, seed, db,
	).await.expect("failed to create onchain wallet");

	// Get an onchain address and fund it via the control server.
	let address = onchain.reveal_next_address(bdk_wallet::KeychainKind::External);
	fund_address(&address.address.to_string(), 100_000).await;

	// Sync the onchain wallet to pick up the funding tx.
	let chain = esplora_chain_source().await;
	onchain.sync(&chain).await.expect("failed to sync onchain wallet");

	// Board funds into Ark.
	let board = wallet.board_amount(&mut onchain, Amount::from_sat(90_000)).await
		.expect("failed to board");
	assert!(!board.vtxos.is_empty(), "board should produce vtxos");

	// Confirm the board transaction.
	generate_blocks(3).await;

	// Register the confirmed board with the server.
	wallet.sync_pending_boards().await.expect("failed to sync boards");

	let balance = wallet.balance().await.expect("failed to get balance");
	assert_eq!(balance.spendable, Amount::from_sat(90_000),
		"should have spendable balance after board (spendable={}, pending_board={})",
		balance.spendable, balance.pending_board,
	);
}
