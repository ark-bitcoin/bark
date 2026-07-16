
use wasm_bindgen_test::*;

use bitcoin::Amount;

use std::sync::Arc;

use bark::onchain::{bdk_wallet, OnchainWallet};
use bark::persist::BarkPersister;
use bark::{OpenWalletArgs, Wallet, WalletSeed};

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_board() {
	let _ = console_log::init_with_level(log::Level::Debug);

	let mnemonic = random_mnemonic();
	let db: Arc<dyn BarkPersister> = open_db("test_board").await;

	// Create an onchain wallet for boarding.
	let mut onchain = OnchainWallet::load_or_create(
		bitcoin::Network::Regtest, mnemonic.to_seed(""), db.clone(),
	).await.expect("failed to create onchain wallet");
	let address = onchain.reveal_next_address(bdk_wallet::KeychainKind::External);
	fund_address(&address.address.to_string(), 100_000).await;
	let chain = esplora_chain_source().await;
	onchain.sync(&chain).await.expect("failed to sync onchain wallet");

	let wallet = Wallet::open(
		bitcoin::Network::Regtest,
		WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &mnemonic),
		test_config(),
		OpenWalletArgs {
			persister: Some(db.clone()),
			lock_manager: Some(test_lock_manager()),
			run_daemon: false,
			create_if_not_exists: true,
			onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
			..Default::default()
		},
	).await.expect("failed to create wallet");

	// Board funds into Ark.
	let board = wallet.board_amount(Amount::from_sat(90_000)).await
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
