
use wasm_bindgen_test::*;

use std::str::FromStr;

use bitcoin::Amount;

use bark::onchain::{bdk_wallet, ChainSync, OnchainWallet};
use bark::Wallet;

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_offboard_all() {
	let _ = console_log::init_with_level(log::Level::Debug);

	let mnemonic = random_mnemonic();
	let db = open_db("test_offboard").await;

	let wallet = Wallet::create(
		&mnemonic,
		bitcoin::Network::Regtest,
		test_config(),
		db.clone(),
		test_lock_manager(),
		false,
	).await.expect("failed to create wallet");

	// Fund and board.
	let seed = mnemonic.to_seed("");
	let mut onchain = OnchainWallet::load_or_create(
		bitcoin::Network::Regtest, seed, db,
	).await.expect("failed to create onchain wallet");

	let address = onchain.reveal_next_address(bdk_wallet::KeychainKind::External);
	fund_address(&address.address.to_string(), 100_000).await;

	let chain = esplora_chain_source().await;
	onchain.sync(&chain).await.expect("failed to sync onchain wallet");

	wallet.board_amount(&mut onchain, Amount::from_sat(90_000)).await
		.expect("failed to board");
	generate_blocks(3).await;
	wallet.sync_pending_boards().await.expect("failed to sync boards");

	let before = wallet.balance().await.expect("failed to get balance");
	assert_eq!(before.spendable, Amount::from_sat(90_000));

	// Offboard all to a fresh on-chain address.
	let dest = get_new_address().await;
	let dest = bitcoin::Address::from_str(&dest).expect("invalid address")
		.assume_checked();

	let (offboard_result, _) = futures::join!(
		wallet.offboard_all(dest),
		trigger_round(),
	);
	offboard_result.expect("offboard failed");

	let after = wallet.balance().await.expect("failed to get balance");
	assert_eq!(after.spendable, Amount::ZERO,
		"all funds should have been offboarded");
}

