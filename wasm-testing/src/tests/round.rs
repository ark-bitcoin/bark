
use wasm_bindgen_test::*;

use bitcoin::Amount;

use std::sync::Arc;

use bark::onchain::{bdk_wallet, OnchainWallet};
use bark::persist::BarkPersister;
use bark::{OpenWalletArgs, Wallet, WalletSeed};

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_round_refresh() {
	let _ = console_log::init_with_level(log::Level::Debug);

	let mnemonic = random_mnemonic();
	let db: Arc<dyn BarkPersister> = open_db("test_round").await;

	// Create and fund an onchain wallet.
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

	// Board and confirm.
	wallet.board_amount(Amount::from_sat(90_000)).await
		.expect("failed to board");
	generate_blocks(3).await;
	wallet.sync_pending_boards().await.expect("failed to sync boards");

	let before = wallet.balance().await.expect("failed to get balance");
	assert_eq!(before.spendable, Amount::from_sat(90_000), "pre-refresh spendable");

	// Get vtxos to refresh.
	let vtxos = wallet.spendable_vtxos().await.expect("failed to get vtxos");
	assert!(!vtxos.is_empty(), "should have vtxos to refresh");

	// Refresh all vtxos by participating in a round.
	// trigger_round must be called concurrently with refresh_vtxos.
	let (refresh_result, _) = futures::join!(
		wallet.refresh_vtxos(vtxos.iter()),
		trigger_round(),
	);
	let status = refresh_result.expect("refresh failed")
		.expect("no round was joined");
	log::info!("Round status: {:?}", status);

	// Confirm the round tx and sync so the wallet sees the new VTXOs.
	generate_blocks(6).await;
	wallet.sync().await;

	// Balance should be preserved after refresh.
	let after = wallet.balance().await.expect("failed to get balance");
	assert_eq!(after.spendable, before.spendable,
		"balance should be preserved after refresh (before={}, after={})",
		before.spendable, after.spendable,
	);
}
