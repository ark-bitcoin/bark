
use wasm_bindgen_test::*;

use bitcoin::Amount;

use std::sync::Arc;

use bark::onchain::{bdk_wallet, ChainSync, OnchainWallet};
use bark::persist::BarkPersister;
use bark::{OpenWalletArgs, Wallet, WalletSeed};

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_arkoor_send() {
	let _ = console_log::init_with_level(log::Level::Debug);

	// -- Sender: create, fund, board, confirm --
	let sender_mnemonic = random_mnemonic();
	let sender_db: Arc<dyn BarkPersister> = open_db("test_arkoor_sender").await;

	let sender = Wallet::open(
		bitcoin::Network::Regtest,
		WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &sender_mnemonic),
		test_config(),
		OpenWalletArgs {
			persister: Some(sender_db.clone()),
			lock_manager: Some(test_lock_manager()),
			run_daemon: false,
			create_if_not_exists: true,
			..Default::default()
		},
	).await.expect("failed to create sender wallet");

	let seed = sender_mnemonic.to_seed("");
	let mut onchain = OnchainWallet::load_or_create(
		bitcoin::Network::Regtest, seed, sender_db,
	).await.expect("failed to create onchain wallet");

	let address = onchain.reveal_next_address(bdk_wallet::KeychainKind::External);
	fund_address(&address.address.to_string(), 100_000).await;

	let chain = esplora_chain_source().await;
	onchain.sync(&chain).await.expect("failed to sync onchain wallet");

	sender.board_amount(&mut onchain, Amount::from_sat(90_000)).await
		.expect("failed to board");
	generate_blocks(3).await;
	sender.sync_pending_boards().await.expect("failed to sync boards");

	// -- Receiver: create wallet, get address --
	let receiver_db: Arc<dyn BarkPersister> = open_db("test_arkoor_receiver").await;
	let receiver_mnemonic = random_mnemonic();

	let receiver = Wallet::open(
		bitcoin::Network::Regtest,
		WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &receiver_mnemonic),
		test_config(),
		OpenWalletArgs {
			persister: Some(receiver_db),
			lock_manager: Some(test_lock_manager()),
			run_daemon: false,
			create_if_not_exists: true,
			..Default::default()
		},
	).await.expect("failed to create receiver wallet");

	let recv_addr = receiver.new_address().await
		.expect("failed to get receiver address");

	// -- Send arkoor --
	let send_amount = Amount::from_sat(20_000);
	sender.send_arkoor_payment(&recv_addr, send_amount).await
		.expect("failed to send arkoor");

	// -- Receiver: sync mailbox to pick up the payment --
	receiver.sync_mailbox().await.expect("failed to sync mailbox");

	let recv_balance = receiver.balance().await.expect("failed to get balance");
	assert_eq!(recv_balance.spendable, send_amount,
		"receiver should have the sent amount");

	let sender_balance = sender.balance().await.expect("failed to get balance");
	assert!(sender_balance.spendable < Amount::from_sat(90_000),
		"sender balance should have decreased");
}

