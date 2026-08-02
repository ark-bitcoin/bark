
use std::sync::Arc;

use wasm_bindgen_test::*;

use bitcoin::Amount;
use futures::StreamExt;

use bark::onchain::{bdk_wallet, OnchainWallet};
use bark::persist::BarkPersister;
use bark::{OpenWalletArgs, Wallet, WalletSeed};

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Test that runs the wallet daemon in the browser: the receiver wallet is
/// opened with `run_daemon: true` and never syncs manually — the daemon's
/// background mailbox stream must pick up an incoming arkoor payment.
#[wasm_bindgen_test]
async fn test_daemon_processes_incoming_arkoor() {
	let _ = console_log::init_with_level(log::Level::Debug);

	// -- Sender: create, fund, board, confirm (no daemon, manual sync) --
	let sender_mnemonic = random_mnemonic();
	let sender_db: Arc<dyn BarkPersister> = open_db("test_daemon_sender").await;

	let mut onchain = OnchainWallet::load_or_create(
		bitcoin::Network::Regtest, sender_mnemonic.to_seed(""), sender_db.clone(),
	).await.expect("failed to create onchain wallet");
	let address = onchain.reveal_next_address(bdk_wallet::KeychainKind::External);
	fund_address(&address.address.to_string(), 100_000).await;
	let chain = esplora_chain_source().await;
	onchain.sync(&chain).await.expect("failed to sync onchain wallet");

	let sender = Wallet::open(
		bitcoin::Network::Regtest,
		WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, &sender_mnemonic),
		test_config(),
		OpenWalletArgs {
			persister: Some(sender_db.clone()),
			lock_manager: Some(test_lock_manager()),
			run_daemon: false,
			create_if_not_exists: true,
			onchain: Some(Arc::new(tokio::sync::RwLock::new(onchain))),
			..Default::default()
		},
	).await.expect("failed to create sender wallet");

	sender.board_amount(Amount::from_sat(90_000)).await
		.expect("failed to board");
	generate_blocks(BOARD_CONFIRMATIONS).await;
	sender.sync_pending_boards().await.expect("failed to sync boards");

	// -- Receiver: open with the daemon running in the browser --
	let receiver_mnemonic = random_mnemonic();
	let receiver_db: Arc<dyn BarkPersister> = open_db("test_daemon_receiver").await;

	// Short sync interval so daemon retries are prompt if the first
	// server connection attempt races the test setup.
	let mut receiver_config = test_config();
	receiver_config.daemon_sync_interval_secs = 2;

	// WasmWallet stops the daemon on drop, so its background tasks
	// don't hold IndexedDB borrows that interfere with other tests
	// in this browser context.
	let receiver = WasmWallet::open(&receiver_mnemonic, receiver_config, receiver_db).await;

	// Subscribe to notifications before the payment is sent so the
	// daemon can't process it before we start listening.
	let mut movements = receiver.subscribe_notifications().movements();

	let recv_addr = receiver.new_address().await
		.expect("failed to get receiver address");

	// -- Send arkoor; the receiver daemon should pick it up by itself --
	let send_amount = Amount::from_sat(20_000);
	sender.send_arkoor_payment(&recv_addr, send_amount).await
		.expect("failed to send arkoor");

	let movement = movements.next().await
		.expect("should receive a movement notification from the daemon");

	log::info!("Daemon processed movement: {:?}", movement);
	assert_eq!(movement.effective_balance.unsigned_abs(), send_amount,
		"movement should reflect the sent amount");

	let balance = receiver.balance().await.expect("failed to get balance");
	assert_eq!(balance.spendable, send_amount,
		"receiver should have the sent amount without any manual sync");
}
