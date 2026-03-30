
use std::sync::Arc;

use wasm_bindgen_test::*;

use bitcoin::Amount;
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

use bark::onchain::{bdk_wallet, ChainSync, OnchainWallet};
use bark::Wallet;

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Test that spawns subscribe_process_mailbox_messages as a background
/// task, sends an arkoor payment, and verifies the notification fires.
#[wasm_bindgen_test]
async fn test_mailbox_subscribe() {
	let _ = console_log::init_with_level(log::Level::Debug);

	// -- Sender: create, fund, board, confirm --
	let sender_mnemonic = random_mnemonic();
	let sender_db = open_db("test_mailbox_sender").await;

	let sender = Wallet::create(
		&sender_mnemonic,
		bitcoin::Network::Regtest,
		test_config(),
		sender_db.clone(),
		test_lock_manager(),
		false,
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

	// -- Receiver: create wallet, wrap in Arc for sharing --
	let receiver_mnemonic = random_mnemonic();
	let receiver_db = open_db("test_mailbox_receiver").await;

	let receiver = Arc::new(Wallet::create(
		&receiver_mnemonic,
		bitcoin::Network::Regtest,
		test_config(),
		receiver_db,
		test_lock_manager(),
		false,
	).await.expect("failed to create receiver wallet"));

	// Subscribe to notifications before starting the mailbox listener.
	let mut movements = receiver.subscribe_notifications().movements();

	let recv_addr = receiver.new_address().await
		.expect("failed to get receiver address");

	// Spawn the mailbox subscription as a background task.
	let cancellation_token = CancellationToken::new();
	let receiver_bg = receiver.clone();
	let bg_token = cancellation_token.clone();
	wasm_bindgen_futures::spawn_local(async move {
		if let Err(e) = receiver_bg.subscribe_process_mailbox_messages(None, bg_token).await {
			log::error!("mailbox subscription error: {:#}", e);
		}
	});

	// -- Send arkoor --
	let send_amount = Amount::from_sat(20_000);
	sender.send_arkoor_payment(&recv_addr, send_amount).await
		.expect("failed to send arkoor");

	// Wait for the notification from the background mailbox processor.
	let movement = movements.next().await
		.expect("should receive a movement notification");

	log::info!("Received movement: {:?}", movement);
	assert_eq!(movement.effective_balance.unsigned_abs(), send_amount,
		"movement should reflect the sent amount");

	// Stop the background subscription so it doesn't hold IndexedDB
	// borrows that interfere with other tests in this browser context.
	cancellation_token.cancel();
}

