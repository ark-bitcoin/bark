
use wasm_bindgen_test::*;

use bark::Wallet;

use crate::test_utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_create_wallet_and_connect() {
	let _ = console_log::init_with_level(log::Level::Debug);

	let db = open_db(WALLET_NAME).await;
	let wallet = Wallet::create(
		&random_mnemonic(),
		bitcoin::Network::Regtest,
		test_config(),
		db,
		test_lock_manager(),
		false,
	).await.expect("failed to create wallet");

	let wallet_properties = wallet.properties().await
		.expect("failed to get wallet properties");

	let info = wallet.require_ark_info().await
		.expect("failed to get ark info");
	assert_eq!(info.network, bitcoin::Network::Regtest);
	assert_eq!(info.server_pubkey, wallet_properties.server_pubkey.unwrap());
}
