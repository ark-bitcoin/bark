use std::ops::Deref;
use std::sync::Arc;

use gloo_net::http::Request;

use bark::persist::adaptor::indexed_db::IndexedDbClient;
use bark::persist::adaptor::StorageAdaptorWrapper;
use bark::persist::BarkPersister;
use bark::chain::{ChainSource, ChainSourceSpec};
use bark::lock_manager::{LockManager, web_locks::WebLockManager};
use bark::{Config, OpenWalletArgs, Wallet, WalletSeed};

pub(crate) const BOARD_CONFIRMATIONS: u32 = 3;
pub(crate) const WALLET_NAME: &str = "my_test_wallet";

pub(crate) fn test_config() -> Config {
	Config {
		server_address: env!("ARK_SERVER_URL").into(),
		esplora_address: Some(env!("ARK_ESPLORA_URL").into()),
		..Config::network_default(bitcoin::Network::Regtest)
	}
}

pub(crate) fn random_mnemonic() -> bip39::Mnemonic {
	bip39::Mnemonic::generate(12).expect("failed to generate mnemonic")
}

pub(crate) fn test_lock_manager() -> Box<dyn LockManager> {
	Box::new(WebLockManager::new())
}

pub(crate) async fn open_db(name: &str) -> Arc<StorageAdaptorWrapper<IndexedDbClient>> {
	let storage = IndexedDbClient::open(name).await
		.expect("failed to open IndexedDB");
	Arc::new(StorageAdaptorWrapper::new(storage))
}

/// A regtest [Wallet] running the background daemon, which is stopped when
/// this wrapper is dropped. The daemon holds a clone of the wallet, so
/// without an explicit stop it would keep running (and hold IndexedDB
/// borrows) for the rest of the browser test context.
pub(crate) struct WasmWallet {
	wallet: Wallet,
}

impl WasmWallet {
	pub(crate) async fn open(
		mnemonic: &bip39::Mnemonic,
		config: Config,
		db: Arc<dyn BarkPersister>,
	) -> WasmWallet {
		let wallet = Wallet::open(
			bitcoin::Network::Regtest,
			WalletSeed::new_from_mnemonic(bitcoin::Network::Regtest, mnemonic),
			config,
			OpenWalletArgs {
				persister: Some(db),
				lock_manager: Some(test_lock_manager()),
				run_daemon: true,
				create_if_not_exists: true,
				..Default::default()
			},
		).await.expect("failed to open wallet");
		WasmWallet { wallet }
	}
}

impl Deref for WasmWallet {
	type Target = Wallet;
	fn deref(&self) -> &Wallet {
		&self.wallet
	}
}

impl Drop for WasmWallet {
	fn drop(&mut self) {
		self.wallet.stop_daemon();
	}
}

pub(crate) async fn esplora_chain_source() -> ChainSource {
	let spec = ChainSourceSpec::Esplora {
		url: env!("ARK_ESPLORA_URL").into(),
	};
	ChainSource::new(spec, bitcoin::Network::Regtest, None).await
		.expect("failed to create chain source")
}

pub async fn generate_blocks(n: u32) -> u64 {
	let url = format!("{}/generate_blocks?n={}", env!("ARK_CONTROL_URL"), n);
	let resp = gloo_net::http::Request::get(&url).send().await
		.expect("failed to reach control server");
	resp.text().await.expect("failed to read response")
		.trim().parse().expect("invalid block height")
}

pub async fn fund_address(address: &str, sats: u64) {
	let url = format!("{}/fund_address?address={}&sats={}", env!("ARK_CONTROL_URL"), address, sats);
	let resp = gloo_net::http::Request::get(&url).send().await
		.expect("failed to reach control server");
	assert!(resp.ok(), "fund_address failed: {}", resp.status());
}

pub async fn trigger_round() {
	let url = format!("{}/trigger_round", env!("ARK_CONTROL_URL"));
	let resp = gloo_net::http::Request::get(&url).send().await
		.expect("failed to reach control server");
	assert!(resp.ok(), "trigger_round failed: {}", resp.status());
}

/// Get a new on-chain bitcoin address from the test bitcoind.
pub async fn get_new_address() -> String {
	let url = format!("{}/get_new_address", env!("ARK_CONTROL_URL"));
	let resp = gloo_net::http::Request::get(&url).send().await
		.expect("failed to reach control server");
	resp.text().await.expect("failed to read response").trim().to_string()
}