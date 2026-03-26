use std::sync::Arc;

use bark::persist::adaptor::indexed_db::IndexedDbClient;
use bark::persist::adaptor::StorageAdaptorWrapper;
use bark::chain::{ChainSource, ChainSourceSpec};
use bark::lock_manager::{LockManager, web_locks::WebLockManager};
use bark::Config;

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

