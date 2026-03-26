use std::sync::Arc;

use gloo_net::http::Request;

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