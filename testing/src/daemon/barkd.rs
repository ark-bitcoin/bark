
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, Network};
use bitcoin::secp256k1::rand::{self, RngCore};
use log::info;
use tokio::process::Command;

use bark_json::cli::{ArkInfo, Balance, NextRoundStart, PendingBoardInfo};
use bark_json::cli::onchain::{Address, OnchainBalance};
use bark_rest::auth::AuthToken;
use bark_json::primitives::{TransactionInfo, UtxoInfo, WalletVtxoInfo};
use bark_json::web::EncodedVtxoResponse;
use bark_json::web::{BarkNetwork, BitcoindAuth, ChainSourceConfig, ConnectedResponse, CreateWalletRequest, TipResponse};
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::{bitcoin_api, boards_api, default_api, onchain_api, wallet_api};

use crate::{Bitcoind, Daemon, DaemonHelper};
use crate::constants::env::{BARKD_EXEC, BARK_TOKIO_WORKER_THREADS};
use crate::util::resolve_path;

pub type Barkd = Daemon<BarkdHelper>;

const AUTH_TOKEN_FILE: &str = "auth_token";

/// Chain source configuration for barkd.
pub enum BarkdChainSource {
	Esplora(String),
	Bitcoind { url: String, cookie: PathBuf },
}

pub struct BarkdHelper {
	name: String,
	datadir: PathBuf,
	ark_server_url: String,
	chain_source: BarkdChainSource,
	/// Optional dedicated bitcoind kept alive for the duration of the test.
	_bitcoind: Option<Bitcoind>,
	port: u16,
	auth_token: AuthToken,
}

impl Barkd {
	pub fn base_cmd() -> Command {
		let e = env::var(BARKD_EXEC).expect("BARKD_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve BARKD_EXEC");
		Command::new(exec)
	}

	pub fn new(
		name: impl AsRef<str>,
		datadir: PathBuf,
		ark_server_url: String,
		chain_source: BarkdChainSource,
		bitcoind: Option<Bitcoind>,
	) -> Self {
		let mut secret = [0u8; 32];
		rand::thread_rng().fill_bytes(&mut secret);

		let helper = BarkdHelper {
			name: name.as_ref().to_string(),
			datadir,
			ark_server_url,
			chain_source,
			_bitcoind: bitcoind,
			port: 0,
			auth_token: AuthToken::new(secret),
		};
		Daemon::wrap(helper)
	}

	pub fn base_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.inner.port)
	}

	fn client_config(&self) -> Configuration {
		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert(
			reqwest::header::AUTHORIZATION,
			reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.inner.auth_token.encode()))
				.expect("invalid auth token header value"),
		);

		let client = reqwest::Client::builder()
			.default_headers(headers)
			.build()
			.expect("failed to build reqwest client");

		Configuration {
			base_path: self.base_url(),
			client,
			..Configuration::default()
		}
	}

	/// Create the barkd wallet via REST. Call this once after the daemon has started.
	pub async fn create_wallet(&self) -> anyhow::Result<()> {
		let chain_source = match &self.inner.chain_source {
			BarkdChainSource::Esplora(url) => ChainSourceConfig::Esplora { url: url.clone() },
			BarkdChainSource::Bitcoind { url, cookie } => ChainSourceConfig::Bitcoind {
				bitcoind: url.clone(),
				bitcoind_auth: BitcoindAuth::Cookie {
					cookie: cookie.to_string_lossy().into_owned(),
				},
			},
		};

		let req = CreateWalletRequest {
			ark_server: self.inner.ark_server_url.clone(),
			chain_source,
			mnemonic: None,
			network: BarkNetwork::Regtest,
			birthday_height: None,
		};

		let config = self.client_config();
		wallet_api::create_wallet(&config, req).await
			.context("failed to create barkd wallet")?;
		Ok(())
	}

	/// Get a new on-chain receiving address from barkd.
	pub async fn onchain_address(&self) -> bitcoin::Address {
		let config = self.client_config();
		let addr: Address = onchain_api::onchain_address(&config).await
			.expect("failed to get barkd onchain address");
		addr.address.require_network(Network::Regtest).unwrap()
	}

	/// Ping the barkd REST server.
	pub async fn ping(&self) {
		let config = self.client_config();
		default_api::ping(&config).await
			.expect("barkd ping failed");
	}

	/// Query the chain source for the current best block height.
	pub async fn tip(&self) -> TipResponse {
		let config = self.client_config();
		bitcoin_api::tip(&config).await
			.expect("failed to get barkd tip")
	}

	/// Return whether the wallet is connected to the Ark server.
	pub async fn connected(&self) -> ConnectedResponse {
		let config = self.client_config();
		wallet_api::connected(&config).await
			.expect("failed to check barkd connection")
	}

	/// Return Ark server configuration parameters.
	pub async fn ark_info(&self) -> ArkInfo {
		let config = self.client_config();
		wallet_api::ark_info(&config).await
			.expect("failed to get barkd ark info")
	}

	/// Return the next scheduled Ark round start time.
	pub async fn next_round(&self) -> NextRoundStart {
		let config = self.client_config();
		wallet_api::next_round(&config).await
			.expect("failed to get barkd next round")
	}

	/// List UTXOs in the on-chain wallet without syncing first.
	pub async fn onchain_utxos(&self) -> Vec<UtxoInfo> {
		let config = self.client_config();
		onchain_api::onchain_utxos(&config).await
			.expect("failed to list barkd onchain utxos")
	}

	/// List transactions in the on-chain wallet without syncing first.
	pub async fn onchain_transactions(&self) -> Vec<TransactionInfo> {
		let config = self.client_config();
		onchain_api::onchain_transactions(&config).await
			.expect("failed to list barkd onchain transactions")
	}

	/// Sync the on-chain wallet, then return the balance.
	pub async fn onchain_balance(&self) -> Amount {
		let config = self.client_config();
		onchain_api::onchain_sync(&config).await
			.expect("failed to sync barkd onchain wallet");
		let balance: OnchainBalance = onchain_api::onchain_balance(&config).await
			.expect("failed to get barkd onchain balance");
		balance.total
	}

	/// Sync the wallet then return the bark (off-chain) balance.
	pub async fn bark_balance(&self) -> Balance {
		let config = self.client_config();
		wallet_api::sync(&config).await
			.expect("failed to sync barkd wallet");
		wallet_api::balance(&config).await
			.expect("failed to get barkd bark balance")
	}

	/// Sync the wallet state.
	pub async fn sync(&self) {
		let config = self.client_config();
		wallet_api::sync(&config).await
			.expect("failed to sync barkd wallet");
	}

	/// List VTXOs in the wallet.
	pub async fn vtxos(&self, all: Option<bool>) -> Vec<WalletVtxoInfo> {
		let config = self.client_config();
		wallet_api::vtxos(&config, all).await
			.expect("failed to list barkd vtxos")
	}

	/// Get a single VTXO by id.
	pub async fn get_vtxo(&self, id: &str) -> WalletVtxoInfo {
		let config = self.client_config();
		wallet_api::get_vtxo(&config, id).await
			.expect("failed to get barkd vtxo")
	}

	/// Get the hex-encoded serialization of a VTXO.
	pub async fn get_vtxo_encoded(&self, id: &str) -> EncodedVtxoResponse {
		let config = self.client_config();
		wallet_api::get_vtxo_encoded(&config, id).await
			.expect("failed to get encoded barkd vtxo")
	}

	/// Import VTXOs from hex-encoded strings.
	pub async fn import_vtxo(&self, vtxo_hexes: Vec<String>) -> Vec<WalletVtxoInfo> {
		let config = self.client_config();
		let req = bark_json::web::ImportVtxoRequest { vtxos: vtxo_hexes };
		wallet_api::import_vtxo(&config, req).await
			.expect("failed to import barkd vtxos")
	}

	/// Sync the on-chain wallet then board all funds into Ark.
	pub async fn board_all(&self) -> PendingBoardInfo {
		info!("{}: Boarding all on-chain funds via REST", self.name);
		let config = self.client_config();
		onchain_api::onchain_sync(&config).await
			.expect("failed to sync barkd onchain wallet before board_all");
		boards_api::board_all(&config).await
			.expect("barkd board_all failed")
	}
}

#[async_trait]
impl DaemonHelper for BarkdHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.datadir.clone()
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Barkd::base_cmd();

		if let Ok(nb) = env::var(BARK_TOKIO_WORKER_THREADS) {
			cmd.env("TOKIO_WORKER_THREADS", nb);
		}

		cmd.args([
			"--datadir", self.datadir.to_str().expect("non-UTF-8 datadir"),
			"--port", &self.port.to_string(),
			"--verbose",
		]);
		Ok(cmd)
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		self.port = portpicker::pick_unused_port().expect("No ports free");
		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		std::fs::create_dir_all(&self.datadir)?;
		std::fs::write(
			self.datadir.join(AUTH_TOKEN_FILE),
			self.auth_token.encode(),
		)?;
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		// `wait_for_init` is on `BarkdHelper`, not the `Barkd` type alias, so
		// `client_config()` is not available here. Construct the config inline.
		let config = Configuration {
			base_path: format!("http://127.0.0.1:{}", self.port),
			..Configuration::default()
		};
		loop {
			if default_api::ping(&config).await.is_ok() {
				return Ok(());
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}
