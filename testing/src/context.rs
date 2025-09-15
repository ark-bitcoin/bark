use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::{Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::RpcApi;
use log::info;
use server::vtxopool::VtxoTarget;
use server::Server;
use tokio::fs;
use tonic::transport::Uri;

use server::config::{self, Config, HodlInvoiceClnPlugin};
use server_rpc as rpc;

use crate::daemon::captaind::proxy::ArkRpcProxyServer;
use crate::postgres::{self, PostgresDatabaseManager};
use crate::util::{
	get_bark_chain_source_from_env, test_data_directory, FutureExt, TestContextChainSource,
};
use crate::{
	btc, constants, sat, Bark, BarkConfig, Bitcoind, BitcoindConfig, Captaind, Electrs, ElectrsConfig, Lightningd, LightningdConfig
};

pub trait ToArkUrl {
	fn ark_url(&self) -> String;
}
impl ToArkUrl for Captaind {
	fn ark_url(&self) -> String { self.ark_url() }
}
impl ToArkUrl for String {
	fn ark_url(&self) -> String { self.clone() }
}
impl ToArkUrl for str {
	fn ark_url(&self) -> String { self.to_owned() }
}
impl ToArkUrl for ArkRpcProxyServer {
	fn ark_url(&self) -> String { self.address.clone() }
}

pub struct TestContext {
	pub test_name: String,
	pub datadir: PathBuf,

	pub bitcoind: Option<Bitcoind>,

	// use a central Electrs for the Esplora and mempool.space API if necessary
	pub electrs: Option<Electrs>,

	// ensures postgres daemon, if any, stays alive the TestContext's lifetime
	postgres_manager: Option<postgres::PostgresDatabaseManager>,
}

impl TestContext {
	pub async fn new_minimal(test_name: impl AsRef<str>) -> Self {
		crate::util::init_logging();

		let test_name = test_name.as_ref().to_owned();
		let datadir = test_data_directory().await.join(&test_name);

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		TestContext {
			test_name,
			datadir,
			bitcoind: None,
			electrs: None,
			postgres_manager: None,
		}
	}

	pub async fn new(test_name: impl AsRef<str>) -> Self {
		let mut ctx = Self::new_minimal(test_name).await;

		ctx.init_central_bitcoind().await;
		ctx.init_central_electrs().await;
		ctx.init_central_postgres().await;

		ctx
	}

	pub fn bitcoind_default_cfg(&self, name: impl AsRef<str>) -> BitcoindConfig {
		let datadir = self.datadir.join(name.as_ref());
		BitcoindConfig {
			datadir,
			wallet: false,
			txindex: true,
			network: Network::Regtest,
			fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
			relay_fee: None,
		}
	}

	pub async fn init_central_bitcoind(&mut self) {
		let bitcoind = {
			let mut bitcoind = Bitcoind::new(
				"bitcoind".to_string(),
				BitcoindConfig {
					datadir: self.datadir.join("bitcoind"),
					wallet: true,
					txindex: true,
					network: Network::Regtest,
					fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
					relay_fee: None,
				},
				None
			);
			bitcoind.start().await.unwrap();
			bitcoind
		};

		bitcoind.init_wallet().await;
		bitcoind.prepare_funds().await;

		self.bitcoind = Some(bitcoind);
	}

	pub async fn init_central_electrs(&mut self) {
		let electrs = match get_bark_chain_source_from_env() {
			TestContextChainSource::BitcoinCore => None,
			TestContextChainSource::ElectrsRest(electrs_type) => {
				let cfg = ElectrsConfig {
					network: Network::Regtest,
					bitcoin_dir: self.bitcoind().datadir(),
					bitcoin_rpc_port: self.bitcoind().rpc_port(),
					bitcoin_zmq_port: self.bitcoind().zmq_port(),
					electrs_dir: self.datadir.join("electrs"),
				};
				let mut electrs = Electrs::new(&self.test_name, cfg, electrs_type);
				electrs.start().await.unwrap();
				Some(electrs)
			},
		};

		self.electrs = electrs;
		self.await_block_count_sync().await
	}

	pub fn postgres_manager(&self) -> &PostgresDatabaseManager {
		self.postgres_manager.as_ref().unwrap()
	}

	pub async fn init_central_postgres(&mut self) {
		if self.postgres_manager.is_none() {
			let datadir = self.datadir.join("central_postgres");
			self.postgres_manager = Some(PostgresDatabaseManager::init(datadir).await);
		}
	}

	/// Returns the `Bitcoind` which is central to this `TextContext`
	/// Will panic if no central `BitcoinD` is present
	pub fn bitcoind(&self) -> &Bitcoind {
		self.bitcoind.as_ref()
			.expect("The central bitcoind hasn't been initialized. Call init_central_bitcoind first")
	}

	pub async fn new_bitcoind(&self, name: impl AsRef<str>) -> Bitcoind {
		self.new_bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn new_bitcoind_with_cfg(&self, name: impl AsRef<str>, cfg: BitcoindConfig) -> Bitcoind {
		let wallet = cfg.wallet;
		let mut bitcoind = Bitcoind::new(name.as_ref().to_string(), cfg, Some(self.bitcoind().p2p_url()));
		bitcoind.start().await.unwrap();
		if wallet {
			bitcoind.init_wallet().await;
		}
		bitcoind
	}

	pub async fn new_postgres(&self, db_name: &str) -> server::config::Postgres {
		self.postgres_manager.as_ref().unwrap()
			.request_database(db_name).await
	}

	async fn captaind_default_cfg(
		&self,
		name: impl AsRef<str>,
		bitcoind: &Bitcoind,
		lightningd: Option<&Lightningd>,
	) -> Config {
		let name = name.as_ref();
		let data_dir = self.datadir.join(name);

		let cln_array = if let Some(lnd) = lightningd {
			let grpc_details = lnd.grpc_details().await;
			let hodl_details = lnd.hodl_details().await;

			let lightningd = config::Lightningd {
				uri: Uri::from_str(&grpc_details.uri).expect("failed to parse cln grpc uri"),
				priority: 1,
				server_cert_path: grpc_details.server_cert_path,
				client_cert_path: grpc_details.client_cert_path,
				client_key_path: grpc_details.client_key_path,
				hodl_invoice: Some(HodlInvoiceClnPlugin {
					uri: Uri::from_str(&hodl_details.uri).expect("failed to parse hodl plugin uri"),
					server_cert_path: hodl_details.server_cert_path,
					client_cert_path: hodl_details.client_cert_path,
					client_key_path: hodl_details.client_key_path,
				})
			};

			let mut cln_array = Vec::new();
			cln_array.push(lightningd);

			cln_array
		} else {
			Vec::new()
		};

		// Create a new postgres database with the name of the test and database
		let db_name = format!("{}/{}", self.test_name, name);
		let postgres_cfg = self.new_postgres(&db_name).await;

		// NB we don't auto-complete `..Default::default()` here
		// to force us to evaluate every value in test context.
		Config {
			data_dir: data_dir.clone(),
			network: Network::Regtest,
			vtxo_lifetime: 144,
			vtxo_exit_delta: 12,
			htlc_expiry_delta: 6,
			round_interval: Duration::from_millis(1000),
			round_submit_time: Duration::from_millis(1000),
			round_sign_time: Duration::from_millis(2500),
			nb_round_nonces: 64,
			round_tx_feerate: FeeRate::from_sat_per_vb_unchecked(10),
			required_board_confirmations: constants::BOARD_CONFIRMATIONS as usize,
			round_tx_untrusted_input_confirmations: 1,
			max_vtxo_amount: None,
			max_arkoor_depth: 5,
			rpc_rich_errors: true,
			txindex_check_interval: Duration::from_millis(500),
			handshake_psa: None,
			otel_collector_endpoint: None,
			otel_tracing_sampler: None,
			vtxo_sweeper: server::sweeps::Config {
				sweep_tx_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(10),
				round_sweep_interval: Duration::from_secs(60),
				sweep_threshold: Amount::from_sat(1_000_000),
			},
			forfeit_watcher: server::forfeits::Config {
				claim_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(25),
				wake_interval: Duration::from_millis(1_000),
			},
			forfeit_watcher_min_balance: Amount::from_sat(1_000_000),
			vtxopool: server::vtxopool::Config {
				vtxo_targets: vec![
					VtxoTarget { count: 3, amount: sat(10_000) },
					VtxoTarget { count: 3, amount: btc(1) },
				],
				vtxo_target_issue_threshold: 50,
				vtxo_lifetime: 144 / 2,
				vtxo_pre_expiry: 12,
				vtxo_max_arkoor_depth: 3,
				issue_tx_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(1),
				issue_interval: Duration::from_secs(3),
			},
			transaction_rebroadcast_interval: std::time::Duration::from_secs(2),
			rpc: config::Rpc {
				// these will be overwritten on start, but can't be empty
				public_address: SocketAddr::from_str("127.0.0.1:3535").unwrap(),
				admin_address: None,
				integration_address: None,
			},
			bitcoind: config::Bitcoind {
				url: bitcoind.rpc_url(),
				cookie: Some(bitcoind.rpc_cookie()),
				rpc_user: None,
				rpc_pass: None,
			},
			postgres: postgres_cfg,
			cln_array,
			cln_reconnect_interval: Duration::from_secs(10),
			invoice_check_interval: Duration::from_secs(3),
			invoice_recheck_delay: Duration::from_secs(2),
			invoice_check_base_delay: Duration::from_secs(2),
			invoice_check_max_delay: Duration::from_secs(10),
			invoice_poll_interval: Duration::from_secs(10),
			htlc_subscription_timeout: Duration::from_secs(10*60),
		}
	}

	pub async fn new_captaind_with_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		mod_cfg: impl FnOnce(&mut server::Config),
	) -> Captaind {
		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;
		let mut cfg = self.captaind_default_cfg(name.as_ref(), &bitcoind, lightningd).await;
		mod_cfg(&mut cfg);

		let mut ret = Captaind::new(name, bitcoind, cfg);
		ret.start().await.unwrap();

		ret
	}

	/// Creates new captaind without any funds.
	pub async fn new_captaind(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Captaind {
		self.new_captaind_with_cfg(name, lightningd, |_| {}).await
	}

	/// Creates new captaind and immediately funds it. Waits until the captaind's bitcoind
	/// receives funding transaction.
	pub async fn new_captaind_with_funds(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		amount: Amount
	) -> Captaind {
		let srv = self.new_captaind(name, lightningd).await;
		let _txid = self.fund_captaind(&srv, amount).await;
		srv
	}

	pub async fn new_server_with_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		mod_cfg: impl FnOnce(&mut server::Config),
	) -> Arc<Server> {
		// using context bitcoind because we don't have a place to store the bitcoind
		let mut cfg = self.captaind_default_cfg(name.as_ref(), self.bitcoind(), lightningd).await;
		mod_cfg(&mut cfg);

		Server::create(cfg.clone()).await.expect("error creating server");
		Server::start(cfg).await.expect("error starting server")
	}

	pub async fn try_new_bark_with_create_args<T: AsRef<str>>(
		&self,
		name: impl AsRef<str>,
		srv: &dyn ToArkUrl,
		fallback_fee_override: Option<FeeRate>,
		extra_create_args: impl IntoIterator<Item = T>,
	) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());

		let (bitcoind, chain_source) = if let Some(ref electrs) = self.electrs {
			(None, electrs.chain_source())
		} else {
			let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;
			let chain_source = bitcoind.chain_source();
			(Some(bitcoind), chain_source)
		};
		let cfg = BarkConfig {
			datadir,
			ark_url: srv.ark_url(),
			network: Network::Regtest,
			chain_source,
			fallback_fee: fallback_fee_override.unwrap_or(FeeRate::from_sat_per_vb(5).unwrap()),
			extra_create_args: extra_create_args.into_iter()
				.map(|s| s.as_ref().to_owned())
				.collect(),
		};
		Bark::try_new(name, bitcoind, cfg).await
	}

	pub async fn try_new_bark(
		&self,
		name: impl AsRef<str>,
		srv: &dyn ToArkUrl,
	) -> anyhow::Result<Bark> {
		self.try_new_bark_with_create_args::<&str>(name, srv, None, []).await
	}

	/// Creates new bark without any funds.
	pub async fn new_bark(&self, name: impl AsRef<str>, srv: &dyn ToArkUrl) -> Bark {
		self.try_new_bark(name, srv).await.unwrap()
	}

	/// Creates new bark and immediately funds it. Waits until the bark's bitcoind
	/// receives funding transaction.
	pub async fn new_bark_with_funds(&self, name: impl AsRef<str>, srv: &dyn ToArkUrl, amount: Amount) -> Bark {
		let bark = self.try_new_bark(name, srv).await.unwrap();
		let _txid = self.fund_bark(&bark, amount).await;
		bark
	}

	pub async fn new_lightningd(&self, name: impl AsRef<str>) -> Lightningd {
		let datadir = self.datadir.join(name.as_ref());

		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: datadir.clone()
		};

		let mut ret = Lightningd::new(name, bitcoind, cfg);
		ret.start().await.unwrap();
		// wait for grpc to be available
		async {
			loop {
				if ret.try_grpc_client().await.is_ok() {
					break;
				} else {
					tokio::time::sleep(Duration::from_millis(200)).await;
				}
			}
		}.wait(5000).await;
		ret
	}

	pub async fn fund_captaind(&self, srv: &Captaind, amount: Amount) {
		info!("Fund {} {}", srv.name, amount);
		let rounds_address = srv.get_rounds_funding_address().await;
		self.bitcoind().fund_addr(rounds_address, amount).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		self.bitcoind().generate(1).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		srv.get_wallet_rpc().await.wallet_sync(rpc::protos::Empty {}).await
			.expect("error calling wallet status after funding server");
	}

	/// Send `amount` to an onchain address of this Bark client.
	pub async fn fund_bark(&self, bark: &Bark, amount: Amount) -> Txid {
		info!("Fund {} {}", bark.name(), amount);
		let address = bark.get_onchain_address().await;
		let txid = self.bitcoind().fund_addr(address, amount).await;
		self.bitcoind().generate(1).await;
		self.await_block_count_sync().await;
		txid
	}

	pub async fn fund_lightning(&self, lightning: &Lightningd, amount: Amount) -> Txid {
		info!("Fund {} {}", lightning.name, amount);
		let address = lightning.get_onchain_address().await;

		let client = self.bitcoind().sync_client();
		client.send_to_address(
			&address, amount, None, None, None, None, None, None,
		).unwrap()
	}

	/// If both bitcoind and electrs are available, this will wait until their tips are equal
	pub async fn await_block_count_sync(&self) {
		match (self.bitcoind.as_ref(), self.electrs.as_ref()) {
			(Some(bitcoind), Some(electrs)) => {
				while bitcoind.get_block_count().await != (electrs.get_block_count().await as u64) {
					tokio::time::sleep(Duration::from_millis(100)).await;
				}
			},
			_ => {}
		}
	}

	/// Waits for the given transaction ID to be available in both the central bitcoind and electrs
	pub async fn await_transaction(&self, txid: &Txid) {
		if let Some(bitcoind) = &self.bitcoind {
			bitcoind.await_transaction(txid).await;
		}
		if let Some(electrs) = &self.electrs {
			electrs.await_transaction(txid).await;
		}
	}

	/// Waits for the given transaction ID to be available in the central bitcoin and electrs, as
	/// well as each given bitcoin node.
	pub async fn await_transaction_across_nodes(
		&self,
		txid: Txid,
		nodes: impl IntoIterator<Item = &Bitcoind>,
	) {
		self.await_transaction(&txid).await;
		for bitcoind in nodes {
			bitcoind.await_transaction(&txid).await;
		}
	}

	/// Generated a block using the central bitcoind and ensures that electrs is synced with it
	pub async fn generate_blocks(&self, block_num: u32) {
		// Give transactions time to propagate
		tokio::time::sleep(Duration::from_millis(1000)).await;

		self.bitcoind().generate(block_num).await;

		// Give blocks time to propagate
		let now = Instant::now();
		const MIN_WAIT: Duration = Duration::from_millis(500);
		self.await_block_count_sync().await;
		if now.elapsed() < MIN_WAIT {
			tokio::time::sleep(MIN_WAIT - now.elapsed()).await;
		}
		info!("New chain tip: {}", self.bitcoind().get_block_count().await);
	}

	/// Generated a block using the central bitcoind without waiting for propagation
	pub async fn generate_blocks_unsynced(&self, block_num: u32) {
		self.bitcoind().generate(block_num).await;
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("TestContext: Datadir is located at {:?}", self.datadir);

		if std::thread::panicking() {
			log::info!("Leave test directory intact");
			// do nothing
		} else {
			if let Some(_) = std::env::var_os(crate::constants::env::CLEAN_SUCCESSFUL_TESTS) {
				log::info!("Cleaning up {:?} because test passed and {} is set",
					self.datadir, crate::constants::env::CLEAN_SUCCESSFUL_TESTS,
				);
				std::fs::remove_dir_all(&self.datadir).unwrap();
			} else {
				log::info!("Leave test-directory intact because {} is not set",
					crate::constants::env::CLEAN_SUCCESSFUL_TESTS,
				);
			}
		}
	}
}
