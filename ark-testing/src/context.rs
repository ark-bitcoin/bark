use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use bitcoin::{Amount, FeeRate, Network, Txid};
use bitcoincore_rpc::RpcApi;
use log::info;
use tokio::fs;
use tonic::transport::Uri;

use aspd::config::{self, Config};
use aspd_rpc as rpc;

use crate::daemon::aspd::postgresd::{self, Postgres};
use crate::util::{should_use_electrs, test_data_directory, FutureExt};
use crate::{
	constants, Aspd, Bitcoind, BitcoindConfig, Bark, BarkConfig, Electrs, ElectrsConfig,
	Lightningd, LightningdConfig,
};

pub trait ToAspUrl {
	fn asp_url(&self) -> String;
}
impl ToAspUrl for Aspd {
	fn asp_url(&self) -> String { self.asp_url() }
}
impl ToAspUrl for String {
	fn asp_url(&self) -> String { self.clone() }
}
impl ToAspUrl for str {
	fn asp_url(&self) -> String { self.to_owned() }
}

pub struct TestContext {
	#[allow(dead_code)]
	pub name: String,
	pub datadir: PathBuf,

	pub bitcoind: Option<Bitcoind>,

	// use a central Electrs for the Esplora API if necessary
	pub electrs: Option<Electrs>,

	// ensures postgres daemon, if any, stays alive the TestContext's lifetime
	pub postgres_config: Option<config::Postgres>,
	_postgresd: Option<Postgres>,
}

impl TestContext {
	pub async fn new_minimal(name: impl AsRef<str>) -> Self {
		crate::util::init_logging().expect("Logging can be initialized");

		let name = name.as_ref();
		let datadir = test_data_directory().await.join(name);

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		TestContext {
			name: name.to_string(),
			datadir,
			bitcoind: None,
			electrs: None,
			_postgresd: None,
			postgres_config: None,
		}
	}

	pub async fn new(name: impl AsRef<str>) -> Self {
		let mut ctx = Self::new_minimal(name).await;

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
		let electrs = if should_use_electrs() {
			let cfg = ElectrsConfig {
				network: Network::Regtest,
				bitcoin_dir: self.bitcoind().datadir(),
				bitcoin_rpc_port: self.bitcoind().rpc_port(),
				bitcoin_zmq_port: self.bitcoind().zmq_port(),
				electrs_dir: self.datadir.join("electrs"),
			};
			let mut electrs = Electrs::new(&self.name, cfg);
			electrs.start().await.unwrap();
			Some(electrs)
		} else {
			None
		};

		self.electrs = electrs;
		self.await_block_count_sync().await
	}

	pub async fn init_central_postgres(&mut self) -> config::Postgres {
		let (postgres_config, postgresd) = if postgresd::use_host_database() {
			postgresd::cleanup_dbs(&postgresd::global_client().await, &self.name).await;
			let mut cfg = postgresd::host_base_config();
			cfg.name = self.name.clone();
			(cfg, None)
		} else {
			let postgresd = self.new_postgres("central_postgres").await;
			(postgresd.helper().into_config(&self.name), Some(postgresd))
		};


		self._postgresd = postgresd;
		self.postgres_config = Some(postgres_config.clone());
		postgres_config
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

	pub async fn new_postgres(&self, name: &str) -> Postgres {
		let datadir = self.datadir.join(name);
		let mut ret = Postgres::new(name, datadir);
		ret.start().await.unwrap();
		ret
	}

	async fn aspd_default_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Config {
		let name = name.as_ref();
		let data_dir = self.datadir.join(name);

		let cln_array = if let Some(lnd) = lightningd {
			let grpc_details = lnd.grpc_details().await;

			let lightningd = config::Lightningd {
				uri: Uri::from_str(&grpc_details.uri).expect("failed to parse cln grpc uri"),
				priority: 1,
				server_cert_path: grpc_details.server_cert_path,
				client_cert_path: grpc_details.client_cert_path,
				client_key_path: grpc_details.client_key_path,
			};

			let mut cln_array = Vec::new();
			cln_array.push(lightningd);

			cln_array
		} else {
			Vec::new()
		};


		// NB we don't auto-complete `..Default::default()` here
		// to force us to evaluate every value in test context.
		Config {
			data_dir: data_dir.clone(),
			log_dir: Some(data_dir),
			network: Network::Regtest,
			vtxo_expiry_delta: 144,
			vtxo_exit_delta: 12,
			htlc_delta: 6,
			htlc_expiry_delta: 6,
			round_interval: Duration::from_millis(500),
			round_submit_time: Duration::from_millis(500),
			round_sign_time: Duration::from_millis(500),
			nb_round_nonces: 64,
			round_tx_feerate: FeeRate::from_sat_per_vb_unchecked(10),
			round_board_confirmations: constants::BOARD_CONFIRMATIONS as usize,
			round_tx_untrusted_input_confirmations: 1,
			max_vtxo_amount: None,
			rpc_rich_errors: true,
			txindex_check_interval: Duration::from_millis(500),
			handshake_psa: None,
			otel_collector_endpoint: None,
			vtxo_sweeper: aspd::sweeps::Config {
				sweep_tx_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(10),
				round_sweep_interval: Duration::from_secs(60),
				sweep_threshold: Amount::from_sat(1_000_000),
			},
			forfeit_watcher: aspd::forfeits::Config {
				claim_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(25),
				wake_interval: Duration::from_millis(1_000),
			},
			forfeit_watcher_min_balance: Amount::from_sat(1_000_000),
			rpc: config::Rpc {
				// these will be overwritten on start, but can't be empty
				public_address: SocketAddr::from_str("127.0.0.1:3535").unwrap(),
				admin_address: None,
			},
			bitcoind: config::Bitcoind {
				// these will be overwritten on start, but can't be empty
				url: "".into(),
				cookie: None,
				rpc_user: None,
				rpc_pass: None,
			},
			postgres: self.postgres_config.clone().expect("postgres config not set"),
			cln_array,
			cln_reconnect_interval: Duration::from_secs(10),
			invoice_check_interval: Duration::from_secs(3),
			invoice_recheck_delay: Duration::from_secs(2),
			invoice_check_base_delay: Duration::from_secs(2),
			invoice_check_max_delay: Duration::from_secs(10),
			invoice_poll_interval: Duration::from_secs(10),
			legacy_wallet: false,
		}
	}

	pub async fn new_aspd_with_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		mod_cfg: impl FnOnce(&mut aspd::Config),
	) -> Aspd {
		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;
		let mut cfg = self.aspd_default_cfg(name.as_ref(), lightningd).await;
		mod_cfg(&mut cfg);

		assert_eq!("", cfg.bitcoind.url, "bitcoind url already set");
		cfg.bitcoind.url = bitcoind.rpc_url();

		// We allow some tests to set custom bitcoind auth
		if cfg.bitcoind.cookie.is_none() && cfg.bitcoind.rpc_user.is_none() {
			cfg.bitcoind.cookie = Some(bitcoind.rpc_cookie());
		}

		let mut ret = Aspd::new(name, bitcoind, cfg);
		ret.start().await.unwrap();

		ret
	}

	/// Creates new aspd without any funds.
	pub async fn new_aspd(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Aspd {
		self.new_aspd_with_cfg(name, lightningd, |_| {}).await
	}

	/// Creates new aspd and immediately funds it. Waits until the aspd's bitcoind
	/// receives funding transaction.
	pub async fn new_aspd_with_funds(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
		amount: Amount
	) -> Aspd {
		let asp = self.new_aspd(name, lightningd).await;
		let _txid = self.fund_asp(&asp, amount).await;
		asp
	}

	pub async fn try_new_bark_with_create_args<T: AsRef<str>>(
		&self,
		name: impl AsRef<str>,
		aspd: &dyn ToAspUrl,
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
			asp_url: aspd.asp_url(),
			network: Network::Regtest,
			chain_source,
			extra_create_args: extra_create_args.into_iter()
				.map(|s| s.as_ref().to_owned())
				.collect(),
		};
		Bark::try_new(name, bitcoind, cfg).await
	}

	pub async fn try_new_bark(
		&self,
		name: impl AsRef<str>,
		aspd: &dyn ToAspUrl,
	) -> anyhow::Result<Bark> {
		self.try_new_bark_with_create_args::<&str>(name, aspd, []).await
	}

	/// Creates new bark without any funds.
	pub async fn new_bark(&self, name: impl AsRef<str>, aspd: &dyn ToAspUrl) -> Bark {
		self.try_new_bark(name, aspd).await.unwrap()
	}

	/// Creates new bark and immediately funds it. Waits until the bark's bitcoind
	/// receives funding transaction.
	pub async fn new_bark_with_funds(&self, name: impl AsRef<str>, aspd: &dyn ToAspUrl, amount: Amount) -> Bark {
		let bark = self.try_new_bark(name, aspd).await.unwrap();
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

	pub async fn fund_asp(&self, asp: &Aspd, amount: Amount) {
		info!("Fund {} {}", asp.name, amount);
		let rounds_address = asp.get_rounds_funding_address().await;
		self.bitcoind().fund_addr(rounds_address, amount).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		self.bitcoind().generate(1).await;
		tokio::time::sleep(Duration::from_millis(1000)).await;
		asp.get_admin_client().await.wallet_sync(rpc::protos::Empty {}).await
			.expect("error calling wallet status after funding aspd");
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
				log::info!("Cleaning up {:?} because test passed and {} is set", self.datadir, crate::constants::env::CLEAN_SUCCESSFUL_TESTS);
				std::fs::remove_dir_all(&self.datadir).unwrap();
			} else {
				log::info!("Leave test-directory intact because {} is not set", crate::constants::env::CLEAN_SUCCESSFUL_TESTS);
			}
		}
	}
}
