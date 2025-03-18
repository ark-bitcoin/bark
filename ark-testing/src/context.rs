use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};
use bitcoin::{Amount, FeeRate, Network, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use tokio::fs;
use tonic::transport::Uri;

use aspd::config::{self, Config};

use crate::daemon::aspd::postgresd::{self, Postgres};
use crate::util::{should_use_electrs, test_data_directory};
use crate::{
	constants, Aspd, Bitcoind, BitcoindConfig, Bark, BarkConfig, Electrs, ElectrsConfig,
	Lightningd, LightningdConfig,
};
use crate::bark::ChainSource;

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

	pub bitcoind: Bitcoind,

	// use a central Electrs for the Esplora API if necessary
	pub electrs: Option<Electrs>,

	// ensures postgres daemon, if any, stays alive the TestContext's lifetime
	_postgresd: Option<Postgres>,
	postgres_config: config::Postgres,
}

impl TestContext {
	pub async fn new(name: impl AsRef<str>) -> Self {
		crate::util::init_logging().expect("Logging can be initialized");

		let name = name.as_ref();
		let datadir = test_data_directory().await.join(name);

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		let bitcoind = {
			let mut bitcoind = Bitcoind::new(
				"bitcoind".to_string(),
				BitcoindConfig {
					datadir: datadir.join("bitcoind"),
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

		let electrs = if should_use_electrs() {
			let cfg = ElectrsConfig {
				network: Network::Regtest,
				bitcoin_dir: bitcoind.datadir(),
				bitcoin_rpc_port: bitcoind.rpc_port(),
				bitcoin_zmq_port: bitcoind.zmq_port(),
				electrs_dir: datadir.join("electrs"),
			};
			let mut electrs = Electrs::new(name, cfg);
			electrs.start().await.unwrap();
			Some(electrs)
		} else {
			None
		};

		let (postgres_config, postgresd) = if postgresd::use_host_database() {
			postgresd::cleanup_dbs(&postgresd::global_client().await, name).await;
			let cfg = postgresd::host_base_config();
			(cfg, None)
		} else {
			let postgresd = Self::new_postgres("postgres", datadir.join("postgres")).await;
			(postgresd.helper().as_base_config(), Some(postgresd))
		};

		TestContext {
			name: name.to_string(),
			datadir,
			bitcoind,
			electrs,

			postgres_config,
			_postgresd: postgresd,
		}
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

	pub async fn new_bitcoind(&self, name: impl AsRef<str>) -> Bitcoind {
		self.new_bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn new_bitcoind_with_cfg(&self, name: impl AsRef<str>, cfg: BitcoindConfig) -> Bitcoind {
		let wallet = cfg.wallet;
		let mut bitcoind = Bitcoind::new(name.as_ref().to_string(), cfg, Some(self.bitcoind.p2p_url()));
		bitcoind.start().await.unwrap();
		if wallet {
			bitcoind.init_wallet().await;
		}
		bitcoind
	}

	async fn new_postgres(name: &str, datadir: PathBuf) -> Postgres {
		let mut ret = Postgres::new(name, datadir);
		ret.start().await.unwrap();
		ret
	}

	fn postgres_default_cfg(&self, name: impl AsRef<str>) -> config::Postgres {
		config::Postgres {
			name: format!("{}/{}", &self.name, name.as_ref()),
			..self.postgres_config.clone()
		}
	}

	pub async fn aspd_default_cfg(
		&self,
		name: impl AsRef<str>,
		lightningd: Option<&Lightningd>,
	) -> Config {
		let name = name.as_ref();
		let data_dir = self.datadir.join(name);

		let lightningd = if let Some(lnd) = lightningd {
			let grpc_details = lnd.grpc_details().await;
			Some(config::Lightningd {
				uri: Uri::from_str(&grpc_details.uri).expect("failed to parse cln grpc uri"),
				server_cert_path: grpc_details.server_cert_path,
				client_cert_path: grpc_details.client_cert_path,
				client_key_path: grpc_details.client_key_path,
			})
		} else {
			None
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
			sweep_tx_fallback_feerate: FeeRate::from_sat_per_vb_unchecked(10),
			round_sweep_interval: Duration::from_secs(60),
			sweep_threshold: Amount::from_sat(1_000_000),
			round_onboard_confirmations: constants::ONBOARD_CONFIRMATIONS as usize,
			max_vtxo_amount: None,
			rpc_rich_errors: true,
			txindex_check_interval: Duration::from_millis(800),
			otel_collector_endpoint: None,
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
			postgres: self.postgres_default_cfg(name),
			lightningd,
		}
	}

	pub async fn new_aspd_with_cfg(&self, name: impl AsRef<str>, mut cfg: Config) -> Aspd {
		let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;

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
		let cfg = self.aspd_default_cfg(name.as_ref(), lightningd).await;
		self.new_aspd_with_cfg(name, cfg).await
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

	pub async fn try_new_bark(
		&self,
		name: impl AsRef<str>,
		aspd: &dyn ToAspUrl,
	) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());

		let (bitcoind, chain_source) = if let Some(ref electrs) = self.electrs {
			(None, ChainSource::Esplora { url: electrs.rest_url() })
		} else {
			let bitcoind = self.new_bitcoind(format!("{}_bitcoind", name.as_ref())).await;
			(Some(bitcoind), ChainSource::Bitcoind)
		};
		let cfg = BarkConfig {
			datadir,
			asp_url: aspd.asp_url(),
			network: Network::Regtest,
			chain_source,
		};
		Bark::try_new(name, bitcoind, cfg).await
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
		ret
	}

	pub async fn fund_asp(&self, asp: &Aspd, amount: Amount) -> Txid {
		info!("Fund {} {}", asp.name, amount);
		let address = asp.get_funding_address().await;
		let txid = self.bitcoind.fund_addr(address, amount).await;
		self.bitcoind.generate(1).await;
		asp.get_admin_client().await.wallet_status(aspd_rpc::Empty {}).await
			.expect("error calling wallet status after funding apsd");
		txid
	}

	/// Send `amount` to an onchain address of this Bark client.
	pub async fn fund_bark(&self, bark: &Bark, amount: Amount) -> Txid {
		info!("Fund {} {}", bark.name(), amount);
		let address = bark.get_onchain_address().await;
		let txid = self.bitcoind.fund_addr(address, amount).await;
		self.bitcoind.generate(1).await;
		txid
	}

	pub async fn fund_lightning(&self, lightning: &Lightningd, amount: Amount) -> Txid {
		info!("Fund {} {}", lightning.name, amount);
		let address = lightning.get_onchain_address().await;

		let client = self.bitcoind.sync_client();
		client.send_to_address(
			&address, amount, None, None, None, None, None, None,
		).unwrap()
	}

	pub async fn await_transaction(&self, txid: &Txid) -> Transaction {
		let client = self.bitcoind.sync_client();
		let start = Instant::now();
		while Instant::now().duration_since(start).as_millis() < 30_000 {
			if let Ok(result) = client.get_raw_transaction(&txid, None) {
				return result;
			} else {
				tokio::time::sleep(Duration::from_millis(200)).await;
			}
		}
		panic!("Failed to get raw transaction: {}", txid);
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("TestContext: Datadir is located at {:?}", self.datadir);
	}
}
