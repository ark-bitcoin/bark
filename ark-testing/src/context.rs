use std::path::PathBuf;
use std::time::Duration;

use bitcoin::{FeeRate, Network};
use tokio::fs;

use crate::util::test_data_directory;
use crate::daemon::log::FileLogger;
use crate::{
	Aspd, AspdConfig, Bitcoind, BitcoindConfig, Bark, BarkConfig, Lightningd, LightningdConfig,
};

pub struct TestContext {
	#[allow(dead_code)]
	pub name: String,
	pub datadir: PathBuf
}

impl TestContext {
	pub async fn new(name: impl AsRef<str>) -> Self {
		crate::util::init_logging().expect("Logging can be initialized");
		let datadir = test_data_directory().await.join(name.as_ref());

		if datadir.exists() {
			fs::remove_dir_all(&datadir).await.unwrap();
		}
		fs::create_dir_all(&datadir).await.unwrap();

		TestContext { name: name.as_ref().to_string(), datadir}
	}

	pub fn bitcoind_default_cfg(&self, name: impl AsRef<str>) -> BitcoindConfig {
		let datadir = self.datadir.join(name.as_ref());
		BitcoindConfig {
			datadir,
			txindex: true,
			network: Network::Regtest,
			fallback_fee: FeeRate::from_sat_per_vb(1).unwrap(),
			relay_fee: None,
		}
	}

	pub async fn bitcoind(&self, name: impl AsRef<str>) -> Bitcoind {
		self.bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn bitcoind_with_cfg(
		&self,
		name: impl AsRef<str>,
		cfg: BitcoindConfig,
	) -> Bitcoind {
		let mut ret = Bitcoind::new(name.as_ref().to_string(), cfg);
		ret.start().await.unwrap();
		ret
	}

	pub async fn aspd_with_cfg(&self, name: impl AsRef<str>, cfg: AspdConfig) -> Aspd {
		let datadir = self.datadir.join(name.as_ref());

		let mut ret = Aspd::new(name, cfg);
		ret.add_stdout_handler(FileLogger::new(datadir.join("stdout.log"))).unwrap();

		ret.start().await.unwrap();
		ret
	}

	pub async fn aspd_default_cfg(
		&self,
		name: impl AsRef<str>,
		bitcoind: &Bitcoind,
		lightningd: Option<&Lightningd>,
	) -> AspdConfig {
		let datadir = self.datadir.join(name.as_ref());
		let mut aspd_config = AspdConfig {
			datadir: datadir.clone(),
			bitcoind_url: bitcoind.rpc_url(),
			bitcoind_cookie: bitcoind.rpc_cookie(),
			round_interval: Duration::from_millis(500),
			round_submit_time: Duration::from_millis(500),
			round_sign_time: Duration::from_millis(500),
			nb_round_nonces: 100,
			cln_grpc_uri: None,
			cln_grpc_server_cert_path: None,
			cln_grpc_client_cert_path: None,
			cln_grpc_client_key_path: None,
		};

		if lightningd.is_some() {
			aspd_config.configure_lighting(lightningd.unwrap()).await;
		};

		aspd_config
	}

	pub async fn aspd(
		&self,
		name: impl AsRef<str>,
		bitcoind: &Bitcoind,
		lightningd: Option<&Lightningd>,
	) -> Aspd {
		let name = name.as_ref();
		self.aspd_with_cfg(name, self.aspd_default_cfg(name, bitcoind, lightningd).await).await
	}

	pub async fn try_bark(
		&self,
		name: impl AsRef<str>,
		bitcoind: &Bitcoind,
		aspd: &Aspd,
	) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());
		let asp_url = aspd.asp_url();

		let cfg = BarkConfig {
			datadir,
			asp_url,
			bitcoind_url: bitcoind.rpc_url(),
			bitcoind_cookie: bitcoind.rpc_cookie(),
			network: String::from("regtest"),
		};
		Bark::try_new(name, cfg).await
	}

	pub async fn bark(&self, name: impl AsRef<str>, bitcoind: &Bitcoind, aspd: &Aspd) -> Bark {
		self.try_bark(name, &bitcoind, &aspd).await.unwrap()
	}

	pub async fn lightningd(&self, name: impl AsRef<str>, bitcoind: &Bitcoind) -> Lightningd {
		let datadir = self.datadir.join(name.as_ref());

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: datadir.clone()
		};

		let mut ret = Lightningd::new(name, cfg);
		ret.add_stdout_handler(FileLogger::new(datadir.join("stdout.log"))).unwrap();
		ret.start().await.unwrap();
		ret
	}
}



impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("Textcontext: Datadir is located at {:?}", self.datadir);
	}
}
