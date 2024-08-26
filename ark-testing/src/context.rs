use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::util::test_data_directory;
use crate::daemon::log::FileLogger;
use crate::{Aspd, AspdConfig, Bitcoind, BitcoindConfig, Bark, BarkConfig};

pub struct TestContext {
	#[allow(dead_code)]
	pub name: String,
	pub datadir: PathBuf
}

impl TestContext {
	pub fn new(name: impl AsRef<str>) -> Self {
		crate::util::init_logging().expect("Logging can be initialized");
		let datadir = test_data_directory().join(name.as_ref());

		if datadir.exists() {
			fs::remove_dir_all(&datadir).unwrap();
		}
		fs::create_dir_all(&datadir).unwrap();

		TestContext { name: name.as_ref().to_string(), datadir}
	}

	pub fn bitcoind_default_cfg(&self, name: impl AsRef<str>) -> BitcoindConfig {
		let datadir = self.datadir.join(name.as_ref());
		BitcoindConfig {
			datadir,
			txindex: true,
			network: String::from("regtest"),
			..BitcoindConfig::default()
		}
	}

	pub async fn bitcoind(&self, name: impl AsRef<str>) -> anyhow::Result<Bitcoind> {
		self.bitcoind_with_cfg(name.as_ref(), self.bitcoind_default_cfg(name.as_ref())).await
	}

	pub async fn bitcoind_with_cfg(
		&self,
		name: impl AsRef<str>,
		cfg: BitcoindConfig,
	) -> anyhow::Result<Bitcoind> {
		let mut bitcoind = Bitcoind::new(name.as_ref().to_string(), cfg);
		bitcoind.start().await?;
		Ok(bitcoind)
	}

	pub async fn aspd_with_cfg(&self, name: impl AsRef<str>, cfg: AspdConfig) -> anyhow::Result<Aspd> {
		let datadir = self.datadir.join(name.as_ref());

		let mut aspd = Aspd::new(name, cfg);
		aspd.add_stdout_handler(FileLogger::new(datadir.join("stdout.log")))?;
		aspd.add_stderr_handler(FileLogger::new(datadir.join("stderr.log")))?;

		aspd.start().await?;
		Ok(aspd)
	}

	pub fn aspd_default_cfg(&self, name: impl AsRef<str>, bitcoind: &Bitcoind) -> AspdConfig {
		let datadir = self.datadir.join(name.as_ref());
		AspdConfig {
			datadir: datadir.clone(),
			bitcoind_url: bitcoind.bitcoind_url(),
			bitcoind_cookie: bitcoind.bitcoind_cookie(),
			round_interval: Duration::from_millis(500),
			round_submit_time: Duration::from_millis(500),
			round_sign_time: Duration::from_millis(500),
			nb_round_nonces: 100,
		}
	}

	pub async fn aspd(&self, name: impl AsRef<str>, bitcoind: &Bitcoind) -> anyhow::Result<Aspd> {
		let name = name.as_ref();
		self.aspd_with_cfg(name, self.aspd_default_cfg(name, bitcoind)).await
	}


	pub async fn bark(&self, name: impl AsRef<str>, bitcoind: &Bitcoind, aspd: &Aspd) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());
		let asp_url = aspd.asp_url()?;

		let cfg = BarkConfig {
			datadir,
			asp_url,
			bitcoind_url: bitcoind.bitcoind_url(),
			bitcoind_cookie: bitcoind.bitcoind_cookie(),
			network: String::from("regtest")};
		Ok(Bark::new(name, cfg).await?)
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("Textcontext: Datadir is located at {:?}", self.datadir);
	}
}

