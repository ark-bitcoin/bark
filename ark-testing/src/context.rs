use std::path::PathBuf;
use std::fs;

use crate::util::test_data_directory;
use crate::daemon::bitcoind::bitcoind_exe_path;
use crate::daemon::log::FileLogger;
use crate::{AspD, AspDConfig, BitcoinD, BitcoinDConfig, Bark, BarkConfig};

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

	pub async fn bitcoind(&self, name: impl AsRef<str>) -> anyhow::Result<BitcoinD> {
		let bitcoind_exe = bitcoind_exe_path()?;

		let datadir = self.datadir.join(name.as_ref());
		let config = BitcoinDConfig {
			datadir,
			txindex: true,
			network: String::from("regtest"),
			..BitcoinDConfig::default()
		};

		let mut bitcoind = BitcoinD::new(name.as_ref().to_string(), bitcoind_exe, config);
		bitcoind.start().await?;

		Ok(bitcoind)
	}

	pub async fn aspd(&self, name: impl AsRef<str>, bitcoind: &BitcoinD) -> anyhow::Result<AspD> {

		let datadir = self.datadir.join(name.as_ref());

		let stdout_logger = FileLogger::new(datadir.join("stdout.log"));
		let stderr_logger = FileLogger::new(datadir.join("stderr.log"));

		let cfg = AspDConfig {
			datadir,
			bitcoind_url: bitcoind.bitcoind_url(),
			bitcoind_cookie: bitcoind.bitcoind_cookie()
		};

		let mut aspd = AspD::new(name, cfg);

		aspd.add_stdout_handler(stdout_logger)?;
		aspd.add_stderr_handler(stderr_logger)?;

		aspd.start().await?;

		Ok(aspd)
	}


	pub async fn bark(&self, name: impl AsRef<str>, bitcoind: &BitcoinD, aspd: &AspD) -> anyhow::Result<Bark> {
		let datadir = self.datadir.join(name.as_ref());
		let asp_url = aspd.asp_url()?;

		let cfg = BarkConfig {
			datadir,
			asp_url,
			bitcoind_url: bitcoind.bitcoind_url(),
			bitcoind_cookie: bitcoind.bitcoind_cookie(),
			network: String::from("regtest")};
		let bark = cfg.create(name).await?;

		Ok(bark)
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		log::info!("Textcontext: Datadir is located at {:?}", self.datadir);
	}
}

