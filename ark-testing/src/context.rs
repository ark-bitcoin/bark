use std::path::PathBuf;
use std::fs;

use crate::util::random_string;
use crate::constants;
use crate::daemon::bitcoind::bitcoind_exe_path;
use crate::daemon::log::FileLogger;
use crate::{AspD, AspDConfig, BitcoinD, BitcoinDConfig, Bark, BarkConfig};

pub struct TestContext {
	#[allow(dead_code)]
	pub name: String,
	pub datadir: PathBuf
}

impl TestContext {
	pub fn new(name: impl AsRef<str>, base_path: PathBuf) -> Self {
		fs::create_dir_all(base_path.clone()).unwrap();
		crate::util::init_logging().expect("Logging can be initialized");
		TestContext { name: name.as_ref().to_string(), datadir: base_path}
	}

	pub fn generate() -> Self {
		let name = random_string();
		let datadir = ["/tmp/ark-testing/", &name].iter().collect();
		Self::new(name, datadir)
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
		// Remove the data-directory
		// If the user has set `LEAVE_INTACT` we don't delete any
		// test-data.

		if std::env::var(constants::env::TEST_LEAVE_INTACT).is_ok() {
			log::info!("Textcontext: Leave intact at {:?}", self.datadir);
			return
		}
		if self.datadir.exists() {
			log::trace!("Testcontext: Clean up datadir at {:?}. Set `TEST_LEAVE_INTACT` if you want to see the content", self.datadir);
			std::fs::remove_dir_all(self.datadir.clone()).unwrap();
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn context_creates_and_deletes_datadir() {
		let context = TestContext::generate();
		let base_path = context.datadir.clone();

		// The base-path is created
		assert!(context.datadir.exists());
		drop(context);

		// The test cleans up after itself
		match std::env::var(constants::env::TEST_LEAVE_INTACT) {
			Ok(_) => assert!(base_path.exists()),
			Err(_) => assert!(!base_path.exists())
		}
	}
}
