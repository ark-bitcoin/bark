#[macro_use] extern crate log;

pub mod aspd;
pub mod cmd;
pub mod constants;
pub mod bark;

mod error;
mod runner;
mod util;

use std::path::PathBuf;
use std::fs;
pub use bitcoind;
use bitcoind::BitcoinD;
use aspd::AspD;
pub use runner::DaemonRunner;

pub struct TestContext {
	#[allow(dead_code)]
	name: String,
	datadir: PathBuf,
	bitcoind_count: usize,
	aspd_count: usize
}

impl TestContext {

	pub fn new(name: String, base_path: PathBuf) -> Self {
		fs::create_dir_all(base_path.clone()).unwrap();
		let context = TestContext { name, datadir: base_path, bitcoind_count: 0, aspd_count: 0};
		context.init_logging().unwrap();
		context
	}

	pub fn init_logging(&self) -> anyhow::Result<()> {
		// We ignore the error
		// It is only returned when the logger is initiated twice
		// Note, that every test tries to initiate the logger 
		// so this happens all the time
		let _ = env_logger::Builder::from_env(
			env_logger::Env::default().default_filter_or("trace"))
			.is_test(true).try_init();
		Ok(())
	}

	pub fn generate() -> Self {
		let name = util::random_string();
		let datadir = ["/tmp/ark-testing/", &name].iter().collect();
		Self::new(name, datadir)
	}

	pub fn bitcoind(&mut self) -> BitcoinD {
		self.bitcoind_count+=1;
		let name = format!("bitcoind-{}", self.bitcoind_count);

		// Launching bitcoind
		info!("Starting {}", name);
		let exe_path = bitcoind::exe_path().unwrap();

		// Note, that `arkd` requires the `--txindex` argument
		// Because we use `staticdir` the bitcoind`-folder will not be
		// deleted if the test completes
		let mut conf = bitcoind::Conf::default();
		conf.args.push("--txindex");
		conf.staticdir = Some(self.datadir.join(name));

		BitcoinD::with_conf(exe_path, &conf).unwrap()
	}

	pub fn aspd(&mut self, bitcoind: &BitcoinD) -> AspD 
	{
		self.aspd_count+=1;
		let name = format!("aspd-{}", self.aspd_count);

		let base_command = aspd::get_base_cmd().unwrap();
		let datadir = self.datadir.join(&name);

		let mut aspd = AspD::new(name, base_command, datadir, bitcoind);
		aspd.start().expect("aspd started");
		aspd
	}
}

impl Drop for TestContext {
	fn drop(&mut self) {
		// Remove the data-directory
		// If the user has set `LEAVE_INTACT` we don't delete any 
		// test-data.
		if std::env::var(constants::env::TEST_LEAVE_INTACT).is_ok() {
			log::info!("Leaving test-context intact at {:?}", self.datadir);
			return
		}
		if self.datadir.exists() {
			log::trace!("Cleaning up test-context. Run again with `TEST_LEAVE_INTACT=1` to keep the test intact");
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

				// The test cleans up after itself if TEST_LEAVE_INTACT is not set
				match std::env::var(constants::env::TEST_LEAVE_INTACT) {
					Ok(_) => assert!(base_path.exists()),
					Err(_) => assert!(!base_path.exists())
				}
		}
}
