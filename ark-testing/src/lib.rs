pub mod aspd;
pub mod cmd;
pub mod constants;
pub mod bark;
mod util;

use std::path::PathBuf;
use std::fs;

pub struct TestContext {
	#[allow(dead_code)]
	name: String,
	datadir: PathBuf
}

impl TestContext {

	pub fn new(name: String, base_path: PathBuf) -> Self {
		fs::create_dir_all(base_path.clone()).unwrap();
		let context = TestContext { name, datadir: base_path};
		context.init_logging().unwrap();
		context
	}

	pub fn init_logging(&self) -> anyhow::Result<()> {
		// We ignore the output
		// An error is returned if the logger is initiated twice
		// Note, that every test tries to initiate the logger
		let _ = env_logger::builder().is_test(true).try_init();
		Ok(())
	}

	pub fn generate() -> Self {
		let name = util::random_string();
		let datadir = ["/tmp/ark-testing/", &name].iter().collect();
		Self::new(name, datadir)
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
