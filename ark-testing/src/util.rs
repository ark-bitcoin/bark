
use std::borrow::Borrow;
use std::process::Child;
use std::path::{Path, PathBuf};
use std::fs;

use bitcoin::{Denomination, FeeRate, Weight};

use crate::constants::env::TEST_DIRECTORY;

pub fn init_logging() -> anyhow::Result<()> {
	// We ignore the output
	// An error is returned if the logger is initiated twice
	// Note, that every test tries to initiate the logger
	let _ = fern::Dispatch::new()
		.format(|out, msg, rec| {
			let now = chrono::Local::now();
			let stamp = now.format("%H:%M:%S.%3f");
			out.finish(format_args!("[{} {: >5}] {}", stamp, rec.level(), msg))
		})
		.level(log::LevelFilter::Trace)
		.chain(std::io::stdout())
		.apply();
	Ok(())
}

/// Returns the directory where all test data will be written
///
/// By default this is written in the `./test` directory at the project root.
/// You can also set TEST_DIRECTORY to pick another location.
/// You are responsible to ensure the `TEST_DIRECTORY` exists
pub fn test_data_directory() -> PathBuf {
	match std::env::var_os(TEST_DIRECTORY) {
		Some(directory) => { PathBuf::from(directory) },
		None => {
			let path = get_cargo_workspace().join("test");
			if !path.exists() {
				fs::create_dir_all(&path).unwrap();
			};
			path
		}
	}
}


/// The root of the current cargo workspace
fn get_cargo_workspace() -> PathBuf {
	let output = std::process::Command::new("cargo")
		.args(["locate-project", "--workspace", "--message-format=plain"])
		.output()
		.unwrap();

		let cargo_path = String::from_utf8(output.stdout).unwrap();
		Path::new(&cargo_path.trim()).parent().unwrap().to_path_buf()
}

pub fn is_running(child: &mut Child) -> bool {
	match child.try_wait() {
		Ok(None) => true,
		Ok(Some(_status)) => false,
		Err(err) => {
			error!("Failed to get status of Child={:?}", child);
			error!("{:?}", err);
			false
		},
	}
}

pub trait FeeRateExt: Borrow<FeeRate> {
	fn to_btc_per_kvb(&self) -> String {
		(*self.borrow() * Weight::from_vb(1000).unwrap()).to_string_in(Denomination::Bitcoin)
	}
}
impl FeeRateExt for FeeRate {}
