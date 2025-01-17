
use std::env;
use std::borrow::Borrow;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Denomination, FeeRate, Weight};

use tokio::fs;
use tokio::process::Child;

use crate::constants::env::TEST_DIRECTORY;

pub fn init_logging() -> anyhow::Result<()> {
	// We ignore the output
	// An error is returned if the logger is initiated twice
	// Note, that every test tries to initiate the logger
	let _ = fern::Dispatch::new()
		.level(log::LevelFilter::Trace)
		.level_for("rustls", log::LevelFilter::Off)
		.level_for("tonic", log::LevelFilter::Off)
		.format(|out, msg, rec| {
			let now = chrono::Local::now();
			let stamp = now.format("%H:%M:%S.%3f");
			out.finish(format_args!("[{} {: >5}] {}", stamp, rec.level(), msg))
		})
		.chain(std::io::stdout())
		.apply();
	Ok(())
}

/// Resolves the directory when it is a relative path, and
/// returns canonicalized path.
///
/// Returns error if path doesn't exist.
pub fn resolve_path(path: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
	let path = path.as_ref().to_path_buf();
	let path = if path.is_relative() {
		let cur = env::current_dir().expect("failed to get current dir");
		let abs = cur.join(&path);
		if abs.exists() {
			abs
		} else {
			bail!("relative path {} doesn't exist for current directory {}",
				path.display(), cur.display(),
			);
		}
	} else {
		path
	};
	Ok(path.canonicalize()
		.with_context(|| format!("failed to canonicalize path {}", path.display()))?)
}

/// Returns the directory where all test data will be written
///
/// By default this is written in the `./test` directory at the project root.
/// You can also set `TEST_DIRECTORY` to pick another location.
pub async fn test_data_directory() -> PathBuf {
	let path = if let Some(dir) = env::var_os(TEST_DIRECTORY) {
		let path = PathBuf::from(dir);
		if path.is_relative() {
			get_cargo_workspace().join(path)
		} else {
			path
		}
	} else {
		get_cargo_workspace().join("test")
	};

	if !path.exists() {
		fs::create_dir_all(&path).await.unwrap();
	};
	path.canonicalize().unwrap()
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

/// Extension trait for futures.
#[async_trait]
pub trait FutureExt: Future {
	/// Add a timeout of the given number of milliseconds.
	#[track_caller]
	fn try_wait(self, milliseconds: u64) -> tokio::time::Timeout<Self> where Self: Sized {
		tokio::time::timeout(Duration::from_millis(milliseconds), self)
	}

	/// Add a timeout of the given number of milliseconds.
	#[track_caller]
	async fn wait(self, milliseconds: u64) -> Self::Output where Self: Sized {
		match self.try_wait(milliseconds).await {
			Ok(v) => v,
			Err(_) => {
				error!("future timed out");
				panic!("future timed out");
			},
		}
	}

	/// Add a short timeout.
	#[track_caller]
	fn try_fast(self) -> tokio::time::Timeout<Self> where Self: Sized {
		self.try_wait(500)
	}

	/// Add a short timeout.
	#[track_caller]
	async fn fast(self) -> Self::Output where Self: Sized {
		match self.try_fast().await {
			Ok(v) => v,
			Err(_) => {
				error!("future timed out");
				panic!("future timed out");
			},
		}
	}
}
impl<T: Future> FutureExt for T {}
