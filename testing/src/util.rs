
use std::{env, fmt};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use log::error;
use tokio::fs;
use tokio::process::Child;

use crate::constants::env::{CHAIN_SOURCE, TEST_DIRECTORY, TX_PROPAGATION_TIMEOUT_MILLIS};
use crate::daemon::electrs::ElectrsType;

pub enum TestContextChainSource {
	BitcoinCore,
	ElectrsRest(ElectrsType),
}

impl TestContextChainSource {
	pub fn as_str(&self) -> &'static str {
		match self {
			TestContextChainSource::BitcoinCore => "bitcoind",
			TestContextChainSource::ElectrsRest(ElectrsType::Esplora) => "esplora",
			TestContextChainSource::ElectrsRest(ElectrsType::Mempool) => "mempool",
		}
	}
}

impl From<String> for TestContextChainSource {
	fn from(s: String) -> Self {
		match s.as_str() {
			"bitcoind" => TestContextChainSource::BitcoinCore,
			"esplora" => TestContextChainSource::ElectrsRest(ElectrsType::Esplora),
			"mempool" => TestContextChainSource::ElectrsRest(ElectrsType::Mempool),
			_ => panic!("invalid chain source {}", s),
		}
	}
}

pub fn init_logging() {
	use std::io::Write;

	// every test calls this, so we ignore the error it throws on the
	// all calls after the first
	let _ = env_logger::Builder::new()
		.filter_level(log::LevelFilter::Trace)
		.filter_module("rustls", log::LevelFilter::Off)
		.filter_module("tonic", log::LevelFilter::Off)
		.filter_module("tokio_postgres", log::LevelFilter::Off)
		.parse_env(env_logger::Env::new().filter("TEST_LOG"))
		.format(|out, rec| {
			let now = chrono::Local::now();
			let ts = now.format("%H:%M:%S.%3f");
			let lvl = rec.level();
			let module = rec.module_path().expect("no module");
			let msg = rec.args();
			if module.starts_with("ark_testing") {
				let module = module.strip_prefix("ark_").unwrap();
				let file = rec.file().expect("log record without file");
				let file = file.split("testing/src/").last().unwrap();
				let line = rec.line().expect("log record without line");
				writeln!(out, "[{ts} {lvl: >5} {module} {file}:{line}] {msg}")
			} else {
				writeln!(out, "[{ts} {lvl: >5} {module}] {msg}")
			}
		})
		.target(env_logger::Target::Stdout)
		.try_init();
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
			error!("Failed to get status of Child={:?}: {:?}", child, err);
			false
		},
	}
}

pub async fn wait_for_completion(child: &mut Child) -> () {
	while is_running(child) {
		tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	}
}

pub fn get_bark_chain_source_from_env() -> TestContextChainSource {
	if let Ok(cs) = env::var(&CHAIN_SOURCE) {
		TestContextChainSource::from(cs)
	} else {
		TestContextChainSource::BitcoinCore
	}
}

pub fn get_tx_propagation_timeout_millis() -> u64 {
	if let Ok(timeout) = env::var(TX_PROPAGATION_TIMEOUT_MILLIS) {
		timeout.parse::<u64>()
			.expect(&format!("{} should be in milliseconds", TX_PROPAGATION_TIMEOUT_MILLIS))
	} else {
		30_000
	}
}

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

	/// Awaits a future for a short period. Using this assumes that the future is already complete, 
	/// so if the operation times out, we panic because a test is likely failing unexpectedly.
	#[track_caller]
	async fn ready(self) -> Self::Output where Self: Sized {
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

/// Extension trait for channel receivers.
pub trait ReceiverExt<T> {
	/// Collect all pending items in a Vec.
	fn collect(&mut self) -> Vec<T>;

	/// Empty all pending items.
	fn clear(&mut self);
}

impl<T> ReceiverExt<T> for tokio::sync::mpsc::UnboundedReceiver<T> {
	fn collect(&mut self) -> Vec<T> {
		let mut ret = Vec::new();
		while let Ok(v) = self.try_recv() {
			ret.push(v);
		}
		ret
	}

	fn clear(&mut self) {
		while let Ok(_) = self.try_recv() {}
	}
}

/// Trait similar to [ToString] that returns the alt string
pub trait ToAltString: fmt::Display {
	fn to_alt_string(&self) -> String {
		format!("{:#}", self)
	}
}
impl<T: fmt::Display> ToAltString for T {}
