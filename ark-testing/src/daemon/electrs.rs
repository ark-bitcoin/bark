use std::fmt;
use std::path::PathBuf;

use bdk_esplora::esplora_client::Builder;
use tokio::fs;
use tokio::process::Command;

use crate::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use crate::constants::env::ELECTRS_EXEC;
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::resolve_path;

pub type Electrs = Daemon<ElectrsHelper>;

impl fmt::Debug for Electrs {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "esplora-electrs in {}", self.inner.datadir().display())
	}
}

impl Electrs {
	fn exec() -> PathBuf {
		if let Ok(e) = std::env::var(&ELECTRS_EXEC) {
			resolve_path(e).expect("failed to resolve ELECTRS_EXEC")
		} else if let Ok(e) = which::which("electrs") {
			e.into()
		} else {
			panic!("ELECTRS_EXEC env not set")
		}
	}

	pub fn new(name: impl AsRef<str>, config: ElectrsConfig) -> Self {
		let inner = ElectrsHelper {
			name: name.as_ref().to_owned(),
			config,
			state: ElectrsHelperState::default()
		};
		Daemon::wrap(inner)
	}

	pub fn electrum_port(&self) -> u16 {
		self.inner.electrum_port()
	}

	pub fn electrum_url(&self) -> String {
		self.inner.electrum_url()
	}

	pub fn monitoring_port(&self) -> u16 {
		self.inner.monitoring_port()
	}

	pub fn monitoring_url(&self) -> String {
		self.inner.monitoring_url()
	}

	pub fn rest_port(&self) -> u16 {
		self.inner.rest_port()
	}

	pub fn rest_url(&self) -> String {
		self.inner.rest_url()
	}
}

#[derive(Default)]
struct ElectrsHelperState {
	rest_port: Option<u16>,
	electrum_port: Option<u16>,
	monitoring_port: Option<u16>,
}

pub struct ElectrsConfig {
	pub network: String,
	pub bitcoin_rpc_port: u16,
	pub bitcoin_zmq_port: u16,
	pub bitcoin_dir: PathBuf,
	pub electrs_dir: PathBuf,
}

pub struct ElectrsHelper {
	name: String,
	config: ElectrsConfig,
	state: ElectrsHelperState
}

impl ElectrsHelper {
	pub fn electrum_port(&self) -> u16 {
		self.state.electrum_port.expect("A port should be configured")
	}

	pub fn electrum_url(&self) -> String {
		format!("tcp://127.0.0.1:{}", self.state.electrum_port.expect("A port should be configured"))
	}

	pub fn monitoring_port(&self) -> u16 {
		self.state.monitoring_port.expect("A port should be configured")
	}

	pub fn monitoring_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.state.monitoring_port.expect("A port should be configured"))
	}

	pub fn rest_port(&self) -> u16 {
		self.state.rest_port.expect("A port should be configured")
	}

	pub fn rest_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.state.rest_port.expect("A port should be configured"))
	}

	async fn is_ready(&self) -> bool {
		let client = Builder::new(&self.rest_url()).build_async();
		if let Ok(client) = client {
			client.get_height().await.is_ok()
		} else {
			false
		}
	}
}

impl DaemonHelper for ElectrsHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.config.electrs_dir.clone()
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let rest_port = portpicker::pick_unused_port().expect("No ports free");
		let electrum_port = portpicker::pick_unused_port().expect("No ports free");
		let monitoring_port = portpicker::pick_unused_port().expect("No ports free");

		trace!("Reserved electrs ports = {}, {} and {}", rest_port, electrum_port, monitoring_port);
		self.state.rest_port = Some(rest_port);
		self.state.electrum_port = Some(electrum_port);
		self.state.monitoring_port = Some(monitoring_port);

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		if !self.config.electrs_dir.exists() {
			fs::create_dir_all(&self.config.electrs_dir).await?;
		}
		Ok(())
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let mut cmd = Command::new(Electrs::exec());
		cmd.args([
			"-vvvv",
			"--network", &self.config.network,
			"--db-dir", &self.config.electrs_dir.to_string_lossy(),
			"--daemon-rpc-addr", &format!("127.0.0.1:{}", self.config.bitcoin_rpc_port),
			"--zmq-addr", &format!("127.0.0.1:{}", self.config.bitcoin_zmq_port),
			"--daemon-dir", &self.config.bitcoin_dir.to_string_lossy(),
			"--cookie", &format!("{}:{}", BITCOINRPC_TEST_USER, BITCOINRPC_TEST_PASSWORD),
			"--electrum-rpc-addr", &format!("127.0.0.1:{}", self.electrum_port()),
			"--monitoring-addr", &format!("127.0.0.1:{}", self.monitoring_port()),
			"--http-addr", &format!("127.0.0.1:{}", self.rest_port()),
		]);
		Ok(cmd)
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		loop {
			if self.is_ready().await {
				return Ok(());
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
	}
}
