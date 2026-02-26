use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bdk_esplora::esplora_client::{AsyncClient, Builder};
use bitcoin::{Network, Transaction, Txid};
use log::trace;
use tokio::fs;
use tokio::process::Command;

use bark::chain::ChainSourceSpec;

use crate::constants::bitcoind::{BITCOINRPC_TEST_PASSWORD, BITCOINRPC_TEST_USER};
use crate::constants::env::{ESPLORA_ELECTRS_EXEC, MEMPOOL_ELECTRS_EXEC};
use crate::constants::TX_PROPAGATION_SLEEP_TIME;
use crate::daemon::{Daemon, DaemonHelper};
use crate::util::{get_tx_propagation_timeout_millis, resolve_path};

#[derive(Clone, Copy)]
pub enum ElectrsType {
	Esplora,
	Mempool,
}

impl fmt::Debug for ElectrsType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ElectrsType::Esplora => write!(f, "esplora"),
			ElectrsType::Mempool => write!(f, "mempool"),
		}
	}
}

pub type Electrs = Daemon<ElectrsHelper>;

impl fmt::Debug for Electrs {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?} in {}", self.inner.electrs_type, self.inner.datadir().display())
	}
}

impl Electrs {
	fn exec(electrs_type: ElectrsType) -> PathBuf {
		let env_name = match electrs_type {
			ElectrsType::Esplora => ESPLORA_ELECTRS_EXEC,
			ElectrsType::Mempool => MEMPOOL_ELECTRS_EXEC,
		};
		if let Ok(e) = std::env::var(&env_name) {
			resolve_path(e).expect(&format!("failed to resolve {}", env_name))
		} else if let Ok(e) = which::which("electrs") {
			e.into()
		} else {
			panic!("{} env not set", env_name)
		}
	}

	pub fn new(name: impl AsRef<str>, config: ElectrsConfig, electrs_type: ElectrsType) -> Self {
		let inner = ElectrsHelper {
			name: name.as_ref().to_owned(),
			config,
			electrs_type,
			state: ElectrsHelperState::default()
		};
		Daemon::wrap(inner)
	}

	pub fn async_client(&self) -> AsyncClient {
		Builder::new(&self.rest_url()).build_async().unwrap()
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

	pub fn chain_source(&self) -> ChainSourceSpec {
		ChainSourceSpec::Esplora { url: self.rest_url() }
	}

	pub async fn await_transaction(&self, txid: Txid) -> Transaction {
		let client = self.async_client();
		let start = Instant::now();
		let timeout = get_tx_propagation_timeout_millis();
		while Instant::now().duration_since(start).as_millis() < timeout as u128 {
			if let Ok(Some(result)) = client.get_tx(&txid).await {
				return result;
			} else {
				tokio::time::sleep(TX_PROPAGATION_SLEEP_TIME).await;
			}
		}
		panic!("Failed to get raw transaction: {}", txid);
	}

	pub async fn get_block_count(&self) -> u32 {
		let client = self.async_client();
		client.get_height().await.unwrap()
	}

	/// Poll the Prometheus `tip_height` metric from the monitoring endpoint.
	///
	/// Both blockstream/electrs and mempool/electrs set this metric *after*
	/// the full indexing pipeline (txstore, history, synced-tip) completes.
	/// The REST API's `/blocks/tip/height` can return a new height before
	/// the history index is ready, causing BDK wallet syncs to miss recent
	/// transactions. Polling `tip_height` avoids that race.
	async fn get_tip_height_metric(&self) -> Option<u32> {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let addr = format!("127.0.0.1:{}", self.monitoring_port());
		let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
		let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", addr);
		stream.write_all(request.as_bytes()).await.ok()?;

		let mut body = String::new();
		stream.read_to_string(&mut body).await.ok()?;

		for line in body.lines() {
			if line.starts_with("tip_height ") {
				let value = line.strip_prefix("tip_height ")?;
				return value.trim().parse::<f64>().ok().map(|v| v as u32);
			}
		}
		None
	}

	/// Wait until electrs has fully indexed up to `height`.
	///
	/// Uses the Prometheus `tip_height` metric which is only updated after
	/// the entire indexing pipeline finishes, including the history (address)
	/// index that BDK's wallet sync depends on.
	pub async fn await_tip_synced(&self, height: u32) {
		let start = Instant::now();
		while start.elapsed().as_millis() < 10_000 {
			if let Some(tip) = self.get_tip_height_metric().await {
				if tip >= height {
					return;
				}
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("Electrs tip_height metric did not reach {} after 10s", height);
	}
}

#[derive(Default)]
struct ElectrsHelperState {
	rest_port: Option<u16>,
	electrum_port: Option<u16>,
	monitoring_port: Option<u16>,
}

pub struct ElectrsConfig {
	pub network: Network,
	pub bitcoin_rpc_port: u16,
	pub bitcoin_zmq_port: u16,
	pub bitcoin_dir: PathBuf,
	pub electrs_dir: PathBuf,
}

pub struct ElectrsHelper {
	name: String,
	config: ElectrsConfig,
	electrs_type: ElectrsType,
	state: ElectrsHelperState,
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

#[async_trait]
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
		let exec = Electrs::exec(self.electrs_type);
		trace!("Starting {}", exec.display());

		let mut cmd = Command::new(exec);
		cmd.args([
			"-vvvv",
			"--timestamp",
			"--network", &self.config.network.to_string(),
			"--db-dir", &self.config.electrs_dir.to_string_lossy(),
			"--daemon-rpc-addr", &format!("127.0.0.1:{}", self.config.bitcoin_rpc_port),
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
