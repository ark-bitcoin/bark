
pub mod proxy;
pub mod postgresd;

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::Network;
use bitcoin::address::{Address, NetworkUnchecked};
use log::{info, trace};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{self, mpsc, Mutex};
use tokio::process::Command;

use aspd_log::{LogMsg, ParsedRecord, TipUpdated, TxIndexUpdateFinished, SLOG_FILENAME};
use aspd_rpc::{self as rpc, protos};
pub use aspd::config::{self, Config};

use crate::{Bitcoind, Daemon, DaemonHelper};
use crate::constants::env::ASPD_EXEC;
use crate::util::resolve_path;

pub type Aspd = Daemon<AspdHelper>;

pub type AdminClient = rpc::AdminServiceClient<tonic::transport::Channel>;
pub type ArkClient = rpc::ArkServiceClient<tonic::transport::Channel>;


pub const ASPD_CONFIG_FILE: &str = "config.toml";

/// The bark client version we report in handshake message
/// that will always give us ark-info.
const TESTING_CLIENT_VERSION: &str = "testing";


pub trait SlogHandler {
	/// Process a log line. Return true when you're done.
	fn process_slog(&mut self, log: &ParsedRecord) -> bool;
}

impl<F> SlogHandler for F
where
	F: FnMut(&ParsedRecord) -> bool,
{
	fn process_slog(&mut self, log: &ParsedRecord) -> bool {
		self(log)
	}
}

pub struct AspdHelper {
	name: String,
	cfg: Config,
	bitcoind: Bitcoind,
	slog_handlers: Arc<Mutex<Vec<Box<dyn SlogHandler + Send + Sync + 'static>>>>,
}

impl Aspd {
	pub fn bitcoind(&self) -> &Bitcoind {
		&self.inner.bitcoind
	}

	pub fn config(&self) -> &Config {
		&self.inner.cfg
	}

	/// Gracefully shutdown bitcoind associated with this ASP.
	pub async fn shutdown_bitcoind(&self) {
		self.inner.bitcoind.stop().await.expect("error stopping bitcoind");
	}

	pub fn base_cmd() -> Command {
		let e = env::var(ASPD_EXEC).expect("ASPD_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve ASPD_EXEC");
		Command::new(exec)
	}

	/// Creates ASP with a dedicated bitcoind daemon.
	pub fn new(name: impl AsRef<str>, bitcoind: Bitcoind, cfg: Config) -> Self {
		let helper = AspdHelper {
			name: name.as_ref().to_string(),
			cfg,
			bitcoind,
			slog_handlers: Arc::new(Mutex::new(Vec::new())),
		};

		Daemon::wrap(helper)
	}

	pub fn asp_url(&self) -> String {
		self.inner.asp_url()
	}

	pub async fn get_admin_client(&self) -> AdminClient {
		self.inner.connect_admin_client().await.unwrap()
	}

	pub async fn get_public_client(&self) -> ArkClient {
		self.inner.connect_public_client().await.unwrap()
	}

	pub async fn ark_info(&self) -> ark::ArkInfo {
		self.get_public_client().await.handshake(protos::HandshakeRequest {
			version: TESTING_CLIENT_VERSION.into(),
		}).await.unwrap().into_inner().ark_info.unwrap().try_into().expect("invalid ark info")
	}

	pub async fn wallet_status(&self) -> rpc::WalletStatus {
		let mut rpc = self.get_admin_client().await;
		rpc.wallet_sync(protos::Empty{}).await.expect("sync error");
		rpc.wallet_status(protos::Empty{}).await.expect("sync error").into_inner()
			.rounds.unwrap().try_into().unwrap()
	}

	pub async fn get_rounds_funding_address(&self) -> Address {
		let mut admin_client = self.get_admin_client().await;
		let response = admin_client.wallet_status(protos::Empty {}).await.unwrap().into_inner();
		response.rounds.unwrap().address.parse::<Address<NetworkUnchecked>>().unwrap()
			.require_network(Network::Regtest).unwrap()
	}

	pub async fn trigger_round(&self) {
		let start = Instant::now();
		let minimum_wait = tokio::time::sleep(Duration::from_millis(500));
		let mut l1 = self.subscribe_log::<TipUpdated>().await;
		let mut l2 = self.subscribe_log::<TxIndexUpdateFinished>().await;
		self.bitcoind().generate(1).await;
		let _ = tokio::join!(l1.recv(), l2.recv(), minimum_wait);
		trace!("Waited {} ms before starting round", start.elapsed().as_millis());
		self.get_admin_client().await.trigger_round(protos::Empty {}).await.unwrap();
	}

	pub async fn add_slog_handler<L: SlogHandler + Send + Sync + 'static>(&self, handler: L) {
		self.inner.slog_handlers.lock().await.push(Box::new(handler));
	}

	/// Subscribe to all structured logs of the given type.
	pub async fn subscribe_log<L: LogMsg>(&self) -> mpsc::UnboundedReceiver<L> {
		let (tx, rx) = sync::mpsc::unbounded_channel();
		self.add_slog_handler(move |log: &ParsedRecord| {
			if log.is::<L>() {
				return tx.send(log.try_as().expect("invalid slog data")).is_err();
			}
			false
		}).await;
		rx
	}

	/// Wait for the first occurrence of the given log message type and return it.
	pub async fn wait_for_log<L: LogMsg>(&self) -> L {
		let (tx, mut rx) = sync::mpsc::channel(1);
		self.add_slog_handler(move |log: &ParsedRecord| {
			if log.is::<L>() {
				let msg = log.try_as().expect("invalid slog data");
				// if channel already closed, user is no longer interested
				let _ = tx.try_send(msg);
				return true;
			}
			false
		}).await;
		rx.recv().await.expect("log wait channel closed")
	}
}

#[tonic::async_trait]
impl DaemonHelper for AspdHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.cfg.data_dir.clone()
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let config_file = self.datadir().join(ASPD_CONFIG_FILE);

		let mut cmd = Aspd::base_cmd();
		let args = vec![
			"start",
			"--config",
			config_file.to_str().unwrap(),
		];
		trace!("base_cmd={:?}; args={:?}", cmd, args);
		cmd.args(args);

		Ok(cmd)
	}

	async fn make_reservations(&mut self) -> anyhow::Result<()> {
		let public_port = portpicker::pick_unused_port().expect("No ports free");
		let admin_port = portpicker::pick_unused_port().expect("No ports free");

		let public_address = format!("0.0.0.0:{}", public_port);
		let admin_address = format!("127.0.0.1:{}", admin_port);
		trace!("ASPD_RPC_PUBLIC_ADDRESS: {}", public_port.to_string());
		trace!("ASPD_RPC_ADMIN_ADDRESS: {}", admin_port.to_string());

		self.cfg.rpc = config::Rpc {
			public_address: SocketAddr::from_str(public_address.as_str())?,
			admin_address: Some(SocketAddr::from_str(admin_address.as_str())?),
		};

		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		let mut first_run = false;

		let data_dir = self.datadir();
		if !data_dir.exists() {
			info!("Data directory {:?} does not exist. Creating...", data_dir);
			std::fs::create_dir_all(data_dir.clone())?;
			first_run = true;
		}

		let config_path = data_dir.join(ASPD_CONFIG_FILE);
		info!("Preparing to create configuration file at: {}", config_path.display());
		self.cfg.write_to_file(&config_path)
			.with_context(|| format!("error writing aspd config to '{}'", config_path.display()))?;
		info!("Configuration file successfully created at: {}", config_path.display());

		if first_run {
			info!("Initializing new {} instance", self.name.to_string());
			self.create().await?;
		}

		Ok(())
	}

	async fn post_start(&mut self) -> anyhow::Result<()> {
		// setup slog handling
		let log_dir = match self.cfg.log_dir {
			Some(ref d) => d,
			None => return Ok(()),
		};
		let file = tokio::fs::File::open(log_dir.join(SLOG_FILENAME)).await
			.expect("failed to open log file");

		let buf_reader = BufReader::new(file);
		let mut lines = buf_reader.lines();
		let handlers = self.slog_handlers.clone();
		let _ = tokio::spawn(async move {
			loop {
				match lines.next_line().await.expect("I/O error on log file handle") {
					Some(line) => {
						let log = serde_json::from_str::<ParsedRecord>(&line)
							.expect("error parsing slog line");
						for handler in handlers.lock().await.iter_mut() {
							handler.process_slog(&log);
						}
					},
					None => {
						tokio::time::sleep(std::time::Duration::from_millis(50)).await;
					},
				}
			}
		});
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		while !self.is_ready().await {
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		Ok(())
	}
}

impl AspdHelper {
	async fn is_ready(&self) -> bool {
		return self.admin_grpc_is_ready().await && self.public_grpc_is_ready().await
	}

	async fn public_grpc_is_ready(&self) -> bool {
		match self.connect_public_client().await {
			Ok(mut c) => {
				c.handshake(protos::HandshakeRequest {
					version: TESTING_CLIENT_VERSION.into(),
				}).await.is_ok()
			},
			Err(_e) => false,
		}
	}

	async fn admin_grpc_is_ready(&self) -> bool {
		match self.connect_admin_client().await {
			Ok(mut c) => c.wallet_status(protos::Empty {}).await.is_ok(),
			Err(_e) => false,
		}
	}

	pub fn asp_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.public_address)
	}

	pub fn admin_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.admin_address.expect("missing admin addr"))
	}

	pub async fn connect_public_client(&self) -> anyhow::Result<ArkClient> {
		ArkClient::connect(self.asp_url()).await.context("can't connect asp public rpc")
	}

	pub async fn connect_admin_client(&self) -> anyhow::Result<AdminClient> {
		AdminClient::connect(self.admin_url()).await.context("can't connect asp admin rpc")
	}

	async fn create(&self) -> anyhow::Result<()> {
		let config_file = self.datadir().join(ASPD_CONFIG_FILE);

		let mut cmd = Aspd::base_cmd();
		let args = vec![
			"create",
			"--config",
			config_file.to_str().unwrap(),
		];
		trace!("base_cmd={:?}; args={:?}", cmd, args);

		let stdout_path = self.datadir().join("create_stdout.log");
		let stderr_path = self.datadir().join("create_stderr.log");
		cmd.stdout(std::fs::File::create(&stdout_path)?);
		cmd.stderr(std::fs::File::create(&stderr_path)?);

		let status = cmd.args(args).status().await?;
		if status.success() {
			Ok(())
		} else {
			bail!("Failed to create aspd '{}'", self.name);
		}
	}
}
