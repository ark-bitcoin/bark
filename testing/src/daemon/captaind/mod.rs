pub mod proxy;

use std::{env, fs};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Network, Amount};
use bitcoin::address::{Address, NetworkUnchecked};
use log::{info, trace};
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{self, mpsc};
use tokio::process::Command;

use server_log::{LogMsg, ParsedRecord, TipUpdated, TxIndexUpdateFinished, SLOG_FILENAME};
use server_rpc::{self as rpc, protos};
pub use server::config::{self, Config};

use crate::{Bitcoind, Daemon, DaemonHelper};
use crate::constants::env::CAPTAIND_EXEC;
use crate::util::{resolve_path, AnyhowErrorExt};

pub type Captaind = Daemon<CaptaindHelper>;

pub type ArkClient = rpc::ArkServiceClient<tonic::transport::Channel>;
pub type WalletAdminClient = rpc::admin::WalletAdminServiceClient<tonic::transport::Channel>;
pub type RoundAdminClient = rpc::admin::RoundAdminServiceClient<tonic::transport::Channel>;
pub type SweepAdminClient = rpc::admin::SweepAdminServiceClient<tonic::transport::Channel>;


pub const CAPTAIND_CONFIG_FILE: &str = "config.toml";


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

#[derive(Debug, Clone)]
pub struct WalletStatuses {
	pub rounds: rpc::WalletStatus,
	pub forfeits: rpc::WalletStatus,
}

impl WalletStatuses {
	pub fn total(&self) -> Amount {
		self.rounds.total_balance + self.forfeits.total_balance
	}
}

pub struct CaptaindHelper {
	name: String,
	cfg: Config,
	bitcoind: Bitcoind,
	slog_handlers: Arc<Mutex<Vec<Box<dyn SlogHandler + Send + Sync + 'static>>>>,
}

impl Captaind {
	pub fn bitcoind(&self) -> &Bitcoind {
		&self.inner.bitcoind
	}

	pub fn config(&self) -> &Config {
		&self.inner.cfg
	}

	/// Gracefully shutdown bitcoind associated with this server.
	pub async fn shutdown_bitcoind(&self) {
		self.inner.bitcoind.stop().await.expect("error stopping bitcoind");
	}

	pub fn base_cmd() -> Command {
		let e = env::var(CAPTAIND_EXEC).expect("CAPTAIND_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve CAPTAIND_EXEC");
		Command::new(exec)
	}

	/// Creates server with a dedicated bitcoind daemon.
	pub fn new(name: impl AsRef<str>, bitcoind: Bitcoind, cfg: Config) -> Self {
		let helper = CaptaindHelper {
			name: name.as_ref().to_string(),
			cfg,
			bitcoind,
			slog_handlers: Arc::new(Mutex::new(Vec::new())),
		};

		Daemon::wrap(helper)
	}

	pub fn ark_url(&self) -> String {
		self.inner.ark_url()
	}

	pub async fn get_public_rpc(&self) -> ArkClient {
		ArkClient::connect(self.ark_url()).await.expect("can't connect server public rpc")
	}

	pub async fn get_wallet_rpc(&self) -> WalletAdminClient {
		WalletAdminClient::connect(self.inner.admin_url()).await.expect("can't connect server wallet rpc")
	}

	pub async fn get_round_rpc(&self) -> RoundAdminClient {
		RoundAdminClient::connect(self.inner.admin_url()).await.expect("can't connect server wallet rpc")
	}

	pub async fn get_sweep_rpc(&self) -> SweepAdminClient {
		SweepAdminClient::connect(self.inner.admin_url()).await.expect("can't connect server wallet rpc")
	}

	pub async fn ark_info(&self) -> ark::ArkInfo {
		self.get_public_rpc().await.get_ark_info(protos::Empty {}).await.unwrap()
			.into_inner().try_into().expect("invalid ark info")
	}

	pub async fn wallet_status(&self) -> WalletStatuses {
		let mut rpc = self.get_wallet_rpc().await;
		rpc.wallet_sync(protos::Empty{}).await.expect("sync error");
		let res = rpc.wallet_status(protos::Empty{}).await.expect("sync error").into_inner();
		WalletStatuses {
			rounds: res.rounds.unwrap().try_into().unwrap(),
			forfeits: res.forfeits.unwrap().try_into().unwrap(),
		}
	}

	pub async fn get_rounds_funding_address(&self) -> Address {
		let mut rpc = self.get_wallet_rpc().await;
		let response = rpc.wallet_status(protos::Empty {}).await.unwrap().into_inner();
		response.rounds.unwrap().address.parse::<Address<NetworkUnchecked>>().unwrap()
			.require_network(Network::Regtest).unwrap()
	}

	pub async fn trigger_round(&self) {
		let start = Instant::now();
		let minimum_wait = tokio::time::sleep(Duration::from_millis(500));
		let mut l1 = self.subscribe_log::<TipUpdated>();
		let mut l2 = self.subscribe_log::<TxIndexUpdateFinished>();
		self.bitcoind().generate(1).await;
		let _ = tokio::join!(l1.recv(), l2.recv(), minimum_wait);
		trace!("Waited {} ms before starting round", start.elapsed().as_millis());
		self.get_round_rpc().await.trigger_round(protos::Empty {}).await.unwrap();
	}

	pub async fn trigger_sweep(&self) {
		self.get_sweep_rpc().await.trigger_sweep(protos::Empty {}).await.unwrap();
	}

	pub fn add_slog_handler<L: SlogHandler + Send + Sync + 'static>(&self, handler: L) {
		self.inner.slog_handlers.lock().push(Box::new(handler));
	}

	/// Subscribe to all structured logs of the given type.
	pub fn subscribe_log<L: LogMsg>(&self) -> mpsc::UnboundedReceiver<L> {
		let (tx, rx) = sync::mpsc::unbounded_channel();
		self.add_slog_handler(move |log: &ParsedRecord| {
			if let Ok(msg) = log.try_as() {
				return tx.send(msg).is_err();
			}
			false
		});
		rx
	}

	/// Wait for the first occurrence of the given log message type and return it.
	pub async fn wait_for_log<L: LogMsg>(&self) -> L {
		let (tx, mut rx) = sync::mpsc::channel(1);
		self.add_slog_handler(move |log: &ParsedRecord| {
			if let Ok(msg) = log.try_as() {
				// if channel already closed, user is no longer interested
				let _ = tx.try_send(msg);
				return true;
			}
			false
		});
		rx.recv().await.expect("log wait channel closed")
	}
}

#[tonic::async_trait]
impl DaemonHelper for CaptaindHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.cfg.data_dir.clone()
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let config_file = self.datadir().join(CAPTAIND_CONFIG_FILE);

		let mut cmd = Captaind::base_cmd();
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
		trace!("public rpc address: {}", public_address.to_string());
		trace!("admin rpc address: {}", admin_address.to_string());

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

		let config_path = data_dir.join(CAPTAIND_CONFIG_FILE);
		info!("Preparing to create configuration file at: {}", config_path.display());
		let mut config_file = fs::File::create(&config_path).unwrap();
		self.cfg.write_into(&mut config_file)
			.with_context(|| format!("error writing server config to '{}'", config_path.display()))?;
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
						for handler in handlers.lock().iter_mut() {
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

impl CaptaindHelper {
	async fn try_is_ready(&self) -> anyhow::Result<()> {
		let mut public = ArkClient::connect(self.ark_url()).await.context("public rpc")?;
		let req = protos::HandshakeRequest { bark_version: None };
		let _ = public.handshake(req).await.context("handshake")?;

		let mut wallet = WalletAdminClient::connect(self.admin_url()).await.context("wallet")?;
		let _ = wallet.wallet_status(protos::Empty {}).await.context("wallet status")?;

		Ok(())
	}

	async fn is_ready(&self) -> bool {
		if let Err(e) = self.try_is_ready().await {
			trace!("Error from is_ready: {}", e.full_msg());
			false
		} else {
			true
		}
	}

	pub fn ark_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.public_address)
	}

	pub fn admin_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.admin_address.expect("missing admin addr"))
	}

	async fn create(&self) -> anyhow::Result<()> {
		let config_file = self.datadir().join(CAPTAIND_CONFIG_FILE);

		let mut cmd = Captaind::base_cmd();
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
			bail!("Failed to create captaind '{}'", self.name);
		}
	}
}
