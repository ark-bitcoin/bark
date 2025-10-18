pub mod proxy;

use std::sync::Arc;
use std::{env, fs};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, Network, Txid};
use bitcoin::address::{Address, NetworkUnchecked};
use log::{info, trace};
use parking_lot::Mutex;
use tokio::sync::{self, mpsc};
use tokio::process::Command;

use server_log::{FinishedPoolIssuance, LogMsg, ParsedRecord, TipUpdated, TxIndexUpdateFinished};
use server_rpc::{self as rpc, protos};
pub use server::config::{self, Config};

use crate::daemon::captaind::proxy::{ArkRpcProxy, ArkRpcProxyServer};
use crate::{secs, Bitcoind, Daemon, DaemonHelper, TestContext};
use crate::daemon::LogHandler;
use crate::constants::env::CAPTAIND_EXEC;
use crate::util::resolve_path;

pub type Captaind = Daemon<CaptaindHelper>;

pub type ArkClient = rpc::ArkServiceClient<tonic::transport::Channel>;
pub type WalletAdminClient = rpc::admin::WalletAdminServiceClient<tonic::transport::Channel>;
pub type RoundAdminClient = rpc::admin::RoundAdminServiceClient<tonic::transport::Channel>;
pub type SweepAdminClient = rpc::admin::SweepAdminServiceClient<tonic::transport::Channel>;


pub const CAPTAIND_CONFIG_FILE: &str = "config.toml";


pub trait SlogHandler: Send + Sync + 'static {
	/// Process a log line. Return true when you're done.
	fn process_slog(&mut self, log: &ParsedRecord) -> bool;
}

impl<F> SlogHandler for F
where
	F: FnMut(&ParsedRecord) -> bool + Send + Sync + 'static,
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

#[derive(Debug)]
pub enum VtxoPoolState {
	Ready(Txid),
	NotReady,
}

impl Default for VtxoPoolState {
	fn default() -> Self { VtxoPoolState::NotReady }
}

#[derive(Debug, Default)]
pub struct State {
	vtxopool_state: VtxoPoolState,
}

impl SlogHandler for Arc<parking_lot::Mutex<State>> {
	fn process_slog(&mut self, log: &ParsedRecord) -> bool {
	    if let Ok(FinishedPoolIssuance { txid, .. }) = log.try_as::<FinishedPoolIssuance>() {
			self.lock().vtxopool_state = VtxoPoolState::Ready(txid);
		}

		false
	}
}

pub struct CaptaindHelper {
	name: String,
	cfg: Config,
	bitcoind: Bitcoind,
	slog_handler_tx: Mutex<Option<mpsc::Sender<Box<dyn SlogHandler>>>>,
	state: Arc<parking_lot::Mutex<State>>,
}

impl Captaind {
	pub fn bitcoind(&self) -> &Bitcoind {
		&self.inner.bitcoind
	}

	pub fn config(&self) -> &Config {
		&self.inner.cfg
	}

	pub fn config_mut(&mut self) -> &mut Config {
		&mut self.inner.cfg
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
			slog_handler_tx: Mutex::new(None),
			state: Arc::new(parking_lot::Mutex::new(State::default())),
		};

		Daemon::wrap(helper)
	}

	pub async fn get_custom_command(&self, args: &[&str]) -> anyhow::Result<Command> {
		self.inner.get_custom_command(args).await
	}

	pub async fn integration_cmd(&self, args: &[&str]) -> String {
		let mut full_args = Vec::with_capacity(args.len() + 1);
		full_args.push("integration");
		full_args.extend_from_slice(args);
		let output = self.get_custom_command(full_args.as_slice()).await.unwrap().output().await
			.expect("Failed to spawn process and capture output");

		let stdout = String::from_utf8(output.stdout).expect("stdout is valid utf-8");
		trace!("captaind command '{:?}' stdout: {}", args, stdout);

		let stderr = String::from_utf8(output.stderr).expect("stderr is valid utf-8");
		trace!("captaind command '{:?}' stderr: {}", args, stderr);
		// Filter out lines that start with '['
		let filtered_stdout = stdout
			.lines()
			.filter(|line| !line.trim_start().starts_with('['))
			.collect::<Vec<_>>();
		let last_line_stdout = filtered_stdout[filtered_stdout.len() - 1];
		trace!("captaind command '{:?}' stdout-filtered: {}", args, last_line_stdout);

		last_line_stdout.to_string()
	}

	pub fn ark_url(&self) -> String {
		self.inner.ark_url()
	}

	pub async fn get_public_rpc(&self) -> ArkClient {
		ArkClient::connect(self.ark_url()).await.expect("can't connect server public rpc")
	}

	pub async fn get_proxy_rpc(&self, proxy: impl ArkRpcProxy) -> ArkRpcProxyServer {
		ArkRpcProxyServer::start(proxy, self.get_public_rpc().await).await
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

	pub fn add_slog_handler<L: SlogHandler>(&self, handler: L) {
		self.inner.slog_handler_tx.lock().as_ref().expect("not started yet")
			.try_send(Box::new(handler)).expect("too many slog handlers pending");
	}

	/// Subscribe to all structured logs of the given type.
	pub fn subscribe_log<L: LogMsg>(&self) -> mpsc::UnboundedReceiver<L> {
		info!("Subscribing to {} logs", L::LOGID);
		let (tx, rx) = sync::mpsc::unbounded_channel();
		self.add_slog_handler(move |log: &ParsedRecord| {
			if let Ok(msg) = log.try_as() {
				info!("Captured {} log", L::LOGID);
				return tx.send(msg).is_err();
			}
			false
		});
		rx
	}

	/// Wait for the first occurrence of the given log message type and return it.
	pub async fn wait_for_log<L: LogMsg>(&self) -> L {
		info!("Waiting for log {}", L::LOGID);
		let (tx, mut rx) = sync::mpsc::channel(1);
		self.add_slog_handler(move |log: &ParsedRecord| {
			if let Ok(msg) = log.try_as() {
				// if channel already closed, user is no longer interested
				let _ = tx.try_send(msg);
				return true;
			}
			false
		});
		let ret = rx.recv().await.expect("log wait channel closed");
		info!("Got {} log!", L::LOGID);
		ret
	}

	/// Wait until the vtxopool is ready
	pub async fn wait_for_vtxopool(&self, ctx: &TestContext) {
		info!("Waiting for VtxoPool...");
		loop {
			if let VtxoPoolState::Ready(txid) = self.inner.state.lock().vtxopool_state {
				info!("VtxoPool ready: waiting for tx {} propagation", txid);
				ctx.await_transaction(txid).await;
				return;
			}
			tokio::time::sleep(secs(1)).await;
		}
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
		let config_file = self.get_config_file().await;

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
		let integration_port = portpicker::pick_unused_port().expect("No ports free");

		let public_address = format!("0.0.0.0:{}", public_port);
		let admin_address = format!("127.0.0.1:{}", admin_port);
		let integration_address = format!("127.0.0.1:{}", integration_port);
		trace!("public rpc address: {}", public_address.to_string());
		trace!("admin rpc address: {}", admin_address.to_string());
		trace!("integration rpc address: {}", integration_port.to_string());

		self.cfg.rpc = config::Rpc {
			public_address: SocketAddr::from_str(public_address.as_str())?,
			admin_address: Some(SocketAddr::from_str(admin_address.as_str())?),
			integration_address: Some(SocketAddr::from_str(integration_address.as_str())?),
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

	async fn wait_for_init(&self) -> anyhow::Result<()> {
		while !self.is_ready().await {
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		Ok(())
	}

	async fn post_start(
		&mut self,
		log_handler_tx: &mpsc::Sender<Box<dyn LogHandler>>,
	) -> anyhow::Result<()> {
		log_handler_tx.send(self.init_slog_handler()).await.unwrap();
		Ok(())
	}
}

impl CaptaindHelper {
	async fn get_custom_command(&self, args: &[&str]) -> anyhow::Result<Command> {
		let config_file = self.get_config_file().await;

		let mut cmd = Captaind::base_cmd();
		let mut new_args = args.to_vec();
		new_args.push("--config");
		new_args.push(config_file.to_str().unwrap());

		trace!("base_cmd={:?}; args={:?}", cmd, new_args);
		cmd.args(new_args);

		Ok(cmd)
	}

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
			trace!("Error from is_ready: {:#}", e);
			false
		} else {
			true
		}
	}

	async fn get_config_file(&self) -> PathBuf {
		self.datadir().join(CAPTAIND_CONFIG_FILE)
	}

	pub fn ark_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.public_address)
	}

	pub fn admin_url(&self) -> String {
		format!("http://{}", self.cfg.rpc.admin_address.expect("missing admin addr"))
	}

	async fn create(&self) -> anyhow::Result<()> {
		let config_file = self.get_config_file().await;

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

	/// Initialize the [LogHandler] that will drive slog handlers
	fn init_slog_handler(&mut self) -> Box<dyn LogHandler> {
		/// This handler will forward the raw stdout log lines into
		/// the slog handlers after parsing
		struct Handler {
			handlers: Vec<Box<dyn SlogHandler>>,
			hadler_rx: mpsc::Receiver<Box<dyn SlogHandler>>,
		}

		impl LogHandler for Handler {
			fn process_log(&mut self, line: &str) -> bool {
				loop {
					match self.hadler_rx.try_recv() {
						Ok(h) => self.handlers.push(h),
						Err(mpsc::error::TryRecvError::Empty) => break,
						Err(mpsc::error::TryRecvError::Disconnected) => return true,
					}
				}

				if !self.handlers.is_empty() {
					let log = serde_json::from_str::<ParsedRecord>(&line)
						.expect("error parsing slog line");
					if log.is_slog() {
						self.handlers.retain_mut(|h| !h.process_slog(&log));
					}
				}

				false
			}
		}

		let (tx, rx) = mpsc::channel(8);
		*self.slog_handler_tx.lock() = Some(tx);
		Box::new(Handler {
			handlers: vec![Box::new(self.state.clone())],
			hadler_rx: rx,
		})
	}
}
