
use std::sync::Arc;
use std::{env, fs};
use std::time::Duration;
use std::path::PathBuf;

use anyhow::Context;
use bitcoin_ext::BlockHeight;
use log::{error, info, trace, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::{self, mpsc};
use tokio::process::Command;

use server_log::{parse_record, ParsedRecord, LogMsg, SyncedToHeight};
pub use server::config::watchmand::{self, Config};

use crate::{Bitcoind, Daemon, DaemonHelper};
use crate::daemon::{LogHandler, STDOUT_LOGFILE};
use crate::daemon::captaind::SlogHandler;
use crate::constants::env::WATCHMAND_EXEC;
use crate::util::resolve_path;

pub type Watchmand = Daemon<WatchmandHelper>;


pub const WATCHMAND_CONFIG_FILE: &str = "config.toml";
pub const HUMAN_READABLE_LOGFILE: &str = "stdout.hr.log";

#[derive(Debug, Default)]
pub struct State {
	sync_height: BlockHeight,
}

impl SlogHandler for Arc<parking_lot::Mutex<State>> {
	fn process_slog(&mut self, log: &ParsedRecord) -> bool {
		if log.is::<SyncedToHeight>() {
			let sth = log.try_as::<SyncedToHeight>().unwrap();
			self.lock().sync_height = sth.height;
		}

		false
	}
}

pub struct WatchmandHelper {
	name: String,
	cfg: Config,
	bitcoind: Arc<Bitcoind>,
	slog_handler_tx: parking_lot::Mutex<Option<mpsc::Sender<Box<dyn SlogHandler>>>>,
	state: Arc<parking_lot::Mutex<State>>,
}

impl Watchmand {
	pub fn bitcoind(&self) -> &Arc<Bitcoind> {
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
		let e = env::var(WATCHMAND_EXEC).expect("WATCHMAND_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve WATCHMAND_EXEC");
		Command::new(exec)
	}

	/// Creates server with a dedicated bitcoind daemon.
	pub fn new(name: impl AsRef<str>, bitcoind: Arc<Bitcoind>, cfg: Config) -> Self {
		let helper = WatchmandHelper {
			name: name.as_ref().to_string(),
			cfg,
			bitcoind,
			slog_handler_tx: parking_lot::Mutex::new(None),
			state: Arc::new(parking_lot::Mutex::new(State::default())),
		};

		Daemon::wrap(helper)
	}

	pub async fn get_custom_command(&self, args: &[&str]) -> anyhow::Result<Command> {
		self.inner.get_custom_command(args).await
	}

	pub fn add_slog_handler<L: SlogHandler>(&self, handler: L) {
		self.inner.slog_handler_tx.lock().as_ref().expect("not started yet")
			.try_send(Box::new(handler)).expect("too many slog handlers pending");
	}

	/// Subscribe to all tracing logs of the given type.
	pub fn subscribe_log<L: LogMsg>(&self) -> mpsc::UnboundedReceiver<L> {
		trace!("Subscribing to {} tracing logs", L::LOGID);
		let (tx, rx) = sync::mpsc::unbounded_channel();
		self.add_slog_handler(move |log: &ParsedRecord| {
			if log.is::<L>() {
				trace!("Captured {} log", L::LOGID);
				return tx.send(log.try_as::<L>().unwrap()).is_err();
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
			if log.is::<L>() {
				// if channel already closed, user is no longer interested
				let _ = tx.try_send(log.try_as::<L>().unwrap());
				return true;
			}
			false
		});
		let ret = rx.recv().await.expect("log wait channel closed");
		info!("Got {} log!", L::LOGID);
		ret
	}

	/// Wait until synced to the given height
	pub async fn wait_for_sync_height(&self, height: BlockHeight) {
		info!("Waiting for sync height {}...", height);
		loop {
			if self.inner.state.lock().sync_height >= height {
				return;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}
}

#[async_trait]
impl DaemonHelper for WatchmandHelper {
	fn name(&self) -> &str {
		&self.name
	}

	fn datadir(&self) -> PathBuf {
		self.cfg.data_dir.clone()
	}

	async fn get_command(&self) -> anyhow::Result<Command> {
		let config_file = self.get_config_file().await;

		let mut cmd = Watchmand::base_cmd();
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
		Ok(())
	}

	async fn prepare(&self) -> anyhow::Result<()> {
		let data_dir = self.datadir();
		if !data_dir.exists() {
			info!("Data directory {:?} does not exist. Creating...", data_dir);
			std::fs::create_dir_all(data_dir.clone())?;
		}

		let config_path = data_dir.join(WATCHMAND_CONFIG_FILE);
		info!("Preparing to create configuration file at: {}", config_path.display());
		let mut config_file = fs::File::create(&config_path).unwrap();
		self.cfg.write_into(&mut config_file)
			.with_context(|| format!("error writing server config to '{}'", config_path.display()))?;
		info!("Configuration file successfully created at: {}", config_path.display());

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

		// create human-readable log file if we have our `slf` tool
		spawn_slf_pipe(self.datadir()).await;

		Ok(())
	}
}

impl WatchmandHelper {
	async fn get_custom_command(&self, args: &[&str]) -> anyhow::Result<Command> {
		let config_file = self.get_config_file().await;

		let mut cmd = Watchmand::base_cmd();
		let mut new_args = args.to_vec();
		new_args.push("--config");
		new_args.push(config_file.to_str().unwrap());

		trace!("base_cmd={:?}; args={:?}", cmd, new_args);
		cmd.args(new_args);

		Ok(cmd)
	}

	async fn try_is_ready(&self) -> anyhow::Result<()> {
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
		self.datadir().join(WATCHMAND_CONFIG_FILE)
	}

	/// Initialize the [LogHandler] that will drive slog handlers
	fn init_slog_handler(&mut self) -> Box<dyn LogHandler> {
		/// This handler will forward the raw stdout log lines into
		/// the slog handlers after parsing
		struct Handler {
			handlers: Vec<Box<dyn SlogHandler>>,
			handler_rx: mpsc::Receiver<Box<dyn SlogHandler>>,
		}

		impl LogHandler for Handler {
			fn process_log(&mut self, line: &str) -> bool {
				loop {
					match self.handler_rx.try_recv() {
						Ok(h) => self.handlers.push(h),
						Err(mpsc::error::TryRecvError::Empty) => break,
						Err(mpsc::error::TryRecvError::Disconnected) => return true,
					}
				}

				if !self.handlers.is_empty() {
					let log = parse_record(&line)
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
			handler_rx: rx,
		})
	}
}

/// Check if the `slf` command is available on the system.
async fn is_slf_available() -> bool {
	tokio::process::Command::new("which")
		.arg("slf")
		.output()
		.await
		.map(|output| output.status.success())
		.unwrap_or(false)
}

/// Spawns a task that reads stdout.log and pipes it through slf to stdout.hr.log
async fn spawn_slf_pipe(datadir: PathBuf) {
	// Check if slf is available
	if !is_slf_available().await {
		trace!("slf not available, skipping formatted log output");
		return;
	}

	tokio::spawn(async move {
		let stdout_path = datadir.join(STDOUT_LOGFILE);
		let out_path = datadir.join(HUMAN_READABLE_LOGFILE);

		// Spawn slf process
		let out_file = match std::fs::File::options()
			.create(true)
			.append(true)
			.open(&out_path)
		{
			Ok(f) => f,
			Err(e) => {
				warn!("Failed to create slf log file: {}", e);
				return;
			}
		};

		let mut cmd = tokio::process::Command::new("slf");
		cmd.stdin(std::process::Stdio::piped());
		cmd.stdout(out_file);
		cmd.stderr(std::process::Stdio::null());
		cmd.kill_on_drop(true);

		let mut child = match cmd.spawn() {
			Ok(c) => {
				info!("slf process spawned, human-readable output will be written to {}",
					out_path.display(),
				);
				c
			},
			Err(e) => {
				warn!("Failed to spawn slf: {}", e);
				return;
			}
		};

		let mut stdin = child.stdin.take().expect("slf stdin was piped");

		// Open and read from stdout.log
		let in_file = match tokio::fs::File::open(&stdout_path).await {
			Ok(f) => f,
			Err(e) => {
				error!("Failed to open stdout.log for slf reader: {}", e);
				return;
			}
		};

		let mut reader = tokio::io::BufReader::new(in_file);
		let mut line = String::new();
		loop {
			line.clear();
			match reader.read_line(&mut line).await {
				Ok(0) => {
					// EOF or no data yet, wait a bit
					tokio::time::sleep(std::time::Duration::from_millis(100)).await;
				}
				Ok(_) => {
					if let Err(e) = stdin.write_all(line.as_bytes()).await {
						warn!("slf pipe closed or error occurred: {}", e);
						break;
					}
				}
				Err(e) => {
					warn!("Error reading stdout.log for slf: {}", e);
					break;
				}
			}
		}

		let _ = stdin.flush().await;
		drop(stdin);
		let _ = child.wait().await;
	});
}
