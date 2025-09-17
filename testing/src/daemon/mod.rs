pub mod captaind;
pub mod bitcoind;
pub mod electrs;
pub mod lightningd;
pub mod postgres;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use log::{error, info, trace, warn};
use nix::sys::signal;
use nix::unistd::Pid;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Command, Child};
use tokio::sync::{mpsc, Mutex};

use crate::constants::env::DAEMON_INIT_TIMEOUT_MILLIS;
use crate::util::{FutureExt, wait_for_completion};

/// The file inside the datadir where stderr output is logged.
pub const STDERR_LOGFILE: &str = "stderr.log";

/// The file inside the datadir where stdout output is logged.
pub const STDOUT_LOGFILE: &str = "stdout.log";

pub enum DaemonState {
	Init,
	Starting,
	Running,
	Stopping,
	Stopped,
	Error
}

pub trait LogHandler: Send + Sync + 'static {
	/// Process a log line. Return true when you're done.
	fn process_log(&mut self, line: &str) -> bool;
}

impl<F> LogHandler for F
where
	F: FnMut(&str) -> bool + Send + Sync + 'static,
{
	fn process_log(&mut self, line: &str) -> bool {
		self(line)
	}
}

#[tonic::async_trait]
pub trait DaemonHelper {
	fn name(&self) -> &str;
	fn datadir(&self) -> PathBuf;
	async fn get_command(&self) -> anyhow::Result<Command>;
	async fn make_reservations(&mut self) -> anyhow::Result<()>;
	async fn prepare(&self) -> anyhow::Result<()>;

	/// A hook to run right after daemon succesfully started.
	async fn post_start(&mut self) -> anyhow::Result<()> {
		Ok(())
	}

	async fn wait_for_init(&self) -> anyhow::Result<()>;
}

pub struct Daemon<T>
	where T : DaemonHelper + Send + Sync + 'static
{
	pub name: String,
	inner: T,
	daemon_state: Mutex<DaemonState>,
	child: Mutex<Option<Child>>,
	log_handler_tx: Option<mpsc::Sender<Box<dyn LogHandler>>>,
}

impl<T> Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	pub fn wrap(inner : T) -> Self {
		Self {
			name: inner.name().to_owned(),
			inner: inner,
			daemon_state: Mutex::new(DaemonState::Init),
			child: Mutex::new(None),
			log_handler_tx: None,
		}
	}

	pub fn name(&self) -> &str {
		return self.inner.name()
	}

	pub async fn start(&mut self) -> anyhow::Result<()> {
		info!("Starting {}", self.name);
		*self.daemon_state.get_mut() = DaemonState::Starting;

		let mut tries = 3;
		let res = loop {
			match self.try_start().await {
				Ok(_) => break Ok(()),
				Err(err) => {
					warn!("{:?}", err);
					if tries == 0 {
						break Err(err);
					} else {
						tries -= 1;
						warn!("Failed attempt to start {}. Retrying {} more times...",
							self.name, tries,
						);
					}
				}
			}
		};

		match res {
			Ok(()) => {
				if let Err(e) = self.inner.post_start().await {
					*self.daemon_state.get_mut() = DaemonState::Error;
					bail!("post_start hook failed for '{}': {}", e, self.name);
				}

				info!("Started {}", self.name);
				*self.daemon_state.get_mut() = DaemonState::Running;
				Ok(())
			},
			Err(e) => {
				*self.daemon_state.get_mut() = DaemonState::Error;
				bail!("Failed to launch daemon: {}", e);
			},
		}
	}

	pub async fn try_start(&mut self) -> anyhow::Result<()> {
		trace!("Preparing {}", self.name);
		self.inner.make_reservations().await?;
		self.inner.prepare().await?;

		let mut cmd = self.inner.get_command().await?;
		cmd.kill_on_drop(true);

		// Create files to where the outputs is logged
		let stdout_path = self.inner.datadir().join(STDOUT_LOGFILE);
		let stderr_path = self.inner.datadir().join(STDERR_LOGFILE);
		cmd.stdout(std::fs::File::options().create(true).append(true).open(&stdout_path)?);
		cmd.stderr(std::fs::File::options().create(true).append(true).open(&stderr_path)?);

		let mut child = cmd.spawn()?;

		// Read the log-file for stdout
		let (log_hander_tx, log_handler_rx) = mpsc::channel(8);
		let _jh = tokio::spawn(process_log_file(stdout_path.clone(), log_handler_rx));
		self.log_handler_tx = Some(log_hander_tx);

		// Wait for initialization
		let init_timeout = std::env::var(DAEMON_INIT_TIMEOUT_MILLIS)
			.unwrap_or("30000".into())
			.parse::<u64>()
			.map(|s| Duration::from_millis(s))
			.expect("DAEMON_INIT_TIMEOUT_MILLIS should be a number");

		let is_initialized = tokio::time::timeout(init_timeout, self.inner.wait_for_init());
		let child_died = wait_for_completion(&mut child);

		let result = tokio::select!(
			val = is_initialized => {
				val
					.with_context(|| format!("Daemon {} failed to initialize within reasonable time", self.inner.name()))?
					.with_context(|| format!("Daemon {} errored during wait_for_init", self.inner.name()))
			}
			_ = child_died => {
				bail!("Daemon {} stopped running before initialization", self.inner.name())
			}
		);

		match result {
			Ok(()) => {
				*self.child.get_mut() = Some(child);
				Ok(())
			},
			Err(e) => {
				error!("Daemon '{}' failed to start.", self.name);
				match fs::read_to_string(&stderr_path) {
					Ok(c) => error!("stderr: {c}"),
					Err(e) => error!("failed to read stderr at {}: {}", stderr_path.display(), e),
				}
				match fs::read_to_string(&stdout_path) {
					Ok(c) => error!("stdout: {c}"),
					Err(e) => error!("failed to read stdout at {}: {}", stdout_path.display(), e),
				}
				Err(e)
			}
		}
	}

	pub async fn stop(&self) -> anyhow::Result<()> {
		trace!("Stopping {}", self.name);
		let mut state_lock = self.daemon_state.lock().await;
		*state_lock = DaemonState::Stopping;

		let mut child_lock = self.child.lock().await;
		let child = child_lock.as_mut().expect("daemon not started yet");

		if let Some(pid) = child.id() {
			// Send SIGTERM
			let pid = Pid::from_raw(pid as i32);
			signal::kill(pid, signal::Signal::SIGTERM).expect("sending SIGTERM failed");
		}

		match child.wait().try_wait(30_000).await {
			Ok(Ok(s)) => if s.success() {
				info!("Daemon {} succesfully shut down gracefully", self.name);
			} else {
				warn!("Daemon {} shut down with exit status {}", self.name, s);
			},
			Ok(Err(e)) => error!("Error sending TERM signal to daemon {}: {}", self.name, e),
			Err(_) => warn!("Shutting down daemon {} timed out", self.name),
		}

		// In case that failed, we send a SIGKILL
		if let Some(pid) = child.id() {
			let pid = nix::unistd::Pid::from_raw(pid as i32);
			signal::kill(pid, signal::Signal::SIGKILL).expect("sending SIGKILL failed");
		}

		info!("Stopped {}", self.name);
		*state_lock = DaemonState::Stopped;
		Ok(())
	}

	pub fn add_stdout_handler<L: LogHandler>(&self, log_handler: L) {
		self.log_handler_tx.as_ref().expect("not started yet")
			.try_send(Box::new(log_handler))
			.expect("too many log handlers pending");
	}
}

impl<T> Drop for Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	fn drop(&mut self) {
		if let Some(child) = self.child.get_mut() {
			if let Some(pid) = child.id() {
				let pid = nix::unistd::Pid::from_raw(pid as i32);
				nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
					.expect("error sending SIGKILL");
			}
		}
	}
}


async fn process_log_file<P: AsRef<Path>>(
	filename: P,
	mut log_handler_rx: mpsc::Receiver<Box<dyn LogHandler>>,
) {
	let file = tokio::fs::File::open(filename).await.expect("failed to open log file");
	let mut reader = BufReader::new(file);

	let mut handlers = Vec::new();
	let mut line = String::new();
	loop {
		loop {
			match log_handler_rx.try_recv() {
				Ok(h) => handlers.push(h),
				Err(mpsc::error::TryRecvError::Empty) => break,
				Err(mpsc::error::TryRecvError::Disconnected) => return,
			}
		}

		line.clear();
		match reader.read_line(&mut line).await.expect("I/O error on log file handle") {
			0 => tokio::time::sleep(Duration::from_millis(100)).await,
			_ => handlers.retain_mut(|h| !h.process_log(&line)),
		}
	}
}

