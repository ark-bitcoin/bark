pub mod bitcoind;
pub mod electrs;
pub mod aspd;
pub mod lightningd;

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Command, Child};
use tokio::sync::Mutex;

use crate::constants::env::DAEMON_INIT_TIMEOUT_MILLIS;
use crate::util::wait_for_completion;

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

pub trait LogHandler {
	/// Process a log line. Return true when you're done.
	fn process_log(&mut self, line: &str) -> bool;
}

impl<F> LogHandler for F
where
	F: FnMut(&str) -> bool,
{
	fn process_log(&mut self, line: &str) -> bool {
		self(line)
	}
}

pub trait DaemonHelper {
	fn name(&self) -> &str;
	fn datadir(&self) -> PathBuf;
	fn make_reservations(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send;
	fn prepare(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
	fn get_command(&self) -> impl Future<Output = anyhow::Result<Command>> + Send;
	fn wait_for_init(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

pub struct Daemon<T>
	where T : DaemonHelper + Send + Sync + 'static
{
	pub name: String,
	inner: T,
	daemon_state: Mutex<DaemonState>,
	child: Mutex<Option<Child>>,
	stdout_handler: Arc<Mutex<Vec<Box<dyn LogHandler + Send + Sync + 'static>>>>,
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
			stdout_handler: Arc::new(Mutex::new(vec![])),
		}
	}

	pub fn name(&self) -> &str {
		return self.inner.name()
	}

	pub async fn start(&mut self) -> anyhow::Result<()> {
		info!("Starting {}", self.name);
		*self.daemon_state.get_mut() = DaemonState::Starting;

		let retries = 3;
		for i in 0..retries {
			match self.try_start().await {
				Ok(_) => {
					info!("Started {}", self.name);
					*self.daemon_state.get_mut() = DaemonState::Running;
					return Ok(());
				},
				Err(err) => {
					warn!("{:?}", err);
					warn!("Failed attempt to start {}. This was attempt {} of {}", self.name, i, retries);
				}
			}
		}

		error!("Failed to start {}", self.name);
		*self.daemon_state.get_mut() = DaemonState::Error;
		anyhow::bail!("Failed to launch daemon");
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
		cmd.stdout(std::fs::File::create(&stdout_path)?);
		cmd.stderr(std::fs::File::create(&stderr_path)?);
		let mut child = cmd.spawn()?;

		// Read the log-file for stdout
		info!("Process the file");
		let (path,handler) = (stdout_path.clone(), self.stdout_handler.clone());
		let _jh = tokio::spawn(async move {
			process_log_file(path, handler).await
		});
		info!("Spawn completed the file");


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
					.with_context(|| format!("Daemon {} errorded during wait_for_init", self.inner.name()))
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

		match self.child.lock().await.take() {
			Some(mut child) => child.kill().await.context("Failed to kill child")?,
			None => anyhow::bail!("Failed to stop daemon because there is no child. Was it running?")
		};


		info!("Stopped {}", self.name);
		*state_lock = DaemonState::Stopped;
		Ok(())
	}

	pub async fn join(&self) -> anyhow::Result<()> {
		match &mut *self.child.lock().await {
			Some(ref mut child) => child.wait().await?,
			None => anyhow::bail!("Failed to wait for daemon to complete. Was it running?")
		};

		Ok(())
	}

	pub async fn add_stdout_handler<L: LogHandler + Send + Sync + 'static>(&self, log_handler: L) {
		let mut handlers = self.stdout_handler.lock().await;
		handlers.push(Box::new(log_handler));
	}
}

impl<T> Drop for Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	fn drop(&mut self) {
		match self.child.get_mut() {
			Some(ref mut c) => { let _ = c.kill(); },
			None => {}
		}
	}
}


async fn process_log_file<P: AsRef<Path>>(
	filename: P,
	handlers: Arc<Mutex<Vec<Box<dyn LogHandler + Send + Sync + 'static>>>>
) -> ! {
	let file = tokio::fs::File::open(filename).await.expect("failed to open log file");
	let buf_reader = BufReader::new(file);
	let mut lines = buf_reader.lines();

	loop {
		match lines.next_line().await.expect("I/O error on log file handle") {
			Some(line) => {
				for handler in handlers.lock().await.iter_mut() {
					handler.process_log(&line);
				}
			},
			None => {
				tokio::time::sleep(std::time::Duration::from_millis(50)).await;
			},
		}
	}
}
