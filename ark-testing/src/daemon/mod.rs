pub mod bitcoind;
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

use crate::util::is_running;

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
	inner : T,
	daemon_state: DaemonState,
	child: Option<Child>,
	stdout_handler: Arc<Mutex<Vec<Box<dyn LogHandler + Send + Sync + 'static>>>>,
}

impl<T> Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	pub fn wrap(inner : T) -> Self {
		Self {
			inner,
			daemon_state: DaemonState::Init,
			child: None,
			stdout_handler: Arc::new(Mutex::new(vec![])),
		}
	}
}

impl<T> Daemon<T>
	where T : DaemonHelper + Send + Sync + 'static
{
	pub fn name(&self) -> &str {
		return self.inner.name()
	}

	pub async fn start(&mut self) -> anyhow::Result<()> {
		info!("Starting {}", self.inner.name());
		self.daemon_state = DaemonState::Starting;

		trace!("Preparing {}", self.inner.name());
		self.inner.prepare().await?;

		let retries = 3;
		for i in 0..retries {
			match self.try_start().await {
				Ok(_) => {
					info!("Started {}", self.inner.name());
					self.daemon_state = DaemonState::Running;
					return Ok(());
				},
				Err(_) => {
					warn!("Failed attempt to start {}. This was attempt {} of {}", self.inner.name(), i, retries);
				}
			}
		}

		error!("Failed to start {}", self.inner.name());
		self.daemon_state = DaemonState::Error;
		anyhow::bail!("Failed to launch daemon");
	}

	pub async fn try_start(&mut self) -> anyhow::Result<()> {
		self.inner.make_reservations().await?;

		let mut cmd = self
			.inner
			.get_command()
			.await?;
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


		// Wait for init
		// But check every 100 milliseconds if the Child is
		// still running
		let success = loop {
			if !is_running(&mut child) {
				break false;
			}
			let duration = Duration::from_millis(100);
			if let Ok(res) = tokio::time::timeout(duration, self.inner.wait_for_init()).await {
				res?;
				break true;
			}
		};

		if success {
			self.child = Some(child);
			Ok(())
		} else {
			error!("Daemon '{}' failed to start.", self.name());
			match fs::read_to_string(&stderr_path) {
				Ok(c) => error!("stderr: {c}"),
				Err(e) => error!("failed to read stderr at {}: {}", stderr_path.display(), e),
			}
			match fs::read_to_string(&stdout_path) {
				Ok(c) => error!("stdout: {c}"),
				Err(e) => error!("failed to read stdout at {}: {}", stdout_path.display(), e),
			}
			anyhow::bail!("Failed to initialize {}", self.name());
		}
	}


	pub async fn stop(&mut self) -> anyhow::Result<()> {
		trace!("Stopping {}", self.inner.name());
		self.daemon_state = DaemonState::Stopping;

		match self.child.take() {
			Some(mut child) => child.kill().await.context("Failed to kill child")?,
			None => anyhow::bail!("Failed to stop daemon because there is no child. Was it running?")
		};


		info!("Stopped {}", self.inner.name());
		self.daemon_state = DaemonState::Stopped;
		Ok(())
	}

	pub async fn join(&mut self) -> anyhow::Result<()> {
		match self.child.take() {
			Some(mut child) => child.wait().await?,
			None => anyhow::bail!("Failed to wait for daemon to complete. Was it running?")
		};

		Ok(())
	}

	pub async fn add_stdout_handler<L: LogHandler + Send + Sync + 'static>(&mut self, log_handler: L) {
		let mut handlers = self.stdout_handler.lock().await;
		handlers.push(Box::new(log_handler));
	}
}

impl<T> Drop for Daemon<T>
	where T: DaemonHelper + Send + Sync + 'static
{
	fn drop(&mut self) {
		match self.child.take() {
			Some(mut c) => { let _ = c.kill(); },
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
