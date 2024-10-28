pub mod bitcoind;
pub mod aspd;
pub mod lightningd;

use std::fs;
use std::future::Future;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

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
	fn process_log(&mut self, line: &str);
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
	stdout_jh: Option<JoinHandle<()>>,
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
			stdout_jh: None,
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

		cmd.stdout(Stdio::piped());
		let stderr_path = self.inner.datadir().join(STDERR_LOGFILE);
		cmd.stderr(std::fs::File::create(&stderr_path)?);

		trace!("{}: Trying to spawn {:?}", self.inner.name(), cmd);
		let mut child = cmd.spawn()?;

		let stdout = child.stdout.take().unwrap();
		let stdout_log = self.stdout_handler.clone();
		let stdout_path = self.inner.datadir().join(STDOUT_LOGFILE);
		let mut stdout_logfile = BufWriter::new(std::fs::File::create(&stdout_path)?);

		self.stdout_jh = Some(std::thread::spawn(move || {
			let reader = BufReader::new(stdout);
			for line in reader.lines() {
				let line = line.unwrap();
				// first write to our logfile
				stdout_logfile.write_all(line.as_bytes()).expect("stdout logfile error");
				stdout_logfile.write_all("\n".as_bytes()).expect("stdout logfile error");
				// then invoke custom handlers
				for handler in stdout_log.lock().unwrap().iter_mut() {
					handler.process_log(&line)
				}
			}
		}));

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
			match fs::read_to_string(&stderr_path) {
				Ok(c) => error!("Daemon '{}' failed to start, stderr: {}", self.name(), c),
				Err(e) => error!("Daemon '{}' failed to start and failed to read stderr at {}: {}",
					self.name(), stderr_path.display(), e),
			}
			anyhow::bail!("Failed to initialize {}", self.name());
		}
	}

	pub async fn stop(&mut self) -> anyhow::Result<()> {
		trace!("Stopping {}", self.inner.name());
		self.daemon_state = DaemonState::Stopping;

		match self.child.take() {
			Some(mut child) => tokio::task::spawn_blocking(move || child.kill()).await?,
			None => anyhow::bail!("Failed to stop daemon because there is no child. Was it running?")
		}?;


		info!("Stopped {}", self.inner.name());
		self.daemon_state = DaemonState::Stopped;
		Ok(())
	}

	pub async fn join(&mut self) -> anyhow::Result<()> {

		match self.child.take() {
			Some(mut child) => { tokio::task::spawn_blocking(move || child.wait())}.await?,
			None => anyhow::bail!("Failed to wait for daemon to complete. Was it running?")
		}?;

		Ok(())
	}

	pub fn add_stdout_handler<L : LogHandler + Send + Sync + 'static>(&mut self, log_handler: L) -> anyhow::Result<()> {
		let mut handlers = self.stdout_handler.lock().unwrap();
		handlers.push(Box::new(log_handler));
		Ok(())
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

		match self.stdout_jh.take() {
			Some(jh) => { let _ = jh.join(); },
			None => {}
		}
	}
}
