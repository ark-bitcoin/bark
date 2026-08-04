//! Wrapper around the thin `bark-cli` REST client binary.
//!
//! Unlike [`crate::Bark`], which shells into the in-process `bark-legacy`
//! binary, this drives the barkd-backed `bark-cli` (resolved through
//! `BARK_CLIENT_EXEC`) against a datadir where a barkd already runs —
//! tests point it at a [`crate::Barkd`]'s datadir. The test barkd binds
//! a reserved port rather than barkd's default, so wallet commands need
//! the wrapper's `base_url` passed as `--url`.

use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context;
use log::trace;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::constants::env::{BARK_CLIENT_EXEC, BARK_COMMAND_TIMEOUT_MILLIS, BARK_TOKIO_WORKER_THREADS};
use crate::util::resolve_path;

const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(120);

pub struct BarkClient {
	pub name: String,
	datadir: PathBuf,
	/// Passed as `--url`; `None` exercises the default-address path.
	base_url: Option<String>,
	counter: AtomicUsize,
}

impl BarkClient {
	pub fn new(name: impl AsRef<str>, datadir: PathBuf, base_url: Option<String>) -> Self {
		BarkClient {
			name: name.as_ref().to_string(),
			datadir,
			base_url,
			counter: AtomicUsize::new(0),
		}
	}

	pub fn cmd() -> Command {
		let e = env::var(BARK_CLIENT_EXEC).expect("BARK_CLIENT_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve BARK_CLIENT_EXEC");
		Command::new(exec)
	}

	pub fn datadir(&self) -> PathBuf {
		self.datadir.clone()
	}

	/// The pid stamped in the datadir lock. Only meaningful while a barkd
	/// runs: the stamp outlives a dead holder.
	pub fn barkd_pid(&self) -> Option<u32> {
		std::fs::read_to_string(self.datadir.join("barkd.lock")).ok()?
			.trim().parse().ok()
	}

	pub async fn run<I, S>(&self, args: I) -> String
		where I: IntoIterator<Item = S>, S: AsRef<str>
	{
		self.try_run(args).await.expect("bark client command failed")
	}

	pub async fn try_run<I, S>(&self, args: I) -> anyhow::Result<String>
		where I: IntoIterator<Item = S>, S: AsRef<str>
	{
		let args: Vec<String> = args.into_iter().map(|x| x.as_ref().to_string()).collect();

		let mut command = BarkClient::cmd();
		if let Ok(nb) = env::var(BARK_TOKIO_WORKER_THREADS) {
			command.env("TOKIO_WORKER_THREADS", nb);
		}
		command.args(["--verbose", "--datadir", self.datadir.to_str().unwrap()]);
		if let Some(url) = &self.base_url {
			command.args(["--url", url]);
		}
		command.args(&args);
		command.kill_on_drop(true);
		let command_str = format!("{:?}", command.as_std());
		trace!("{}: {}", self.name, command_str);

		// Log every command and its stderr next to the datadir for
		// post-mortems. Not inside it: barkd's create rejects a datadir
		// with unexpected contents.
		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		let cmd_dir = self.datadir.with_file_name(
			format!("{}-{}-cmd", self.datadir.file_name().unwrap().to_str().unwrap(), self.name),
		);
		let folder = cmd_dir.join(format!("{:03}", count));
		fs::create_dir_all(&folder).await?;
		fs::write(folder.join("cmd.log"), &command_str).await?;

		let stderr_path = folder.join("stderr.log");
		command.stderr(fs::File::create(&stderr_path).await?.into_std().await);
		command.stdout(Stdio::piped());

		let mut child = command.spawn()?;

		let timeout = if let Ok(millis) = env::var(BARK_COMMAND_TIMEOUT_MILLIS) {
			let millis = millis.parse()
				.expect(&format!("{} is not in milliseconds", BARK_COMMAND_TIMEOUT_MILLIS));
			Duration::from_millis(millis)
		} else {
			DEFAULT_CMD_TIMEOUT
		};

		// Drain stdout concurrently with wait so a full pipe never blocks
		// the child (see `Bark::try_run` for details).
		let mut stdout = child.stdout.take().expect("stdout was piped");
		let read_fut = async move {
			let mut buf = String::new();
			stdout.read_to_string(&mut buf).await.unwrap();
			buf
		};

		let (exit_result, output) = tokio::join!(
			tokio::time::timeout(timeout, child.wait()),
			read_fut,
		);

		let status = exit_result
			.with_context(|| format!("timeout running '{}'", command_str))?
			.with_context(|| format!("error waiting for '{}'", command_str))?;

		if status.success() {
			Ok(output.trim().to_string())
		} else {
			let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
			bail!(
				"bark client command failed with {}: '{}'\nstderr: {}",
				status, command_str, stderr.trim(),
			)
		}
	}
}
