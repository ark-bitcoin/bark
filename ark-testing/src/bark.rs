
use std::{env, fmt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::address::{Address, NetworkUnchecked};
use bitcoin::{Amount, Network, OutPoint};
use serde_json;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex;

use bark_json::cli as json;

use crate::constants::env::BARK_EXEC;
use crate::util::resolve_path;

const COMMAND_LOG_FILE: &str = "commands.log";

#[derive(Debug)]
pub struct BarkConfig {
	pub datadir: PathBuf,
	pub asp_url: String,
	pub network: String,
	pub bitcoind_url: String,
	pub bitcoind_cookie: PathBuf
}

#[derive(Debug)]
pub struct Bark {
	name: String,
	config: BarkConfig,
	counter: AtomicUsize,
	timeout: Duration,

	command_log: Mutex<fs::File>,
}

impl Bark {
	fn cmd() -> TokioCommand {
		let e = env::var(BARK_EXEC).expect("BARK_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve BARK_EXEC");
		TokioCommand::new(exec)
	}

	pub async fn new(name: impl AsRef<str>, cfg: BarkConfig) -> Bark {
		Self::try_new(name, cfg).await.unwrap()
	}

	pub async fn try_new(name: impl AsRef<str>, cfg: BarkConfig) -> anyhow::Result<Bark> {
		let output = Bark::cmd()
			.arg("create")
			.arg("--datadir")
			.arg(&cfg.datadir)
			.arg("--verbose")
			.arg("--asp")
			.arg(&cfg.asp_url)
			.arg(format!("--{}", cfg.network))
			.arg("--bitcoind-cookie")
			.arg(&cfg.bitcoind_cookie)
			.arg("--bitcoind")
			.arg(&cfg.bitcoind_url)
			.output()
			.await?;

		info!("Ran command");
		if !output.status.success() {
			info!("Detected failure");
			let stdout = String::from_utf8(output.stdout)?;
			let stderr = String::from_utf8(output.stderr)?;

			error!("{}", stderr);
			error!("{}", stdout);

			bail!("Failed to create {}", name.as_ref());
		}

		Ok(Bark {
			name: name.as_ref().to_string(),
			counter: AtomicUsize::new(0),
			timeout: Duration::from_millis(10_000),
			command_log: Mutex::new(fs::File::create(cfg.datadir.join(COMMAND_LOG_FILE)).await?),
			config: cfg,
		})
	}

	pub fn name(&self) -> &str {
		&self.name
	}

	pub async fn onchain_balance(&self) -> Amount {
		self.run(["onchain", "balance"]).await.parse().unwrap()
	}

	pub async fn onchain_utxos(&self) -> Vec<OutPoint> {
		self.run(["onchain", "utxos"]).await.lines().map(FromStr::from_str)
			.collect::<Result<_, _>>().unwrap()
	}

	pub async fn offchain_balance(&self) -> Amount {
		let json = self.run(["balance", "--json"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap().offchain
	}

	pub async fn get_onchain_address(&self) -> Address {
		let address_string = self.run(["onchain", "address"]).await.trim().to_string();
		Address::<NetworkUnchecked>::from_str(&address_string).unwrap()
			.require_network(Network::Regtest).unwrap()
	}

	pub async fn vtxos(&self) -> Vec<json::VtxoInfo> {
		let res = self.run(["vtxos", "--json"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn vtxo_pubkey(&self) -> String {
		self.run(["vtxo-pubkey"]).await
	}

	pub async fn send_onchain(&self, destination: impl fmt::Display, amount: Amount) {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send-onchain", &destination, &amount, "--verbose"]).await;
	}

	pub async fn send_oor(&self, destination: impl fmt::Display, amount: Amount) {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send", &destination, &amount, "--verbose"]).await;
	}

	pub async fn try_send_bolt11(&self, destination :impl fmt::Display, amount: Option<Amount>)-> anyhow::Result<()> {
		let destination = destination.to_string();

		if let Some(amount) = amount {
			self.try_run(["send", &destination, &amount.to_string(), "--verbose"]).await?;
		} else {
			self.try_run(["send", &destination, "--verbose"]).await?;
		}
		Ok(())
	}

	pub async fn send_bolt11(&self, destination :impl fmt::Display, amount: Option<Amount>) -> () {
		self.try_send_bolt11(destination, amount).await.unwrap();
	}

	pub async fn onboard(&self, amount: Amount) {
		info!("{}: Onboard {}", self.name, amount);
		self.run(["onboard", &amount.to_string()]).await;
	}

	pub async fn onboard_all(&self) {
		info!("{}: Onboarding all on-chain funds", self.name);
		self.run(["onboard", "--all"]).await;
	}

	pub async fn refresh_all(&self) {
		self.run(["refresh", "--all"]).await;
	}

	pub async fn offboard_all(&self, address: impl fmt::Display) {
		self.run(["offboard", "--all", "--address", &address.to_string()]).await;
	}

	pub async fn offboard_vtxo(&self, vtxo: impl fmt::Display, address: impl fmt::Display) {
		self.run(["offboard", "--vtxos", &vtxo.to_string(), "--address", &address.to_string()]).await;
	}

	pub async fn exit(&self) -> json::ExitStatus {
		let res = self.run(["exit", "--json"]).await;
		serde_json::from_str::<json::ExitStatus>(&res).expect("invalid json from exit")
	}

	pub async fn try_run<I,S>(&self, args: I) -> anyhow::Result<String>
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		let args: Vec<String>  = args.into_iter().map(|x| x.as_ref().to_string()).collect();

		let mut command = Bark::cmd();
		command.args(&[
			"--verbose",
			"--datadir",
			self.config.datadir.as_os_str().to_str().unwrap(),
		]);
		command.args(args);
		command.kill_on_drop(true);
		let command_str = format!("{:?}", command.as_std());

		// Create a folder for each command
		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		let folder = self.config.datadir.join("cmd").join(format!("{:03}", count));
		fs::create_dir_all(&folder).await?;
		fs::write(folder.join("cmd"), &command_str).await?;
		self.command_log.lock().await.write_all(
			format!("\n\n\nCOMMAND: {}\n", command_str).as_bytes()
		).await?;

		// We capture stdout here in output, but we write stderr to a file,
		// so that we can read it even is something fails in the execution.
		let stderr_path = folder.join("stderr.log");
		command.stderr(fs::File::create(&stderr_path).await?.into_std().await);
		command.stdout(Stdio::piped());

		let mut child = command.spawn().unwrap();

		let exit_result = tokio::time::timeout(
			self.timeout,
			child.wait(),
		).await;
		// on timeout, kill the child
		if exit_result.is_err() {
			child.kill().await
				.map_err(|e| anyhow!("wait we can't kill the child??: {}", e))?;
		}
		let out = {
			let mut buf = String::new();
			if let Some(mut o) = child.stdout {
				o.read_to_string(&mut buf).await.unwrap();
			}
			buf
		};
		trace!("output of command '{}': {}", command_str, out);
		let outfile = folder.join("stdout.log");
		if let Err(e) = fs::write(&outfile, &out).await {
			error!("Failed to write stdout of cmd '{}' to file '{}': {}",
				command_str, outfile.display(), e,
			);
		}

		// also append to the command log
		self.command_log.lock().await.write_all("OUTPUT:".as_bytes()).await?;
		self.command_log.lock().await.write_all(out.as_bytes()).await?;
		self.command_log.lock().await.write_all("\nLOGS:\n".as_bytes()).await?;
		let logs = fs::read_to_string(stderr_path).await?;
		self.command_log.lock().await.write_all(logs.as_bytes()).await?;

		match exit_result {
			Ok(Ok(ret)) if ret.success() => Ok(out.trim().to_string()),
			_ => {
				bail!("Failed to execute command on {} '{}': error={:?}\nOUTPUT:\n{}\n\nLOGS:\n{}",
					self.name(), command_str, exit_result, out, logs,
				)
			},
		}
	}

	pub async fn run<I,S>(&self, args: I) -> String
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		self.try_run(args).await.expect("command failed")
	}
}
