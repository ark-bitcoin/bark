
use std::{env, fmt, fs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use bitcoin::address::{Address, NetworkUnchecked};
use bitcoin::Amount;
use serde_json;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;

use crate::constants::env::BARK_EXEC;

pub struct BarkConfig {
	pub datadir: PathBuf,
	pub asp_url: String,
	pub network: String,
	pub bitcoind_url: String,
	pub bitcoind_cookie: PathBuf
}

pub struct Bark {
	name: String,
	config: BarkConfig,
	counter: AtomicUsize,
	timeout: Duration,
}

impl Bark {
	fn cmd() -> TokioCommand {
		let exec = env::var(BARK_EXEC).expect("BARK_EXEC env not set");
		TokioCommand::new(exec)
	}

	pub async fn new(name: impl AsRef<str>, cfg: BarkConfig) -> anyhow::Result<Bark> {
		let output = Bark::cmd()
			.arg("create")
			.arg("--datadir")
			.arg(&cfg.datadir)
			.arg("--asp")
			.arg(&cfg.asp_url)
			.arg(format!("--{}", cfg.network))
			.arg("--bitcoind-cookie")
			.arg(&cfg.bitcoind_cookie)
			.arg("--bitcoind")
			.arg(&cfg.bitcoind_url)
			.output()
			.await?;

		if !output.status.success() {
			let stdout = String::from_utf8(output.stdout)?;
			let stderr = String::from_utf8(output.stderr)?;

			error!("{}", stderr);
			error!("{}", stdout);

			bail!("Failed to create {}", name.as_ref());
		}

		Ok(Bark {
			name: name.as_ref().to_string(),
			config: cfg,
			counter: AtomicUsize::new(0),
			timeout: Duration::from_millis(10_000),
		})
	}

	pub fn name(&self) -> &str {
		&self.name
	}

	pub async fn onchain_balance(&self) -> anyhow::Result<Amount> {
		let json = self.run(["balance", "--json"]).await?;
		let json = serde_json::from_str::<serde_json::Value>(&json).unwrap();
		let sats = json.as_object().unwrap().get("onchain").unwrap().as_i64().unwrap();
		Ok(Amount::from_sat(sats as u64))
	}

	pub async fn offchain_balance(&self) -> anyhow::Result<Amount> {
		let json = self.run(["balance", "--json"]).await?;
		let json = serde_json::from_str::<serde_json::Value>(&json).unwrap();
		let sats = json.as_object().unwrap().get("offchain").unwrap().as_i64().unwrap();
		Ok(Amount::from_sat(sats as u64))
	}

	pub async fn get_address(&self) -> anyhow::Result<Address> {
		let address_string = self.run(["get-address"]).await?.trim().to_string();
		let address_unchecked = Address::<NetworkUnchecked>::from_str(&address_string)?;
		Ok(address_unchecked.assume_checked())
	}

	pub async fn get_vtxo_pubkey(&self) -> anyhow::Result<String> {
		Ok(self.run(["get-vtxo-pubkey"]).await?)
	}

	pub async fn send_round(&self, destination: impl fmt::Display, amount: Amount) -> anyhow::Result<()> {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send-round", &destination, &amount, "--verbose"]).await?;
		Ok(())
	}

	pub async fn send_oor(&self, destination: impl fmt::Display, amount: Amount) -> anyhow::Result<()> {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["send-oor", &destination, &amount, "--verbose"]).await?;
		Ok(())
	}

	pub async fn onboard(&self, amount: Amount) -> anyhow::Result<()> {
		info!("{}: Onboard {}", self.name, amount);

		self.run(["onboard", &amount.to_string()]).await?;
		Ok(())
	}

	pub async fn start_exit(&self) -> anyhow::Result<()> {
		self.run(["start-exit"]).await?;
		Ok(())
	}

	pub async fn claim_exit(&self) -> anyhow::Result<()> {
		self.run(["claim-exit"]).await?;
		Ok(())
	}

	pub async fn run<I,S>(&self, args: I) -> anyhow::Result<String>
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		let args: Vec<String>  = args.into_iter().map(|x| x.as_ref().to_string()).collect();

		let mut command = Bark::cmd();
		command.args(&["--datadir", &self.config.datadir.as_os_str().to_str().unwrap()]);
		command.args(args);
		let command_str = format!("{:?}", command.as_std());

		// Create a folder for each command
		let count = self.counter.fetch_add(1, Ordering::Relaxed);
		let folder = self.config.datadir.join("cmd").join(count.to_string());
		fs::create_dir_all(&folder)?;
		fs::write(folder.join("cmd"), &command_str)?;

		// We capture stdout here in output, but we write stderr to a file,
		// so that we can read it even is something fails in the execution.
		command.stderr(fs::File::create(folder.join("stderr.log"))?);
		command.stdout(Stdio::piped());

		let mut child = command.spawn().unwrap();

		let exit = tokio::time::timeout(
			self.timeout,
			child.wait(),
		).await??;
		if exit.success() {
			let out = {
				let mut buf = String::new();
				if let Some(mut o) = child.stdout {
					o.read_to_string(&mut buf).await.unwrap();
				}
				buf
			};
			let outfile = folder.join("stdout.log");
			if let Err(e) = fs::write(&outfile, &out) {
				error!("Failed to write stdout of cmd '{}' to file '{}': {}",
					command_str, outfile.display(), e,
				);
			}
			Ok(out.trim().to_string())
		}
		else {
			bail!("Failed to execute {:?}", command)
		}
	}
}
