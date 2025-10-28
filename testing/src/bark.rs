
pub use bark_json::cli as json;

use std::{env, fmt};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use ark::lightning::PaymentHash;
use bitcoin::{Address, Amount, FeeRate, Network};
use bitcoincore_rpc::Auth;
use log::{trace, info, error};
use serde_json;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex;

use bark::onchain::ChainSourceSpec;
use bark_json::{InvoiceInfo, LightningReceiveInfo, UtxoInfo, WalletVtxoInfo};
use bitcoin_ext::FeeRateExt;

use crate::constants::BOARD_CONFIRMATIONS;
use crate::{Bitcoind, TestContext};
use crate::context::ToArkUrl;
use crate::constants::env::{BARK_COMMAND_TIMEOUT_MILLIS, BARK_EXEC};
use crate::util::resolve_path;

const COMMAND_LOG_FILE: &str = "commands.log";
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct BarkConfig {
	pub datadir: PathBuf,
	pub ark_url: String,
	pub network: Network,
	pub chain_source: ChainSourceSpec,
	pub fallback_fee: FeeRate,
	pub extra_create_args: Vec<String>,
}

#[derive(Debug)]
pub struct Bark {
	name: String,
	config: BarkConfig,
	counter: AtomicUsize,
	pub timeout: Option<Duration>,
	_bitcoind: Option<Bitcoind>,
	command_log: Mutex<fs::File>,
}

impl Bark {
	fn cmd() -> TokioCommand {
		let e = env::var(BARK_EXEC).expect("BARK_EXEC env not set");
		let exec = resolve_path(e).expect("failed to resolve BARK_EXEC");
		TokioCommand::new(exec)
	}

	/// Creates Bark client with a dedicated bitcoind daemon.
	pub async fn new(name: impl AsRef<str>, bitcoind: Option<Bitcoind>, cfg: BarkConfig) -> Bark {
		Self::try_new(name, bitcoind, cfg).await.unwrap()
	}

	pub async fn try_new(
		name: impl AsRef<str>,
		bitcoind: Option<Bitcoind>,
		cfg: BarkConfig
	) -> anyhow::Result<Bark> {
		let mut cmd = Self::cmd();
		cmd
			.arg("create")
			.arg("--datadir")
			.arg(&cfg.datadir)
			.arg("--verbose")
			.arg("--ark")
			.arg(&cfg.ark_url)
			.arg("--vtxo-refresh-expiry-threshold")
			.arg("24")
			.arg(format!("--{}", &cfg.network))
			.arg("--fallback-fee-rate")
			.arg(&format!("{}", cfg.fallback_fee.to_sat_per_kvb()));

		// allow extra args
		for arg in &cfg.extra_create_args {
			cmd.arg(arg);
		}

		// Configure barks' chain source
		match &cfg.chain_source {
			ChainSourceSpec::Bitcoind { url, auth } => {
				cmd.args(["--bitcoind", &url]);
				match auth {
					Auth::None => panic!("Missing credentials for bitcoind"),
					Auth::UserPass(user, password) => {
						cmd.args([
							"--bitcoind-user", user,
							"--bitcoind-password", password,
						]);
					}
					Auth::CookieFile(cookie) => {
						cmd.args(["--bitcoind-cookie", &cookie.display().to_string()]);
					}
				}
			}
			ChainSourceSpec::Esplora { url } => {
				cmd.args(["--esplora", &url]);
			}
		}

		let output = cmd.output().await?;
		if !output.status.success() {
			error!("Failure creating new bark wallet");
			let stdout = String::from_utf8(output.stdout)?;
			let stderr = String::from_utf8(output.stderr)?;

			error!("{}", stderr);
			error!("{}", stdout);

			bail!("Failed to create {}: stderr: {}; stdout: {}", name.as_ref(), stderr, stdout);
		}

		Ok(Bark {
			_bitcoind: bitcoind,
			name: name.as_ref().to_string(),
			counter: AtomicUsize::new(0),
			timeout: None,
			command_log: Mutex::new(fs::File::create(cfg.datadir.join(COMMAND_LOG_FILE)).await?),
			config: cfg,
		})
	}

	pub fn name(&self) -> &str {
		&self.name
	}

	pub fn config(&self) -> &BarkConfig {
		&self.config
	}

	pub async fn try_client(&self) -> anyhow::Result<bark::Wallet> {
		const MNEMONIC_FILE: &str = "mnemonic";
		const DB_FILE: &str = "db.sqlite";
		const CONFIG_FILE: &str = "config.toml";

		// read mnemonic file
		let mnemonic_path = self.config.datadir.join(MNEMONIC_FILE);
		let mnemonic_str = fs::read_to_string(&mnemonic_path).await
			.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
		let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;

		// Read the config file
		let config_path = self.config.datadir.join(CONFIG_FILE);
		let config_str = fs::read_to_string(&config_path).await
			.with_context(|| format!("Failed to read config file at {}", config_path.display()))?;
		let config: bark::Config = toml::from_str(&config_str)
			.with_context(|| format!("Failed to parse config file at {}", config_path.display()))?;

		let db = bark::SqliteClient::open(self.config.datadir.join(DB_FILE))?;

		Ok(bark::Wallet::open(&mnemonic, Arc::new(db), config).await?)
	}

	pub async fn client(&self) -> bark::Wallet {
		self.try_client().await.expect("failed to create bark::Wallet client")
	}

	pub fn bitcoind(&self) -> Option<&Bitcoind> {
		self._bitcoind.as_ref()
	}

	pub fn command_log_file(&self) -> PathBuf {
		self.config.datadir.join(COMMAND_LOG_FILE)
	}

	/// Set the bark's server address.
	pub async fn set_ark_url(&self, srv: &dyn ToArkUrl) {
		let config_path = self.config().datadir.join("config.toml");

		// Read the config
		let config_str = fs::read_to_string(&config_path).await.expect("Failed to read config.toml");
		let mut config: bark::Config = toml::from_str(&config_str).expect("Failed to parse config.toml");

		// modify the config
		config.server_address = srv.ark_url();

		// Write the config
		let config_str = toml::to_string_pretty(&config).expect("Failed to serialize toml file");
		fs::remove_file(&config_path).await.expect("Failed to delete config.toml");

		let mut file = fs::File::create(&config_path).await.expect("Failed to create config.toml");
		file.write(config_str.as_bytes()).await.expect("Failed to write config to config.toml");
	}

	pub async fn ark_info(&self) -> json::ArkInfo {
		self.try_run_json(["ark-info"]).await.expect("ark-info command failed")
	}

	pub async fn onchain_balance(&self) -> Amount {
		let balance_output = self.run(["onchain", "balance"]).await;
		let balance = serde_json::from_str::<json::onchain::Balance>(&balance_output).unwrap();
		balance.total
	}

	pub async fn onchain_utxos(&self) -> Vec<UtxoInfo> {
		let output = self.run(["onchain", "utxos"]).await;
		serde_json::from_str::<Vec<UtxoInfo>>(&output).unwrap()
	}

	pub async fn offchain_balance(&self) -> json::Balance {
		let json = self.run(["balance"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap()
	}

	pub async fn spendable_balance(&self) -> Amount {
		let json = self.run(["balance"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap().spendable
	}

	pub async fn spendable_balance_no_sync(&self) -> Amount {
		let json = self.run(["balance", "--no-sync"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap().spendable
	}

	pub async fn pending_board_balance(&self) -> Amount {
		let json = self.run(["balance"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap().pending_board
	}

	pub async fn inround_balance(&self) -> Amount {
		let json = self.run(["balance"]).await;
		serde_json::from_str::<json::Balance>(&json).unwrap().pending_in_round
	}

	pub async fn get_onchain_address(&self) -> Address {
		let output = self.run(["onchain", "address"]).await.trim().to_string();
		let parsed = serde_json::from_str::<json::onchain::Address>(&output).unwrap();
		parsed.address.require_network(Network::Regtest).unwrap()
	}

	/// Use onchain wallet to send bitcoin onchain
	pub async fn onchain_send(&self, destination: impl fmt::Display, amount: Amount) {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.run(["onchain", "send", &destination, &amount, "--verbose"]).await;
	}

	pub async fn onchain_drain(&self, destination: impl fmt::Display) {
		let destination = destination.to_string();
		self.run(["onchain", "drain", &destination, "--verbose"]).await;
	}

	/// Use onchain wallet to send to many recipients
	pub async fn onchain_send_many<T1, T2>(&self, addresses: T1, amounts: T2)
	where
		T1: IntoIterator<Item = Address>,
		T2: IntoIterator<Item = Amount>,
	{
		let mut command : Vec<String> = ["onchain", "send-many", "--immediate", "--verbose"]
			.iter()
			.map(|s| s.to_string())
			.collect();

		let destinations = addresses.into_iter().zip(amounts.into_iter())
			.map(|(a, amt)| format!("{}:{}", a, amt));
		command.extend(destinations.flat_map(|d| vec!["--destination".into(), d]));

		self.run(command).await;
	}

	pub async fn utxos(&self) -> Vec<UtxoInfo> {
		let res = self.run(["onchain", "utxos"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn vtxos(&self) -> Vec<WalletVtxoInfo> {
		let res = self.run(["vtxos"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn vtxos_no_sync(&self) -> Vec<WalletVtxoInfo> {
		let res = self.run(["vtxos", "--no-sync"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn list_movements(&self) -> Vec<json::Movement> {
		let res = self.run(["movements"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn address(&self) -> String {
		self.run(["address"]).await
	}

	pub async fn address_at_idx(&self, idx: u32) -> String {
		self.run(["address", "--index", &idx.to_string()]).await
	}

	/// Use bark wallet to send bitcoin onchain
	pub async fn try_send_onchain(&self, destination: impl fmt::Display, amount: Amount) -> anyhow::Result<()> {
		let destination = destination.to_string();
		let amount = amount.to_string();
		self.try_run(["send-onchain", &destination, &amount, "--verbose"]).await?;
		Ok(())
	}

	pub async fn send_onchain(&self, destination: impl fmt::Display, amount: Amount) {
		self.try_send_onchain(destination, amount).await.unwrap();
	}

	pub async fn try_send_oor(&self, dest: impl fmt::Display, amount: Amount, sync: bool) -> anyhow::Result<()> {
		let dest = dest.to_string();
		let amount = amount.to_string();
		let mut args = vec!["send", &dest, &amount, "--verbose"];
		if !sync {
			args.push("--no-sync");
		}
		self.try_run(args).await?;
		Ok(())
	}

	pub async fn send_oor(&self, dest: impl fmt::Display, amount: Amount) {
		self.try_send_oor(dest, amount, true).await.expect("send-oor command failed");
	}

	pub async fn send_oor_nosync(&self, dest: impl fmt::Display, amount: Amount) {
		self.try_send_oor(dest, amount, false).await.expect("send-oor command failed");
	}

	pub async fn try_send_lightning(&self, destination :impl fmt::Display, amount: Option<Amount>)-> anyhow::Result<()> {
		let destination = destination.to_string();

		if let Some(amount) = amount {
			self.try_run(["send", &destination, &amount.to_string(), "--verbose"]).await?;
		} else {
			self.try_run(["send", &destination, "--verbose"]).await?;
		}
		Ok(())
	}

	pub async fn send_lightning(&self, destination :impl fmt::Display, amount: Option<Amount>) -> () {
		self.try_send_lightning(destination, amount).await.unwrap();
	}

	pub async fn try_bolt11_invoice(&self, amount: Amount) -> anyhow::Result<InvoiceInfo> {
		let res = self.try_run([
			"lightning", "invoice", &amount.to_string(), "--verbose"
		]).await?;
		Ok(serde_json::from_str(&res).expect("json error"))
	}

	pub async fn bolt11_invoice(&self, amount: Amount) -> InvoiceInfo {
		self.try_bolt11_invoice(amount).await.expect("bolt11 invoice command failed")
	}

	pub async fn try_lightning_receive(&self, invoice: String) -> anyhow::Result<()> {
		self.try_run(["lightning", "claim", &invoice, "--wait", "--verbose"]).await?;
		Ok(())
	}

	pub async fn lightning_receive(&self, invoice: String) {
		self.try_lightning_receive(invoice).await.unwrap();
	}

	pub async fn try_lightning_receive_no_wait(&self, invoice: String) -> anyhow::Result<()> {
		self.try_run(["lightning", "claim", &invoice, "--verbose"]).await?;
		Ok(())
	}

	pub async fn lightning_receive_no_wait(&self, invoice: String) {
		self.try_lightning_receive_no_wait(invoice).await.unwrap();
	}

	pub async fn try_lightning_receive_all(&self) -> anyhow::Result<()> {
		self.try_run(["lightning", "claim", "--wait", "--verbose"]).await?;
		Ok(())
	}

	pub async fn lightning_receive_all(&self) {
		self.try_lightning_receive_all().await.unwrap();
	}

	pub async fn list_lightning_receives(&self) -> Vec<LightningReceiveInfo> {
		let res = self.run(["lightning", "invoices"]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn lightning_receive_status(
		&self,
		payment_hash: impl Into<PaymentHash>,
	) -> Option<LightningReceiveInfo> {
		let hash = payment_hash.into().to_string();
		let res = self.run(["lightning", "status", &hash]).await;
		serde_json::from_str(&res).expect("json error")
	}

	pub async fn try_board(&self, amount: Amount) -> anyhow::Result<json::Board> {
		info!("{}: Board {}", self.name, amount);
		self.try_run_json(["board", &amount.to_string()]).await
	}

	pub async fn board(&self, amount: Amount) -> json::Board {
		self.try_board(amount).await.expect("board command failed")
	}

	pub async fn board_all(&self) -> json::Board {
		self.try_board_all().await.expect("board command failed")
	}

	pub async fn try_board_all(&self) -> anyhow::Result<json::Board> {
		info!("{}: Boarding all on-chain funds", self.name);
		self.try_run_json(["board", "--all"]).await
	}

	pub async fn maintain(&self) {
		self.run(["maintain"]).await;
	}

	pub async fn board_and_confirm_and_register(&self, ctx: &TestContext, amount: Amount) {
		self.board(amount).await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		self.maintain().await;
	}

	pub async fn board_all_and_confirm_and_register(&self, ctx: &TestContext) {
		self.board_all().await;
		ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
		self.maintain().await;
	}

	pub async fn try_refresh_all(&self) -> anyhow::Result<()> {
		self.try_run(["refresh", "--all"]).await?;
		Ok(())
	}

	pub async fn refresh_all(&self) {
		self.try_refresh_all().await.expect("refresh --all command failed")
	}

	pub async fn refresh_counterparty(&self) {
		self.run(["refresh", "--counterparty"]).await;
	}

	pub async fn try_offboard_all(&self, address: impl fmt::Display) -> anyhow::Result<json::Offboard> {
		self.try_run_json(["offboard", "--all", "--address", &address.to_string()]).await
	}

	pub async fn offboard_all(&self, address: impl fmt::Display) -> json::Offboard {
		self.try_offboard_all(address).await.expect("offboard --all command failed")
	}

	pub async fn offboard_vtxo(
		&self,
		vtxo: impl fmt::Display,
		address: impl fmt::Display,
	) -> json::Offboard {
		self.run_json([
			"offboard", "--vtxo", &vtxo.to_string(), "--address", &address.to_string(),
		]).await
	}

	pub async fn drop_vtxos(&self) {
		self.run(["dev", "vtxo", "drop", "--all", "--dangerous"]).await;
	}

	pub async fn progress_exit(&self) -> json::ExitProgressResponse {
		self.run_json(["exit", "progress"]).await
	}

	pub async fn progress_exit_with_fee_rate(&self, fee_rate: FeeRate) -> json::ExitProgressResponse {
		self.run_json(
			["exit", "progress", "--fee-rate", &fee_rate.to_btc_per_kvb()],
		).await
	}

	pub async fn start_exit_all(&self) {
		self.run(["exit", "start", "--all"]).await;
	}

	pub async fn start_exit_vtxos<I, T>(&self, vtxos: I)
	where
		I: IntoIterator<Item = T>,
		T: fmt::Display,
	{
		let mut command : Vec<String> = ["exit", "start", "--verbose"]
			.iter()
			.map(|s| s.to_string())
			.collect();
		command.extend(vtxos.into_iter().flat_map(|v| vec!["--vtxo".into(), v.to_string()]));
		self.run(command).await;
	}

	pub async fn list_exits(&self) -> Vec<json::ExitTransactionStatus> {
		self.run_json(["exit", "list"]).await
	}

	pub async fn list_exits_with_details(&self) -> Vec<json::ExitTransactionStatus> {
		self.run_json(["exit", "list", "--transactions", "--history"]).await
	}

	pub async fn claim_all_exits(&self, destination: impl fmt::Display) {
		let destination = destination.to_string();
		self.run(["exit", "claim", &destination, "--verbose", "--all"]).await;
	}

	pub async fn claim_exits<I, T>(&self, vtxos: I, destination: impl fmt::Display)
	where
		I: IntoIterator<Item = T>,
		T: fmt::Display,
	{
		let mut command : Vec<String> = ["exit", "claim", "--verbose"]
			.iter()
			.map(|s| s.to_string())
			.collect();
		command.push(destination.to_string());
		command.extend(vtxos.into_iter().flat_map(|v| vec!["--vtxo".into(), v.to_string()]));
		self.run(command).await;
	}

	pub async fn try_run<I,S>(&self, args: I) -> anyhow::Result<String>
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		let args: Vec<String> = args.into_iter().map(|x| x.as_ref().to_string()).collect();

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
		fs::write(folder.join("cmd.log"), &command_str).await?;
		let mut command_log = self.command_log.lock().await;
		command_log.write_all(
			format!("\n\n\nCOMMAND: {}\n", command_str).as_bytes()
		).await?;

		// We capture stdout here in output, but we write stderr to a file,
		// so that we can read it even is something fails in the execution.
		let stderr_path = folder.join("stderr.log");
		command.stderr(fs::File::create(&stderr_path).await?.into_std().await);
		command.stdout(Stdio::piped());

		let mut child = command.spawn()?;

		// The priority is the bark instances' timeout, the env timeout then the default timeout
		let timeout = self.timeout.unwrap_or_else(|| {
			if let Ok(millis) = env::var(BARK_COMMAND_TIMEOUT_MILLIS) {
				let millis = millis.parse()
					.expect(&format!("{} is not in milliseconds", BARK_COMMAND_TIMEOUT_MILLIS));
				Duration::from_millis(millis)
			} else {
				DEFAULT_CMD_TIMEOUT
			}
		});
		let exit_result = tokio::time::timeout(timeout, child.wait()).await;

		// on timeout, kill the child
		if exit_result.is_err() {
			error!("bark command timed out");
			command_log.write_all("TIMED OUT\n".as_bytes()).await?;
			child.kill().await.map_err(|e| anyhow!("can't kill timedout child: {}", e))?;
		}
		let out = {
			let mut buf = String::new();
			if let Some(mut o) = child.stdout {
				o.read_to_string(&mut buf).await?;
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
		command_log.write_all("OUTPUT:".as_bytes()).await?;
		command_log.write_all(out.as_bytes()).await?;
		command_log.write_all("\nLOGS:\n".as_bytes()).await?;
		let logs = fs::read_to_string(stderr_path).await?;
		command_log.write_all(logs.as_bytes()).await?;

		match exit_result {
			Ok(Ok(ret)) if ret.success() => Ok(out.trim().to_string()),
			_ => {
				//TODO(stevenroose) do something fancy that puts the logs into
				// a context object so that we can .contains it without dumping them
				// to stdout on test failure
				bail!("Failed to execute command on {} '{}': error={:?}\nOUTPUT:\n{}\n\nLOGS:\n{}",
					self.name(), command_str, exit_result, out, logs,
				)
			},
		}
	}

	pub async fn run<I, S>(&self, args: I) -> String
		where I: IntoIterator<Item = S>, S : AsRef<str>
	{
		self.try_run(args).await.expect("command failed")
	}

	pub async fn try_run_json<T, I, S>(&self, args: I) -> anyhow::Result<T>
	where
		T: for <'de> serde::Deserialize<'de>,
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		let json = self.try_run(args).await?;
		let ret = serde_json::from_str(&json)
			.with_context(|| format!("unexpected json output: {}", json))?;
		Ok(ret)
	}

	pub async fn run_json<T, I, S>(&self, args: I) -> T
	where
		T: for <'de> serde::Deserialize<'de>,
		I: IntoIterator<Item = S>,
		S: AsRef<str>,
	{
		self.try_run_json(args).await.expect("json command failed")
	}
}

