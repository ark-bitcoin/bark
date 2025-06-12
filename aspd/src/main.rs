
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{bip32, Address};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use clap::Parser;
use log::{error, info};
use tonic::transport::Uri;

use aspd::{Server, Config};
use aspd_log::{RecordSerializeWrapper, SLOG_FILENAME};
use aspd_rpc::{self as rpc, protos};

/// Defaults to our default port on localhost.
const DEFAULT_ADMIN_RPC_ADDR: &str = "127.0.0.1:3536";

/// The full semver version to set, which includes the git commit hash
/// as the build suffix.
/// (GIT_HASH is set in build.rs)
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("GIT_HASH"));

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version = FULL_VERSION, about)]
struct Cli {
	/// Path to the configuration file
	#[arg(global = true, short = 'C', long)]
	config: Option<PathBuf>,

	#[command(subcommand)]
	command: Command,
}

/// Command-line arguments structure for drain
#[derive(Parser, Debug)]
pub struct DrainArgs {
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create and configure asp server
	#[command()]
	Create,

	/// Start asp server
	#[command()]
	Start,

	/// Drain funds of asp
	#[command()]
	Drain {
		/// The address to send all the wallet funds to
		address: Address<bitcoin::address::NetworkUnchecked>,
	},

	/// Retrieve 12 word seed phrase
	#[command()]
	GetMnemonic,

	/// Run RPC commands
	#[command()]
	Rpc {
		#[arg(long, default_value = DEFAULT_ADMIN_RPC_ADDR)]
		addr: String,
		#[command(subcommand)]
		cmd: RpcCommand,
	},
}

#[derive(clap::Subcommand)]
enum RpcCommand {
	/// Report aspd wallet status
	#[command()]
	Wallet,

	/// Start a new asp round
	#[command()]
	TriggerRound,

	/// Stop aspd
	#[command()]
	Stop,
}

#[tokio::main]
async fn main() {
	// Set a custom panic hook to make sure we print stack traces
	// when one of our background processes panic.
	std::panic::set_hook(Box::new(|panic_info| {
		let backtrace = std::backtrace::Backtrace::force_capture();
		eprintln!("Panic occurred: {}\n\nBacktrace:\n{}", panic_info, backtrace);
	}));

	if let Err(e) = inner_main().await {
		println!("An error occurred: {}", e);
		// maybe hide second print behind a verbose flag
		println!("");
		println!("{:?}", e);
		process::exit(1);
	}
}

fn init_logging(slog_dir: Option<&Path>) {
	//TODO(stevenroose) add filename and line number when verbose logging
	let mut dispatch = fern::Dispatch::new()
		.level(log::LevelFilter::Trace)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("bitcoincore_rpc", log::LevelFilter::Warn)
		.level_for("tokio_postgres", log::LevelFilter::Info)
		// regular logging dispatch
		.chain(fern::Dispatch::new()
			.format(|out, msg, rec| {
				let now = chrono::Local::now();
				let stamp = now.to_rfc3339();
				let kv = if rec.key_values().count() > 0 {
					let mut buf = Vec::new();
					buf.extend(" -- ".as_bytes());
					serde_json::to_writer(&mut buf, &aspd_log::SourceSerializeWrapper(rec.key_values())).unwrap();
					String::from_utf8(buf).unwrap()
				} else {
					String::new()
				};
				out.finish(format_args!(
					"[{} {: >5} {}] {}{}",
					stamp, rec.level(), rec.module_path().unwrap_or(""), msg, kv,
				))
			})
			.chain(std::io::stdout())
		);

	if let Some(dir) = slog_dir {
		// structured logging dispatch
		let slog_file = fern::log_file(dir.join(SLOG_FILENAME)).expect("failed to open log file");
		dispatch = dispatch.chain(fern::Dispatch::new()
			.filter(|m| m.target() == aspd_log::SLOG_TARGET)
			.format(|out, _msg, rec| {
				#[derive(serde::Serialize)]
				struct Rec<'a> {
					timestamp: chrono::DateTime<chrono::Local>,
					#[serde(flatten)]
					rec: RecordSerializeWrapper<'a>,
				}
				let rec = Rec {
					timestamp: chrono::Local::now(),
					rec: RecordSerializeWrapper(rec),
				};
				out.finish(format_args!("{}", serde_json::to_string(&rec).unwrap()));
			})
			.chain(slog_file)
		);
	}

	dispatch.apply().expect("error setting up logging");
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	if let Command::Rpc { cmd, addr } = cli.command {
		return run_rpc(&addr, cmd).await;
	}

	let cfg = Config::load(cli.config.as_ref().map(|p| p.as_path()))?;
	cfg.validate().expect("invalid configuration");

	init_logging(cfg.log_dir.as_ref().map(|p| p.as_path()));
	info!("Running with config: {:#?}", cfg);

	match cli.command {
		Command::Rpc { .. } => unreachable!(),
		Command::Create => {
			Server::create(cfg).await?;
		}
		Command::Start => {
			if let Err(e) = Server::run(cfg).await {
				error!("Shutdown error from aspd {:?}", e);

				process::exit(1);
			};
		}
		Command::Drain { address } => {
			let db = aspd::database::Db::connect(&cfg.postgres).await?;
			let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind_auth())?;

			let seed = aspd::wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
			let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

			let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
			let mut w = Server::open_round_wallet(&cfg, db.clone(), &master_xpriv, deep_tip).await?;

			let tx = w.drain(address, &bitcoind).await?;
			println!("{}", tx.compute_txid());
		}
		Command::GetMnemonic => {
			println!("{}", aspd::wallet::read_mnemonic_from_datadir(&cfg.data_dir)?);
		}
	}

	Ok(())
}

fn init_logging_rpc() {
	let colors = fern::colors::ColoredLevelConfig::default();
	fern::Dispatch::new()
		.level(log::LevelFilter::Trace)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("bitcoincore_rpc", log::LevelFilter::Warn)
		.format(move |out, msg, rec| {
			let now = chrono::Local::now();
			// only time, not date
			let stamp = now.format("%H:%M:%S.%3f");
			out.finish(format_args!(
				"[{} {: >5}] {}", stamp, colors.color(rec.level()), msg,
			))
		})
		.chain(std::io::stderr())
		.apply().expect("error setting up logging");
}

async fn run_rpc(addr: &str, cmd: RpcCommand) -> anyhow::Result<()> {
	init_logging_rpc();

	let addr = if addr.starts_with("http") {
		addr.to_owned()
	} else {
		format!("http://{}", addr)
	};
	let asp_endpoint = Uri::from_str(&addr).context("invalid asp addr")?;
	let mut asp = rpc::AdminServiceClient::connect(asp_endpoint)
		.await.context("failed to connect to asp")?;

	match cmd {
		RpcCommand::Wallet => {
			let res = asp.wallet_status(protos::Empty {}).await?.into_inner();
			let ret = serde_json::json!({
				"rounds": WalletStatus(res.rounds.unwrap().try_into().expect("invalid response")),
			});
			serde_json::to_writer_pretty(std::io::stdout(), &ret).unwrap();
			println!("");
		},
		RpcCommand::TriggerRound => {
			asp.trigger_round(protos::Empty {}).await?.into_inner();
		}
		RpcCommand::Stop => unimplemented!(),
	}
	Ok(())
}

struct WalletStatus(rpc::WalletStatus);

impl serde::Serialize for WalletStatus {
	fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
		use serde::ser::SerializeStruct;
		let mut s = ser.serialize_struct("", 7)?;
		s.serialize_field("address", &self.0.address)?;
		s.serialize_field("total_balance", &self.0.total_balance.to_sat())?;
		s.serialize_field("trusted_pending_balance", &self.0.trusted_pending_balance.to_sat())?;
		s.serialize_field("untrusted_pending_balance", &self.0.untrusted_pending_balance.to_sat())?;
		s.serialize_field("confirmed_balance", &self.0.confirmed_balance.to_sat())?;
		s.serialize_field("confirmed_utxos", &self.0.confirmed_utxos)?;
		s.serialize_field("unconfirmed_utxos", &self.0.unconfirmed_utxos)?;
		s.end()
	}
}
