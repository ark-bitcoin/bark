
#[macro_use] extern crate log;

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use anyhow::Context;
use aspd_log::RecordSerializeWrapper;
use aspd_rpc as rpc;
use bitcoin::{Address, Amount};
use clap::Parser;
use tonic::transport::Uri;

use aspd::App;

/// Defaults to our default port on localhost.
const DEFAULT_ADMIN_RPC_ADDR: &str = "127.0.0.1:3536";

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
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
	/// Get asp balance
	#[command()]
	Balance,

	/// Get asp address
	#[command()]
	GetAddress,

	/// Start a new asp round
	#[command()]
	TriggerRound,

	/// Stop aspd
	#[command()]
	Stop,
}

#[tokio::main]
async fn main() {
	if let Err(e) = inner_main().await {
		println!("An error occurred: {}", e);
		// maybe hide second print behind a verbose flag
		println!("");
		println!("{:?}", e);
		process::exit(1);
	}
}

fn init_logging() {
	//TODO(stevenroose) add filename and line number when verbose logging
	fern::Dispatch::new()
		.level(log::LevelFilter::Trace)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("bitcoincore_rpc", log::LevelFilter::Warn)
		.level_for("tokio_postgres", log::LevelFilter::Debug)
		// regular logging dispatch
		.chain(fern::Dispatch::new()
			.format(|out, msg, rec| {
				let now = chrono::Local::now();
				let stamp = now.format("%Y-%m-%d %H:%M:%S.%3f");
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
		)
		// structured logging dispatch
		.chain(fern::Dispatch::new()
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
			.chain(std::io::stdout()) //TODO(stevenroose) pipe to file?
		)
		.apply().expect("error setting up logging");
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();
	let config_path = cli.config.as_ref().map(|p| p.as_path());

	if let Command::Rpc { cmd, addr } = cli.command {
		return run_rpc(&addr, cmd).await;
	}

	init_logging();

	match cli.command {
		Command::Rpc { .. } => unreachable!(),
		Command::Create => {
			App::create(config_path).await?;
		}
		Command::Start => {
			let mut app = App::open(config_path).await.context("server init")?;

			if let Err(e) = app.start().await {
				error!("Shutdown error from aspd {:?}", e);

				process::exit(1);
			};
		}
		Command::Drain { address } => {
			let app = App::open(config_path).await.context("server init")?;

			println!("{}", app.drain(address).await?.compute_txid());
		}
		Command::GetMnemonic => {
			let app = App::open(config_path).await.context("server init")?;
			println!("{}", app.get_master_mnemonic().await?);
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
		RpcCommand::Balance => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", Amount::from_sat(res.balance));
		},
		RpcCommand::GetAddress => {
			let res = asp.wallet_status(rpc::Empty {}).await?.into_inner();
			println!("{}", res.address);
		},
		RpcCommand::TriggerRound => {
			asp.trigger_round(rpc::Empty {}).await?.into_inner();
		}
		RpcCommand::Stop => unimplemented!(),
	}
	Ok(())
}
