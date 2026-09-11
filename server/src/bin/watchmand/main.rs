
#[path = "../common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::process;
use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use tonic::transport::Uri;
use tracing::{debug, error};
use server::config::watchmand::Config;
use server::watchman::Daemon;
use server_rpc::{self as rpc, protos};

/// Defaults to our default port on localhost.
const DEFAULT_ADMIN_RPC_ADDR: &str = "127.0.0.1:3538";

/// The full semver version to set, which includes the git commit hash
/// as the build suffix.
/// (SERVER_VERSION and GIT_HASH are set in build.rs)
const FULL_VERSION: &str = concat!(env!("SERVER_VERSION"), "+", env!("GIT_HASH"));

#[derive(Parser)]
#[command(
	name = "watchmand",
	author = "Team Second <hello@second.tech>",
	version = FULL_VERSION,
	about = "daemon to run background watcher processes not critical for user-facing operations",
)]
struct Cli {
	/// Path to the configuration file
	#[arg(global = true, short = 'C', long)]
	config: Option<PathBuf>,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Start the watchman server
	#[command()]
	Start,

	/// Run RPC commands against a running watchmand
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
	/// Run the reaction and sweep loops right now
	#[command()]
	TriggerSweep,

	/// Re-index the frontier, repairing missed confirmations and on-chain
	/// spends of the VTXOs the watchman tracks
	#[command()]
	ReindexFrontier,
}

#[tokio::main]
async fn main() {
	common::set_panic_hook();

	if let Err(e) = inner_main().await {
		eprintln!("An error occurred: {}", e);
		eprintln!("");
		eprintln!("{:?}", e);

		error!(
			error = %e,
			error_debug = ?e,
			"An error occurred"
		);

		process::exit(1);
	}
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	if let Command::Rpc { cmd, addr } = cli.command {
		// Setting simple logging with no telemetry for RPC commands
		tracing_subscriber::fmt::init();

		let rpc_addr = match cli.config {
			Some(path) => {
				let cfg = Config::load(&path).context("error loading config file")?;
				cfg.admin_address
					.with_context(|| format!("No config for admin_address in {:?}", path))?
					.to_string()
			},
			None => addr,
		};

		return run_rpc(&rpc_addr, cmd).await;
	}

	let cfg = Config::load(cli.config.as_ref().context("no config file path provided")?)
		.context("error loading config file")?;
	cfg.validate().expect("invalid configuration");

	match cli.command {
		Command::Rpc { .. } => unreachable!(),
		Command::Start => {
			if let Err(e) = Daemon::run(cfg).await {
				eprintln!("Error from server {:?}", e);

				process::exit(1);
			};
		},
	}

	Ok(())
}

async fn run_rpc(addr: &str, cmd: RpcCommand) -> anyhow::Result<()> {
	let addr = if addr.starts_with("http") {
		addr.to_owned()
	} else {
		format!("http://{}", addr)
	};
	let endpoint = Uri::from_str(&addr).context("invalid rpc addr")?;

	debug!("Query admin rpc-endpoint at {}", endpoint);

	let mut rpc = rpc::admin::WatchmanAdminServiceClient::connect(endpoint)
		.await.context("failed to connect to rpc")?;

	match cmd {
		RpcCommand::TriggerSweep => {
			rpc.trigger_sweep(protos::Empty {}).await?.into_inner();
			println!("Sweep triggered");
		},
		RpcCommand::ReindexFrontier => {
			let res = rpc.reindex_frontier(protos::Empty {}).await?.into_inner();
			let ret = serde_json::json!({
				"entries_checked": res.entries_checked,
				"confirmations_repaired": res.confirmations_repaired,
				"confirmations_cleared": res.confirmations_cleared,
				"spends_cleared": res.spends_cleared,
				"spends_repaired": res.spends_repaired,
				"vtxos_added": res.vtxos_added,
				"funding_txs_added": res.funding_txs_added,
				"funding_vtxos_added": res.funding_vtxos_added,
				"unresolved_spends": res.unresolved_spends,
				"blocks_scanned": res.blocks_scanned,
			});
			serde_json::to_writer_pretty(std::io::stdout(), &ret).unwrap();
			println!("");
		},
	}
	Ok(())
}

