
#[path = "../common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::process;

use clap::Parser;
use log::{error, info};

use server::config::watchman::Config;
use server::watchman::Watchman;

/// The full semver version to set, which includes the git commit hash
/// as the build suffix.
/// (GIT_HASH is set in build.rs)
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("GIT_HASH"));

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
}

#[tokio::main]
async fn main() {
	common::set_panic_hook();

	if let Err(e) = inner_main().await {
		eprintln!("An error occurred: {}", e);
		eprintln!("");
		eprintln!("{:?}", e);
		process::exit(1);
	}
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	let cfg = Config::load(cli.config.as_ref().map(|p| p.as_path()))?;
	cfg.validate().expect("invalid configuration");

	common::init_logging();
	info!("Running with config: {:#?}", cfg);

	match cli.command {
		Command::Start => {
			if let Err(e) = Watchman::run(cfg).await {
				error!("Shutdown error from server {:?}", e);

				process::exit(1);
			};
		},
	}

	Ok(())
}

