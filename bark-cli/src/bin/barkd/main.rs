use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use clap::builder::BoolishValueParser;
use log::info;
use tokio::sync::RwLock;

use bark::daemon::CancellationToken;
use bark_rest::{Config, RestServer};

use bark_cli::log::init_logging;
use bark_cli::wallet::open_wallet;


/// The full version string we show in our binary.
/// (GIT_HASH is set in build.rs)
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")");

fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		std::env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

#[derive(Parser)]
#[command(name = "barkd", about = "Bark daemon", version = FULL_VERSION)]
struct Cli {
	/// Enable verbose logging
	#[arg(
		long,
		short = 'v',
		env = "BARK_VERBOSE",
		global = true,
		value_parser = BoolishValueParser::new(),
	)]
	verbose: bool,
	/// Disable all terminal logging
	#[arg(
		long,
		short = 'q',
		env = "BARK_QUIET",
		global = true,
		value_parser = BoolishValueParser::new(),
	)]
	quiet: bool,

	/// The datadir of the bark wallet
	#[arg(long, env = "BARKD_DATADIR", default_value_t = default_datadir())]
	datadir: String,
	/// The port to listen on
	#[arg(long, env = "BARKD_PORT")]
	port: Option<u16>,
	/// The host to listen on
	#[arg(long, env = "BARKD_HOST")]
	host: Option<String>,
}

impl Cli {
	fn to_config(&self) -> Config {
		let mut cfg = Config::default();
		if let Some(port) = &self.port {
			cfg.port = *port;
		}
		if let Some(host) = &self.host {
			cfg.host = host.parse().unwrap();
		}
		cfg
	}
}

/// Runs a thread that will watch for SIGTERM and ctrl-c signals.
fn run_shutdown_signal_listener() -> CancellationToken {
	let shutdown = CancellationToken::new();

	let cloned = shutdown.clone();
	tokio::spawn(async move {
		async fn signal_recv() {
			#[cfg(unix)]
			{
				let mut sigterm = tokio::signal::unix::signal(
					tokio::signal::unix::SignalKind::terminate()
				).expect("Failed to listen for SIGTERM");

				sigterm.recv().await;
				info!("SIGTERM received! Sending shutdown signal...");
				return;
			}

			#[cfg(windows)]
			{
				let mut ctrl_break = tokio::signal::windows::ctrl_break()
					.expect("Failed to listen for CTRL+BREAK");

				ctrl_break.recv().await;
				info!("CTRL+BREAK received! Sending shutdown signal...");
				return
			}

			#[cfg(not(any(unix, windows)))]
			{
				log::warn!("Unknown platform, not listening for shutdown signals");
				std::future::pending().await
			}
		}

		tokio::select! {
			_ = signal_recv() => {},
			r = tokio::signal::ctrl_c() => match r {
				Ok(()) => info!("Ctrl+C received! Sending shutdown signal..."),
				Err(e) => panic!("failed to listen to ctrl-c signal: {e}"),
			},
		}

		let _ = cloned.cancel();
	});

	shutdown
}


#[tokio::main]
async fn main() -> anyhow::Result<()>{
	let cli = Cli::parse();

	let datadir = PathBuf::from_str(&cli.datadir).unwrap();

	init_logging(cli.verbose, cli.quiet, &datadir);
	info!("Starting barkd daemon with version {}", FULL_VERSION);

	let (wallet, onchain) = open_wallet(&datadir).await?;
	let wallet = Arc::new(wallet);
	let onchain = Arc::new(RwLock::new(onchain));

	let shutdown = run_shutdown_signal_listener();
	wallet.run_daemon(shutdown.clone(), onchain.clone()).await?;

	let server = RestServer::new(shutdown.clone(), cli.to_config(), wallet, onchain);
	server.serve().await?;

	Ok(())
}
