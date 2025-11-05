use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;

use bark_cli::wallet::open_wallet;
use bark_rest::{Config, RestServer};


fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		std::env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

#[derive(Parser)]
#[command(name = "barkd", about = "Bark web daemon")]
struct Cli {
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

#[tokio::main]
async fn main() -> anyhow::Result<()>{
	configure_tracing();

	let cli = Cli::parse();

	let datadir = PathBuf::from_str(&cli.datadir).unwrap();

	let (wallet, onchain) = open_wallet(&datadir).await?;
	let wallet = Arc::new(wallet);
	let onchain = Arc::new(RwLock::new(onchain));

	let server = RestServer::new(cli.to_config(), wallet, onchain);
	server.serve().await?;

	Ok(())
}

/// Configures the tracing for the applicatoin
pub fn configure_tracing() {
	// Ensures all logs of trace or higher are printed to the console
	let subscriber = tracing_subscriber::fmt::Subscriber::builder()
		.with_env_filter("trace,h2=info,tower=info,tonic=info,hyper_util=info")
		.finish();
	tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");
}
