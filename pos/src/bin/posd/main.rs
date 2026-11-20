use std::path::PathBuf;
use std::process;

use anyhow::Context;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pos::config::Config;


#[derive(Parser)]
#[command(name = "posd", version, about = "The scuttle point-of-sale service")]
struct Cli {
	/// The config file. `POSD__` environment variables override it.
	#[arg(long, short = 'C', global = true, env = "POSD_CONFIG")]
	config: Option<PathBuf>,
	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Runs the service.
	Start,
	/// Checks the config and prints it.
	CheckConfig,
}

#[tokio::main]
async fn main() {
	tracing_subscriber::fmt()
		.with_env_filter(EnvFilter::try_from_default_env()
			.unwrap_or_else(|_| EnvFilter::new("info,tokio_postgres=warn")))
		.init();
	if let Err(e) = inner_main().await {
		eprintln!("An error occurred: {}", e);
		eprintln!();
		eprintln!("{:?}", e);
		process::exit(1);
	}
}

async fn inner_main() -> anyhow::Result<()> {
	let cli = Cli::parse();
	let cfg = Config::load(cli.config.as_deref())?;
	match cli.command {
		Command::CheckConfig => {
			println!("{}", serde_json::to_string_pretty(&cfg)?);
			Ok(())
		},
		Command::Start => start(cfg).await,
	}
}

async fn start(cfg: Config) -> anyhow::Result<()> {
	let listen = cfg.http.listen;
	let app = pos::App::new(cfg).await?;
	tokio::spawn(pos::watcher::run(app.clone()));

	let listener = tokio::net::TcpListener::bind(listen).await
		.with_context(|| format!("failed to listen on {}", listen))?;
	tracing::info!("posd listening on {}", listen);
	axum::serve(listener, pos::api::router(app))
		.with_graceful_shutdown(async {
			let _ = tokio::signal::ctrl_c().await;
		})
		.await?;
	Ok(())
}
