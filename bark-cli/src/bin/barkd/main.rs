use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bark_json::web::{BarkNetwork, BitcoindAuth, ChainSourceConfig, CreateWalletRequest};
use bark_rest::error::ContextExt;
use clap::Parser;
use clap::builder::BoolishValueParser;
use log::{info, warn};
use tokio::sync::RwLock;

use bark_rest::{Config, OnWalletCreate, RestServer, ServerWallet};

use bark_cli::log::init_logging;
use bark_cli::wallet::{ConfigOpts, CreateOpts, create_wallet, open_wallet};


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

/// Runs a thread that will watch for SIGTERM and ctrl-c signals and
/// returns when a signal is received
async fn run_shutdown_signal_listener() {
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
}

fn wallet_create_request_to_create_opts(req: CreateWalletRequest) -> anyhow::Result<CreateOpts> {
	let mnemonic = if let Some(mnemonic) = req.mnemonic {
		Some(bip39::Mnemonic::from_str(&mnemonic).badarg("Invalid mnemonic")?)
	} else {
		None
	};

	let mut config = ConfigOpts {
		ark: Some(req.ark_server),
		esplora: None,
		bitcoind: None,
		bitcoind_cookie: None,
		bitcoind_user: None,
		bitcoind_pass: None,
	};

	match req.chain_source {
		ChainSourceConfig::Esplora { url } => {
			config.esplora = Some(url);
		},
		ChainSourceConfig::Bitcoind { bitcoind, bitcoind_auth } => {
			config.bitcoind = Some(bitcoind);
			match bitcoind_auth {
				BitcoindAuth::Cookie { cookie } => {
					config.bitcoind_cookie = Some(cookie);
				},
				BitcoindAuth::UserPass { user, pass } => {
					config.bitcoind_user = Some(user);
					config.bitcoind_pass = Some(pass);
				},
			}
		},
	}

	Ok(CreateOpts {
		force: false,
		mainnet: req.network == BarkNetwork::Mainnet,
		regtest: req.network == BarkNetwork::Regtest,
		signet: req.network == BarkNetwork::Signet,
		mutinynet: req.network == BarkNetwork::Mutinynet,
		mnemonic: mnemonic,
		birthday_height: req.birthday_height,
		config: config,
	})
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
	let cli = Cli::parse();

	let datadir = PathBuf::from_str(&cli.datadir).unwrap();

	init_logging(cli.verbose, cli.quiet, &datadir);
	info!("Starting barkd daemon with version {}", FULL_VERSION);

	let (wallet_opt, daemon_opt) = if let Some((wallet, onchain)) = open_wallet(&datadir).await? {
		let wallet = Arc::new(wallet);
		let onchain = Arc::new(RwLock::new(onchain));

		let daemon = wallet.run_daemon(onchain.clone()).await?;
		info!("Wallet loaded and daemon started");
		let server_wallet = bark_rest::ServerWallet::new(wallet, onchain);

		(Some(server_wallet), Some(daemon))
	} else {
		warn!("No wallet found. Starting rest server without daemon");
		(None, None)
	};

	let daemon = Arc::new(RwLock::new(daemon_opt));

	let cloned_daemon = daemon.clone();
	let on_wallet_create: Arc<OnWalletCreate> = Arc::new({
		let datadir = datadir.clone();

		move |req: CreateWalletRequest| {
			let datadir = datadir.clone();
			let daemon = cloned_daemon.clone();


			Box::pin(async move {
				let create_opts = wallet_create_request_to_create_opts(req)?;
				create_wallet(&datadir, create_opts).await?;
				let (wallet, onchain) = open_wallet(&datadir).await?
					.expect("Wallet should exist");

				let wallet = Arc::new(wallet);
				let onchain = Arc::new(RwLock::new(onchain));

				let daemon_handle = wallet.run_daemon(onchain.clone()).await?;
				let _ = daemon.write().await.insert(daemon_handle);

				let handle = ServerWallet::new(wallet, onchain);
				Ok::<_, anyhow::Error>(handle)
			})
		}
	});

	let server = RestServer::start(&cli.to_config(), wallet_opt, Some(on_wallet_create)).await?;

	run_shutdown_signal_listener().await;

	if let Some(daemon) = daemon.write().await.take() {
		daemon.stop();
	}

	if let Err(e) = server.stop_wait().await {
		warn!("Error while stopping REST server: {:#}", e);
	}

	Ok(())
}
