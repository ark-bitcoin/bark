use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::rand::{self, RngCore};
use clap::{Parser, Subcommand};
use clap::builder::BoolishValueParser;
use log::{info, warn};
use tokio::sync::RwLock;

use bark::pid_lock::PidLock;
use bark_json::web::{BarkNetwork, BitcoindAuth, ChainSourceConfig, CreateWalletRequest};
use bark_rest::{Config, OnWalletCreate, OnWalletDelete, RestServer, ServerWallet};
use bark_rest::http::HeaderValue;
use bark_rest::error::ContextExt;
use bark_rest::auth::AuthToken;

use bark_cli::VERSION_DIRTY;
use bark_cli::log::init_logging;
use bark_cli::wallet::{ConfigOpts, CreateOpts, create_wallet, open_wallet, AUTH_TOKEN_FILE};


/// The full version string we show in our binary.
/// (BARK_VERSION and GIT_HASH are set in build.rs)
const FULL_VERSION: &str = concat!(env!("BARK_VERSION"), " (", env!("GIT_HASH"), ")");


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
	#[arg(long, env = "BARKD_DATADIR", global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Option<Command>,

	/// The port to listen on
	#[arg(long, env = "BARKD_BIND_PORT")]
	port: Option<u16>,
	/// The host to listen on
	#[arg(long, env = "BARKD_BIND_HOST")]
	host: Option<String>,

	/// Comma-separated list of allowed CORS origins (e.g. "http://localhost:3001,https://myapp.example.com").
	/// If not set, all cross-origin requests are denied.
	#[arg(long, env = "BARKD_ALLOWED_ORIGINS", value_delimiter = ',')]
	allowed_origins: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
	/// Manage auth secrets
	Secret {
		#[command(subcommand)]
		action: SecretCommand,
	},
}

fn parse_hex_secret(s: &str) -> Result<[u8; 32], String> {
	<[u8; 32]>::from_hex(s)
		.map_err(|_| "must be exactly 64 hex characters (32 bytes)".to_string())
}

#[derive(Subcommand)]
enum SecretCommand {
	/// Print the current bearer token.
	Show,
	/// Regenerate the default auth secret and print the bearer token.
	/// If --secret is provided, use that instead of generating a random one.
	Refresh {
		/// Optional 32-byte hex secret to use instead of a random one
		#[arg(long, value_parser = parse_hex_secret)]
		secret: Option<[u8; 32]>,
	},
}

impl Cli {
	fn to_config(&self) -> anyhow::Result<Config> {
		let mut cfg = Config::default();
		if let Some(port) = &self.port {
			cfg.port = *port;
		}
		if let Some(host) = &self.host {
			cfg.host = host.parse()
				.with_context(|| format!("invalid bind host: {host}"))?;
		}
		// Validate that each origin is a well-formed origin (scheme://host[:port]).
		for origin in &self.allowed_origins {
			origin.parse::<HeaderValue>()
				.with_context(|| format!("invalid CORS origin: {origin}"))?;
			let valid = (origin.starts_with("http://") || origin.starts_with("https://"))
				&& !origin.ends_with('/')
				&& origin.matches("://").count() == 1;
			if !valid {
				bail!(
					"invalid CORS origin: {origin} \
					(expected format: http://host[:port] or https://host[:port])"
				);
			}
		}
		cfg.allowed_origins = self.allowed_origins.clone();
		Ok(cfg)
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

/// Load the auth token from the datadir. Returns `None` if the file
/// doesn't exist.
fn load_auth_token(datadir: &PathBuf) -> anyhow::Result<Option<AuthToken>> {
	let path = datadir.join(AUTH_TOKEN_FILE);
	if !path.exists() {
		return Ok(None);
	}

	let str = std::fs::read_to_string(&path)
		.with_context(|| format!("failed to read {}", path.display()))?;
	Ok(Some(AuthToken::decode(&str)?))
}

/// Write the auth token to the datadir.
fn store_auth_token(datadir: &PathBuf, token: &AuthToken) -> anyhow::Result<()> {
	let path = datadir.join(AUTH_TOKEN_FILE);
	std::fs::write(&path, token.encode())
		.with_context(|| format!("failed to write {}", path.display()))?;
	Ok(())
}

/// Generate a random auth token and persist it to the datadir.
fn generate_store_auth_token(datadir: &PathBuf) -> anyhow::Result<AuthToken> {
	let mut secret = [0u8; 32];
	rand::thread_rng().fill_bytes(&mut secret);
	let token = AuthToken::new(secret);
	store_auth_token(datadir, &token)?;
	Ok(token)
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
		socks5_proxy: None,
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
		use_filestore: false,
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

	// Handle subcommands that don't start the daemon.
	if let Some(command) = &cli.command {
		if cli.port.is_some() || cli.host.is_some() {
			warn!("--port and --host are only used when running the daemon, ignoring");
		}

		match command {
			Command::Secret { action: SecretCommand::Show } => {
				let token = load_auth_token(&datadir)?
					.context("no auth token found — run `barkd secret refresh` to generate one")?;
				println!("{}", token.encode());
				return Ok(());
			},
			Command::Secret { action: SecretCommand::Refresh { secret: user_secret } } => {
				let token = if let Some(bytes) = user_secret {
					let token = AuthToken::new(*bytes);
					store_auth_token(&datadir, &token)?;
					token
				} else {
					generate_store_auth_token(&datadir)?
				};
				eprintln!("Restart barkd for the new token to take effect.");
				println!("{}", token.encode());
				return Ok(());
			},
		}
	}

	info!("Starting barkd version {} with datadir {}", FULL_VERSION, datadir.display());
	let _pid_lock = PidLock::acquire(&datadir)?;

	if env!("BARK_VERSION") == VERSION_DIRTY {
		warn!("You're running a custom build of barkd, which might cause unexpected issues. \
			Consider building at one of the tagged versions or using the release builds.");
	}

	let auth_token = match load_auth_token(&datadir)? {
		Some(token) => token,
		None => {
			let token = generate_store_auth_token(&datadir)?;
			eprintln!("No auth tokens found — generated default token: {}", token.encode());
			token
		},
	};

	let (wallet_opt, daemon_opt) = if let Some((wallet, onchain)) = open_wallet(&datadir).await? {
		let wallet = Arc::new(wallet);
		let onchain = Arc::new(RwLock::new(onchain));

		let daemon = wallet.run_daemon(Some(onchain.clone()))?;
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

				let daemon_handle = wallet.run_daemon(Some(onchain.clone()))?;
				let _ = daemon.write().await.insert(daemon_handle);

				let handle = ServerWallet::new(wallet, onchain);
				Ok::<_, anyhow::Error>(handle)
			})
		}
	});

	let daemon_delete = daemon.clone();
	let on_wallet_delete: Arc<OnWalletDelete> = Arc::new({
		let datadir = datadir.clone();
		move || {
			let datadir = datadir.clone();
			let daemon_delete = daemon_delete.clone();
			Box::pin(async move {
				// Stop daemon first
				if let Some(d) = daemon_delete.write().await.take() {
					d.stop();
				}
				// Wipe datadir
				let _ = tokio::fs::remove_dir_all(&datadir).await.ok();
				tokio::fs::create_dir_all(&datadir).await?;
				Ok(())
			})
		}
	});

	let server = RestServer::start(
		&cli.to_config()?, Some(auth_token), wallet_opt, Some(on_wallet_create), Some(on_wallet_delete),
	).await?;

	run_shutdown_signal_listener().await;

	if let Some(daemon) = daemon.write().await.take() {
		daemon.stop();
	}

	if let Err(e) = server.stop_wait().await {
		warn!("Error while stopping REST server: {:#}", e);
	}

	Ok(())
}
