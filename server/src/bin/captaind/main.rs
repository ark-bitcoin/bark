
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
use anyhow::{bail, Context};
use bitcoin::{bip32, Address};
use chrono::Local;
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};
use clap::{Args, Parser};
use log::{error, info};
use serde::{Deserialize, Serialize};
use tonic::transport::Uri;

use ark::integration::{TokenStatus, TokenType};
use server::{Server, Config, filters};
use server_log::{RecordSerializeWrapper, SLOG_FILENAME};
use server_rpc::{self as rpc, protos};

/// Defaults to our default port on localhost.
const DEFAULT_ADMIN_RPC_ADDR: &str = "127.0.0.1:3536";

/// The full semver version to set, which includes the git commit hash
/// as the build suffix.
/// (GIT_HASH is set in build.rs)
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("GIT_HASH"));

#[derive(Parser)]
#[command(
	name = "captaind",
	author = "Team Second <hello@second.tech>",
	version = FULL_VERSION,
	about,
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
	/// Create and configure the server
	#[command()]
	Create,

	/// Start the server
	#[command()]
	Start,

	/// Drain funds from the server
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

	/// Run integration management commands
	#[command()]
	Integration {
		#[command(subcommand)]
		cmd: IntegrationCommand,
	}
}

#[derive(clap::Subcommand)]
enum RpcCommand {
	/// Report server wallet status
	#[command()]
	Wallet,

	/// Start a new round
	#[command()]
	TriggerRound,
}

#[derive(clap::Subcommand)]
enum IntegrationCommand {
	/// Add a new integration
	#[command()]
	Add {
		/// Name of the integration
		integration_name: String,
	},
	/// Deactivate an integration
	#[command()]
	Remove {
		/// Name of the integration to remove
		integration_name: String,
	},
	/// Generate an API key
	#[command()]
	GenerateApiKey {
		/// Name of the integration to generate an API key for
		integration_name: String,
		/// Name of the API key
		api_key_name: String,
		/// Filters for the API key
		#[command(flatten)]
		filters: Filters,
		/// How long the API key should be active
		/// eg: "1month"
		/// We are using the humantime rust crate to parse the input
		expiry: String,
	},
	/// Disable an API key
	#[command()]
	DisableApiKey {
		/// Name of the integration to generate an API key for
		integration_name: String,
		/// Name of the API key
		api_key_name: String,
	},
	/// Update the filters of an API key
	#[command()]
	UpdateApiKeyFilters {
		/// Name of the integration to generate an API key for
		integration_name: String,
		/// Name of the API key
		api_key_name: String,
		/// Filters for the API key
		#[command(flatten)]
		filters: Filters,
	},
	/// Configure an integration token type
	#[command()]
	ConfigureTokenType {
		/// Name of the integration
		integration_name: String,
		/// Type of the token
		/// eg: single-use-board
		token_type: TokenType,
		/// Maximum number of open tokens
		maximum_open_tokens: u32,
		/// Token's active duration in seconds
		active_seconds: u32,
	},
	/// Generate a token
	#[command()]
	GenerateToken {
		/// Name of the integration to generate a token for
		integration_name: String,
		/// The integration's API key
		integration_api_key: uuid::Uuid,
		/// Type of the token
		token_type: TokenType,
		/// Filters for the token
		#[command(flatten)]
		filters: Filters,
	},
	/// Update the status of a token
	#[command()]
	UpdateTokenStatus {
		/// Name of the integration to generate a token for
		integration_name: String,
		/// The integration's API key
		integration_api_key: uuid::Uuid,
		/// Token
		token: String,
		/// Status of the token
		status: TokenStatus,
	},
	/// Update the filters of a token
	#[command()]
	UpdateTokenFilters {
		/// Name of the integration to generate a token for
		integration_name: String,
		/// The integration's API key
		integration_api_key: uuid::Uuid,
		/// Token
		token: String,
		/// Filters for the token
		#[command(flatten)]
		filters: Filters,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Args)]
pub struct Filters {
	#[arg(long, num_args = 0..)]
	#[serde(default)]
	ip: Vec<String>,
	#[arg(long, num_args = 0..)]
	#[serde(default)]
	dns: Vec<String>,
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
		eprintln!("An error occurred: {}", e);
		eprintln!("");
		eprintln!("{:?}", e);
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
					serde_json::to_writer(&mut buf, &server_log::SourceSerializeWrapper(rec.key_values())).unwrap();
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
			.filter(|m| m.target() == server_log::SLOG_TARGET)
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
				error!("Shutdown error from server {:?}", e);

				process::exit(1);
			};
		}
		Command::Drain { address } => {
			let db = server::database::Db::connect(&cfg.postgres).await?;
			let bitcoind = BitcoinRpcClient::new(&cfg.bitcoind.url, cfg.bitcoind.auth())?;

			let seed = server::wallet::read_mnemonic_from_datadir(&cfg.data_dir)?.to_seed("");
			let master_xpriv = bip32::Xpriv::new_master(cfg.network, &seed).unwrap();

			let deep_tip = bitcoind.deep_tip().context("failed to query node for deep tip")?;
			let mut w = Server::open_round_wallet(&cfg, db.clone(), &master_xpriv, deep_tip).await?;

			let tx = w.drain(address, &bitcoind).await?;
			println!("{}", tx.compute_txid());
		}
		Command::GetMnemonic => {
			println!("{}", server::wallet::read_mnemonic_from_datadir(&cfg.data_dir)?);
		}
		Command::Integration { cmd } => {
			let db = server::database::Db::connect(&cfg.postgres).await?;
			match cmd {
				IntegrationCommand::Add {
					integration_name,
				} => {
					let integration = db.store_integration(integration_name.as_str()).await?;
					println!("{}", integration.id);
				}
				IntegrationCommand::Remove {
					integration_name,
				} => {
					let mut integration = db.get_integration_by_name(integration_name.as_str()).await?.expect("no such integration");
					integration.deleted_at = Some(Local::now());
					let _ = db.delete_integration(integration.id).await?;
					println!("Deleted {}", integration_name);
				}
				IntegrationCommand::GenerateApiKey {
					integration_name, api_key_name, filters, expiry,
				} => {
					let db_filters = filters::Filters::init(filters.ip, filters.dns);
					let api_key = uuid::Uuid::new_v4();
					let integration = db.get_integration_by_name(integration_name.as_str()).await?
						.expect("Invalid integration name");
					let expiry_duration = humantime::parse_duration(expiry.as_str())
						.context("Invalid value for <EXPIRY>")?;
					let expiry = Local::now() + chrono::Duration::seconds(expiry_duration.as_secs() as i64);
					let integration_api_key = db.store_integration_api_key(
						api_key_name.as_str(),
						api_key,
						&db_filters,
						integration.id,
						expiry,
					).await?;
					println!("API Key: {}", integration_api_key.api_key.to_string())
				}
				IntegrationCommand::DisableApiKey {
					integration_name, api_key_name,
				} => {
					let integration_api_key =
						db.get_integration_api_key_by_name(integration_name.as_str(), api_key_name.as_str()).await?
							.expect("invalid API Key");
					db.delete_integration_api_key(integration_api_key.id, integration_api_key.updated_at).await?;
					println!("Deleted {}", api_key_name);
				}
				IntegrationCommand::UpdateApiKeyFilters {
					integration_name, api_key_name, filters,
				} => {
					let filters = filters::Filters::init(filters.ip, filters.dns);
					let integration_api_key =
						db.get_integration_api_key_by_name(integration_name.as_str(), api_key_name.as_str()).await?
							.expect("invalid API Key");

					let integration_api_key = db.update_integration_api_key(
						integration_api_key,
						&filters,
					).await?;
					println!("{}", integration_api_key.id);
				}
				IntegrationCommand::ConfigureTokenType {
					integration_name, token_type, maximum_open_tokens, active_seconds,
				} => {
					let integration = db.get_integration_by_name(integration_name.as_str()).await?
						.expect("Invalid integration name");
					let existing_config = db.get_integration_token_config(token_type, integration.id).await?;
					let integration_token_config = if let Some(existing_config) = existing_config {
						db.update_integration_token_config(
							existing_config,
							maximum_open_tokens,
							active_seconds,
						).await?
					} else {
						db.store_integration_token_config(
							token_type,
							maximum_open_tokens,
							active_seconds,
							integration.id,
						).await?
					};
					println!("{}", integration_token_config.id);
				}
				IntegrationCommand::GenerateToken {
					integration_name, integration_api_key, token_type, filters,
				} => {
					let db_filters = filters::Filters::init(filters.ip, filters.dns);
					let token = uuid::Uuid::new_v4().to_string();
					let integration = db.get_integration_by_name(integration_name.as_str()).await?
						.expect("Invalid integration name");
					let integration_token_config = db.get_integration_token_config(token_type, integration.id).await?
						.expect("no token configuration found");
					let integration_api_key = db.get_integration_api_key_by_api_key(integration_api_key).await?
						.expect("invalid API Key");
					let expiry_time = Local::now() +
						chrono::Duration::seconds(integration_token_config.active_seconds as i64);

					let integration_token = db.store_integration_token(
						token.as_str(),
						token_type,
						TokenStatus::Unused,
						expiry_time,
						&db_filters,
						integration.id,
						integration_api_key.id,
					).await?;
					println!("Token: {}", integration_token.token);
				}
				IntegrationCommand::UpdateTokenStatus {
					integration_name, integration_api_key, token, status,
				} => {
					let integration = db.get_integration_by_name(integration_name.as_str()).await?
						.expect("invalid integration name");
					let integration_token =
						db.get_integration_token(token.as_str()).await?
							.expect("invalid Token");

					if integration.id != integration_token.integration_id {
						bail!("integration doesn't match token");
					}

					let integration_api_key = db.get_integration_api_key_by_api_key(integration_api_key).await?
						.expect("invalid API Key");

					let integration_token = db.update_integration_token(
						integration_token.clone(),
						integration_api_key.id,
						status,
						&integration_token.filters,
					).await?;
					println!("{}", integration_token.id);
				}
				IntegrationCommand::UpdateTokenFilters {
					integration_name, integration_api_key, token, filters,
				} => {
					let filters = filters::Filters::init(filters.ip, filters.dns);
					let integration = db.get_integration_by_name(integration_name.as_str()).await?
						.expect("invalid integration name");
					let integration_token =
						db.get_integration_token(token.as_str()).await?
							.expect("invalid Token");

					if integration.id != integration_token.integration_id {
						bail!("integration doesn't match token");
					}

					let integration_api_key = db.get_integration_api_key_by_api_key(integration_api_key).await?
						.expect("invalid API Key");

					let integration_token = db.update_integration_token(
						integration_token.clone(),
						integration_api_key.id,
						integration_token.status,
						&filters,
					).await?;
					println!("{}", integration_token.id);
				}
			}
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
	let endpoint = Uri::from_str(&addr).context("invalid rpc addr")?;

	match cmd {
		RpcCommand::Wallet => {
			let mut rpc = rpc::admin::WalletAdminServiceClient::connect(endpoint)
				.await.context("failed to connect to rpc")?;

			let res = rpc.wallet_status(protos::Empty {}).await?.into_inner();
			let ret = serde_json::json!({
				"rounds": WalletStatus(res.rounds.unwrap().try_into().expect("invalid response")),
			});
			serde_json::to_writer_pretty(std::io::stdout(), &ret).unwrap();
			println!("");
		},
		RpcCommand::TriggerRound => {
			let mut rpc = rpc::admin::RoundAdminServiceClient::connect(endpoint)
				.await.context("failed to connect to rpc")?;

			rpc.trigger_round(protos::Empty {}).await?.into_inner();
		}
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
