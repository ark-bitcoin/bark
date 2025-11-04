#[macro_use] extern crate anyhow;

mod dev;
mod exit;
mod lightning;
mod onchain;
mod util;
mod wallet;

use std::cmp::Ordering;
use std::{cmp, env, process};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use bark::movement::Movement;
use bark::round::RoundStatus;
use bark::vtxo_state::{VtxoStateKind, WalletVtxo};
use bitcoin::{Amount, FeeRate};
use clap::builder::BoolishValueParser;
use clap::Parser;
use ::lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use log::{debug, info, warn};

use ark::VtxoId;
use bark::Config;
use bark::vtxo_selection::VtxoFilter;
use bark_json::{cli as json, primitives};
use bitcoin_ext::FeeRateExt;

use crate::util::output_json;
use crate::wallet::{CreateOpts, create_wallet, open_wallet};

fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

/// The full version string we show in our binary.
/// (GIT_HASH is set in build.rs)
const FULL_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")");

fn wallet_vtxo_to_json(vtxo: &WalletVtxo) -> primitives::WalletVtxoInfo {
	primitives::WalletVtxoInfo {
		vtxo: vtxo.vtxo.clone().into(),
		state: vtxo.state.kind().as_str().to_string(),
	}
}

fn movement_to_json(movement: &Movement) -> json::Movement {
	json::Movement {
		id: movement.id,
		fees: movement.fees,
		spends: movement.spends.clone().into_iter().map(|v| v.into()).collect(),
		receives: movement.receives.clone().into_iter().map(|v| v.into()).collect(),
		recipients: movement.recipients.iter().map(|r| primitives::RecipientInfo {
			recipient: r.recipient.clone(),
			amount: r.amount,
		}).collect(),
		created_at: movement.created_at.to_string(),
	}
}

fn round_status_to_json(status: &RoundStatus) -> json::RoundStatus {
	match status {
		RoundStatus::Confirmed { funding_txid } => {
			json::RoundStatus::Confirmed { funding_txid: *funding_txid }
		},
		RoundStatus::Unconfirmed { funding_txid } => {
			json::RoundStatus::Unconfirmed { funding_txid: *funding_txid }
		},
		RoundStatus::Pending { unsigned_funding_txids } => {
			json::RoundStatus::Pending { unsigned_funding_txids: unsigned_funding_txids.clone() }
		},
		RoundStatus::Failed { error } => {
			json::RoundStatus::Failed { error: error.clone() }
		},
	}
}

#[derive(Parser)]
#[command(name = "bark", author = "Team Second <hello@second.tech>", version = FULL_VERSION, about)]
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
	#[arg(long, env = "BARK_DATADIR", global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Args)]
struct ConfigOpts {
	/// The address of your Ark server.
	#[arg(long)]
	ark: Option<String>,

	/// The address of the Esplora HTTP server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	#[arg(long)]
	esplora: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
	#[arg(long)]
	bitcoind: Option<String>,

	/// The path to the bitcoind rpc cookie file.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_cookie: Option<String>,

	/// The bitcoind RPC username.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_user: Option<String>,

	/// The bitcoind RPC password.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_pass: Option<String>,

	/// The number of blocks before expiration to refresh vtxos.
	///
	/// Default value: 288 (48 hrs)
	#[arg(long)]
	vtxo_refresh_expiry_threshold: Option<u32>,

	/// A fallback fee rate in sats/kvB to use when we fail to retrieve a fee rate from the
	/// configured bitcoind/esplora connection instead of erroring.
	///
	/// Example for 1 sat/vB: --fallback-fee-rate 1000
	#[arg(long)]
	fallback_fee_rate: Option<u64>,
}

impl ConfigOpts {
	fn merge_into(self, cfg: &mut Config) -> anyhow::Result<()> {
		if let Some(url) = self.ark {
			cfg.server_address = util::https_default_scheme(url).context("invalid Ark server url")?;
		}
		if let Some(v) = self.esplora {
			cfg.esplora_address = match v.is_empty() {
				true => None,
				false => Some(util::https_default_scheme(v).context("invalid esplora url")?),
			};
		}
		if let Some(v) = self.bitcoind {
			cfg.bitcoind_address = if v == "" { None } else { Some(v) };
		}
		if let Some(v) = self.bitcoind_cookie {
			cfg.bitcoind_cookiefile = if v == "" { None } else { Some(v.into()) };
		}
		if let Some(v) = self.bitcoind_user {
			cfg.bitcoind_user = if v == "" { None } else { Some(v) };
		}
		if let Some(v) = self.bitcoind_pass {
			cfg.bitcoind_pass = if v == "" { None } else { Some(v) };
		}
		if let Some(v) = self.vtxo_refresh_expiry_threshold {
			cfg.vtxo_refresh_expiry_threshold = v;
		}

		if let Some(v) = self.fallback_fee_rate {
			cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_kvb_ceil(v));
		}

		if cfg.esplora_address.is_none() && cfg.bitcoind_address.is_none() {
			bail!("Provide either an esplora or bitcoind url as chain source.");
		}

		Ok(())
	}
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create a new wallet
	///
	/// Configuration will pass in default values when --signet is used, but will
	/// require full configuration for regtest
	#[command()]
	Create(CreateOpts),

	/// Print the configuration of your bark wallet
	#[command()]
	Config,

	/// Prints information related to the Ark Server
	#[command()]
	ArkInfo,

	/// Get an address to receive VTXOs
	#[command()]
	Address {
		/// address pubkey index to peak
		#[arg(long)]
		index: Option<u32>,
	},

	/// Get the wallet balance
	#[command()]
	Balance {
		/// Skip syncing before computing balance
		#[arg(long)]
		no_sync: bool,
	},

	/// List the wallet's VTXOs
	#[command()]
	Vtxos {
		/// Skip syncing before fetching VTXOs
		#[arg(long)]
		no_sync: bool,
		/// Returns all VTXOs regardless of their state
		#[arg(long)]
		all: bool,
	},

	/// List the wallet's payments
	///
	/// By default will fetch the 10 first items
	#[command()]
	Movements {
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Refresh expiring VTXOs
	///
	/// By default the wallet's configured threshold is used
	#[command()]
	Refresh {
		/// The ID of a VTXO to be refreshed, can be specified multiple times.
		#[arg(long = "vtxo", value_name = "VTXO_ID")]
		vtxos: Option<Vec<String>>,
		/// Refresh VTXOs that expire within this amount of blocks
		#[arg(long)]
		threshold_blocks: Option<u32>,
		/// Refresh VTXOs that expire within this number of hours
		#[arg(long)]
		threshold_hours: Option<u32>,
		/// Force refresh all VTXOs regardless of expiry height
		#[arg(long)]
		all: bool,
		/// Force refresh all VTXOs that have some counterparty risk,
		/// regardless of expiry height
		#[arg(long)]
		counterparty: bool,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Board from the onchain wallet into the Ark
	#[command()]
	Board {
		/// Optional amount of on-chain funds to board.
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		///
		/// Either this or --all should be provided.
		amount: Option<Amount>,
		/// Whether or not all funds in on-chain wallet should be boarded
		#[arg(long)]
		all: bool,
		/// Skip syncing wallet before board
		#[arg(long)]
		no_sync: bool,
	},

	/// Send money using Ark
	#[command()]
	Send {
		/// The destination can be an Ark address, a BOLT11-invoice, LNURL or a lightning address
		destination: String,
		/// The amount to send (optional for bolt11)
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		amount: Option<Amount>,
		/// An optional comment
		comment: Option<String>,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Send money from your vtxo's to an onchain address
	/// This method requires to wait for a round
	#[command()]
	SendOnchain {
		/// The bitcoin address to which money will be sent
		destination: String,
		/// Amount to send.
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		amount: Amount,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Turn VTXOs into UTXOs
	/// This command sends
	#[command()]
	Offboard {
		/// Optional address to receive offboarded VTXOs. If no address is provided, one will be
		/// generated from the onchain wallet
		#[arg(long)]
		address: Option<String>,
		/// Optional ID of a VTXO to offboard, this can be specified multiple times.
		/// Either this or --all should be provided
		#[arg(long = "vtxo", value_name = "VTXO_ID")]
		vtxos: Option<Vec<String>>,
		/// Whether or not all VTXOs should be offboarded. Either this or --vtxos should be provided
		#[arg(long)]
		all: bool,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Use the built-in onchain wallet
	#[command(subcommand)]
	Onchain(onchain::OnchainCommand),

	/// Perform a unilateral exit from the Ark
	#[command(subcommand)]
	Exit(exit::ExitCommand),

	/// Perform any lightning-related command
	#[command(subcommand, visible_alias = "ln")]
	Lightning(lightning::LightningCommand),

	/// developer commands
	#[command(subcommand)]
	Dev(dev::DevCommand),

	/// Run wallet maintenence
	///
	/// This includes onchain sync, offchain sync, registering boards with the server,
	/// syncing Lightning VTXOs, syncing exits, and refreshing soon-to-expire VTXOs
	#[command()]
	Maintain,
}

/// Simple logger that splits into two logger
struct SplitLogger {
	log1: env_logger::Logger,
	log2: env_logger::Logger,
}

impl SplitLogger {
	fn init(log1: env_logger::Logger, log2: env_logger::Logger) {
		let max_level = cmp::max(log1.filter(), log2.filter());
		log::set_boxed_logger(Box::new(SplitLogger {
			log1: log1,
			log2: log2,
		})).expect("error initializing split logger");
		log::set_max_level(max_level);
	}
}

impl log::Log for SplitLogger {
	fn enabled(&self, m: &log::Metadata) -> bool {
	    self.log1.enabled(m) || self.log2.enabled(m)
	}

	fn flush(&self) {
	    self.log1.flush();
		self.log2.flush();
	}

	fn log(&self, rec: &log::Record) {
		self.log1.log(rec);
		self.log2.log(rec);
	}
}

fn init_logging(verbose: bool, quiet: bool, datadir: &Path) {
	if verbose && quiet {
		println!("Can't set both --verbose and --quiet");
		process::exit(1);
	}

	let env = env_logger::Env::new().filter("BARK_LOG");

	// Builder has no clone and we don't want to repeat this
	fn base() -> env_logger::Builder {
		let mut builder = env_logger::Builder::new();
		builder
			.filter_module("rusqlite", log::LevelFilter::Warn)
			.filter_module("rustls", log::LevelFilter::Warn)
			.filter_module("reqwest", log::LevelFilter::Warn);
		builder
	}

	let terminal = if !quiet {
		let mut logger = base();

		// We first set the default and then let the env_logger
		// env overwrite it.
		logger.filter_level(if verbose {
			log::LevelFilter::Trace
		} else {
			log::LevelFilter::Info
		});

		logger.parse_env(env)
			.format(move |out, rec| {
				let now = chrono::Local::now();
				let ts = now.format("%Y-%m-%d %H:%M:%S.%3f");
				let lvl = rec.level();
				let msg = rec.args();
				if verbose {
					let module = rec.module_path().expect("no module");
					if module.starts_with("bark") {
						let file = rec.file().expect("our macro provides file");
						let file = file.split("bark/src/").last().unwrap();
						let line = rec.line().expect("our macro provides line");
						writeln!(out, "[{ts} {lvl: >5} {module} {file}:{line}] {msg}")
					} else {
						writeln!(out, "[{ts} {lvl: >5} {module}] {msg}")
					}
				} else {
					writeln!(out, "[{ts} {lvl: >5}] {msg}")
				}
			})
			.target(env_logger::Target::Stderr);
		Some(logger)
	} else {
		None
	};

	let logfile = if datadir.exists() {
		let path = datadir.join("debug.log");
		match std::fs::File::options().create(true).append(true).open(path) {
			Ok(mut file) => {
				// try write a newline into the file to separate commands
				let _ = file.write_all("\n\n".as_bytes());
				let mut logger = base();
				logger
					.filter_level(log::LevelFilter::Trace)
					.format_timestamp_millis()
					.format_module_path(true)
					.format_file(true)
					.format_line_number(true)
					.target(env_logger::Target::Pipe(Box::new(file)));
				Some(logger)
			},
			Err(e) => {
				eprintln!("Failed to open debug.log file: {:#}", e);
				None
			},
		}
	} else {
		None
	};

	match (terminal, logfile) {
		(Some(mut l1), Some(mut l2)) => SplitLogger::init(l1.build(), l2.build()),
		(Some(mut l), None) => l.init(),
		(None, Some(mut l)) => l.init(),
		(None, None) => {},
	}
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let datadir = PathBuf::from_str(&cli.datadir).unwrap();
	debug!("Using bark datadir at {}", datadir.display());

	init_logging(cli.verbose, cli.quiet, &datadir);

	// Handle create command differently.
	if let Command::Create(opts) = cli.command {
		create_wallet(&datadir, opts).await?;
		return Ok(())
	}

	if let Command::Dev(cmd) = cli.command {
		return dev::execute_dev_command(cmd, datadir).await;
	}

	let (mut wallet, mut onchain) = open_wallet(&datadir).await.context("error opening wallet")?;

	let net = wallet.properties()?.network;

	match cli.command {
		Command::Create { .. } | Command::Dev(_) => unreachable!("handled earlier"),
		Command::Config => {
			let config = wallet.config().clone();
			output_json(&bark_json::cli::Config {
				ark: config.server_address,
				bitcoind: config.bitcoind_address,
				bitcoind_cookie: config.bitcoind_cookiefile.map(|c| c.display().to_string()),
				bitcoind_user: config.bitcoind_user,
				bitcoind_pass: config.bitcoind_pass,
				esplora: config.esplora_address,
				vtxo_refresh_expiry_threshold: config.vtxo_refresh_expiry_threshold,
				fallback_fee_rate: config.fallback_fee_rate,
			})
		},
		Command::ArkInfo => {
			if let Some(info) = wallet.ark_info() {
				output_json(&bark_json::cli::ArkInfo::from(info));
			} else {
				warn!("Could not connect with Ark server.")
			}
		},
		Command::Address { index } => {
			if let Some(index) = index {
				println!("{}", wallet.peak_address(index)?)
			} else {
				println!("{}", wallet.new_address()?)
			}
		},
		Command::Balance { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let balance = wallet.balance()?;
			output_json(&json::Balance {
				spendable: balance.spendable,
				pending_in_round: balance.pending_in_round,
				pending_lightning_send: balance.pending_lightning_send,
				pending_lightning_receive: json::LightningReceiveBalance {
					total: balance.pending_lightning_receive.total,
					claimable: balance.pending_lightning_receive.claimable,
				},
				pending_exit: balance.pending_exit,
				pending_board: balance.pending_board,
			});
		},
		Command::Vtxos { all, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let mut vtxos = if all {
				wallet.all_vtxos()?
			} else {
				wallet.vtxos()?
			};

			vtxos.sort_by(|a, b| {
				match (a.state.kind(), b.state.kind()) {
					(VtxoStateKind::Spent, b) if b != VtxoStateKind::Spent => Ordering::Less,
					(VtxoStateKind::Spendable, a) if a != VtxoStateKind::Spendable => Ordering::Greater,
					_ => a.expiry_height().cmp(&b.expiry_height()),
				}
			});

			output_json(&vtxos.iter().map(wallet_vtxo_to_json).collect::<Vec<_>>());
		},
		Command::Movements { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let mut movements = wallet.movements()?.into_iter()
				.map(|mv| movement_to_json(&mv))
				.collect::<Vec<_>>();

			// movements are ordered from newest to oldest, so we reverse them so last terminal item is newest
			movements.reverse();

			output_json(&movements);
		},
		Command::Refresh { vtxos, threshold_blocks, threshold_hours, counterparty, all, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let vtxos = match (threshold_blocks, threshold_hours, counterparty, all, vtxos) {
				(None, None, false, false, None) => wallet.get_expiring_vtxos(wallet.config().vtxo_refresh_expiry_threshold).await?,
				(Some(b), None, false, false, None) => wallet.get_expiring_vtxos(b).await?,
				(None, Some(h), false, false, None) => wallet.get_expiring_vtxos(h*6).await?,
				(None, None, true, false, None) => {
					let filter = VtxoFilter::new(&wallet).counterparty();
					wallet.spendable_vtxos_with(&filter)?
				},
				(None, None, false, true, None) => wallet.spendable_vtxos()?,
				(None, None, false, false, Some(vs)) => {
					let vtxos = vs.iter()
						.map(|s| {
							let id = VtxoId::from_str(s)?;
							Ok(wallet.get_vtxo_by_id(id)?)
						})
						.collect::<anyhow::Result<Vec<_>>>()
						.with_context(|| "Invalid vtxo_id")?;

					vtxos
				}
				_ => bail!("please provide either threshold vtxo, threshold_blocks, threshold_hours, counterparty or all"),
			};

			let vtxos = vtxos.into_iter().map(|v| v.id()).collect::<Vec<_>>();

			info!("Refreshing {} vtxos...", vtxos.len());
			if let Some(res) = wallet.refresh_vtxos(vtxos).await? {
				output_json(&round_status_to_json(&res));
			} else {
				info!("No round happened");
			}
		},
		Command::Board { amount, all, no_sync } => {
			if !no_sync {
				info!("Syncing onchain wallet...");
				if let Err(e) = onchain.sync(&wallet.chain).await {
					warn!("Sync error: {}", e)
				}
			}
			let board = match (amount, all) {
				(Some(a), false) => {
					info!("Boarding {}...", a);
					wallet.board_amount(&mut onchain, a).await?

				},
				(None, true) => {
					info!("Boarding total balance...");
					wallet.board_all(&mut onchain).await?
				},
				_ => bail!("please provide either an amount or --all"),
			};
			output_json(&json::Board::from(board));
		},
		Command::Send { destination, amount, comment, no_sync } => {
			if let Ok(addr) = ark::Address::from_str(&destination) {
				let amount = amount.context("amount missing")?;
				if comment.is_some() {
					bail!("comment not supported for Ark address");
				}

				if !no_sync {
					info!("Syncing wallet...");
					wallet.sync().await;
				}

				info!("Sending arkoor payment of {} to address {}", amount, addr);
				wallet.send_arkoor_payment(&addr, amount).await?;
			} else if let Ok(inv) = Bolt11Invoice::from_str(&destination) {
				lightning::pay_invoice(inv, amount, comment, no_sync, &mut wallet).await?;
			} else if let Ok(offer) = Offer::from_str(&destination) {
				lightning::pay_offer(offer, amount, comment, no_sync, &mut wallet).await?;
			} else if let Ok(addr) = LightningAddress::from_str(&destination) {
				lightning::pay_lnaddr(addr, amount, comment, no_sync, &mut wallet).await?;
			} else {
				bail!("Argument is not a valid destination. Supported are: \
					VTXO pubkeys, bolt11 invoices, bolt12 offers and lightning addresses",
				);
			}
			info!("Payment sent succesfully!");
		},
		Command::SendOnchain { destination, amount, no_sync } => {
			if let Ok(addr) = bitcoin::Address::from_str(&destination) {
				let addr = addr.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;

				if !no_sync {
					info!("Syncing wallet...");
					wallet.sync().await;
				}

				info!("Sending on-chain payment of {} to {} through round...", amount, addr);
				wallet.send_round_onchain_payment(addr, amount).await?;
			} else {
				bail!("Invalid destination");
			}
		},
		Command::Offboard { address, vtxos , all, no_sync } => {
			let address = if let Some(address) = address {
				let address = bitcoin::Address::from_str(&address)?
					.require_network(net)
					.with_context(|| {
						format!("address is not valid for configured network {}", net)
					})?;

				debug!("Sending to on-chain address {}", address);

				address
			} else {
				onchain.address()?
			};

			let ret = if let Some(vtxos) = vtxos {
				let vtxos = vtxos
					.into_iter()
					.map(|vtxo| {
						VtxoId::from_str(&vtxo).with_context(|| format!("invalid vtxoid: {}", vtxo))
					})
					.collect::<anyhow::Result<Vec<_>>>()?;

				if !no_sync {
					info!("Syncing wallet...");
					wallet.sync().await;
				}

				info!("Offboarding {} vtxos...", vtxos.len());
				wallet.offboard_vtxos(vtxos, address).await?
			} else if all {
				if !no_sync {
					info!("Syncing wallet...");
					wallet.sync().await;
				}
				info!("Offboarding all off-chain funds...");
				wallet.offboard_all(address).await?
			} else {
				bail!("Either --vtxos or --all argument must be provided to offboard");
			};
			output_json(&round_status_to_json(&ret));
		},
		Command::Onchain(onchain_command) => {
			onchain::execute_onchain_command(onchain_command, &mut wallet, &mut onchain).await?;
		},
		Command::Exit(cmd) => {
			exit::execute_exit_command(cmd, &mut wallet, &mut onchain).await?;
		},
		Command::Lightning(cmd) => {
			lightning::execute_lightning_command(cmd, &mut wallet).await?;
		},
		Command::Maintain => {
			wallet.maintenance_with_onchain(&mut onchain).await?;
		},
	}
	Ok(())
}

#[tokio::main]
async fn main() {
	let cli = Cli::parse();
	let verbose = cli.verbose;

	if let Err(e) = inner_main(cli).await {
		eprintln!("An error occurred: {}", e);

		// this is taken from anyhow code because it's not exposed
		if let Some(cause) = e.source() {
			eprintln!("Caused by:");
			for error in anyhow::Chain::new(cause) {
				eprintln!("	{}", error);
			}
		}

		if verbose {
			eprintln!();
			eprintln!("Stack backtrace:");
			eprintln!("{}", e.backtrace());
		}
		process::exit(1);
	}
}
