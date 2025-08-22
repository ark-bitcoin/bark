#[macro_use] extern crate anyhow;

mod exit;
mod lightning;
mod util;
mod wallet;

use std::{env, process};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bark::movement::Movement;
use bitcoin::{address, Amount, FeeRate};
use clap::Parser;
use ::lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use log::{debug, info, warn};

use ark::{Vtxo, VtxoId};
use bark::{Config, Pagination, UtxoInfo};
use bark::vtxo_selection::VtxoFilter;
use bark_json::{cli as json, primitives};
use bitcoin_ext::FeeRateExt;

use crate::util::output_json;
use crate::wallet::{CreateOpts, create_wallet, open_wallet};

const DEFAULT_PAGE_SIZE: u16 = 10;
const DEFAULT_PAGE_INDEX: u16 = 0;

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

#[derive(Parser)]
#[command(name = "bark", author = "Team Second <hello@second.tech>", version = FULL_VERSION, about)]
struct Cli {
	/// Enable verbose logging
	#[arg(long, short = 'v', global = true)]
	verbose: bool,
	/// Disable all terminal logging
	#[arg(long, short = 'q', global = true)]
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

	/// Use the built-in onchain wallet
	#[command(subcommand)]
	Onchain(OnchainCommand),

	/// Change the configuration of your bark wallet
	#[command()]
	Config {
		#[command(flatten)]
		config: Option<ConfigOpts>,
		#[arg(long, default_value_t = false)]
		dangerous: bool,
	},

	/// Prints informations related to the Ark Server
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
	},

	/// List the wallet's payments
	///
	/// By default will fetch the 10 first items
	#[command()]
	Movements {
		/// Page index to return, default to 0
		#[arg(long)]
		page_index: Option<u16>,
		/// Page size to return, default to 10
		#[arg(long)]
		page_size: Option<u16>,

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

	/// Perform a unilateral exit from the Ark
	#[command(subcommand)]
	Exit(exit::ExitCommand),

	/// Perform any lightning-related command
	#[command(subcommand)]
	Lightning(lightning::LightningCommand),


	/// Dev command to drop the vtxo database
	#[command(hide = true)]
	DropVtxos,
}

#[derive(clap::Subcommand)]
enum OnchainCommand {
	/// Get the on-chain balance
	#[command()]
	Balance {
		/// Skip syncing before computing balance
		#[arg(long)]
		no_sync: bool,
	},

	/// Get an on-chain address
	#[command()]
	Address,

	/// Send using the on-chain wallet
	#[command()]
	Send {
		destination: bitcoin::Address<address::NetworkUnchecked>,
		/// Amount to send
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any
		/// amount denomination. Example: `250000 sats`.
		amount: Amount,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	#[command(
		about = "\
			Send using the on-chain wallet to multiple destinations. \n\
			Example usage: send-many --destination bc1pfq...:10000sat --destination bc1pke...:20000sat\n\
			This will send 10,000 sats to bc1pfq... and 20,000 sats to bc1pke...",
	)]
	SendMany {
		/// Adds an output to the given address, this can be specified multiple times.
		/// The format is address:amount, e.g. bc1pfq...:10000sat
		#[arg(long = "destination", required = true)]
		destinations: Vec<String>,

		/// Sends the transaction immediately instead of printing the summary before continuing
		#[arg(long)]
		immediate: bool,

		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Send all wallet funds to provided destination
	#[command()]
	Drain {
		destination: bitcoin::Address<address::NetworkUnchecked>,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// List our wallet's UTXOs
	#[command()]
	Utxos {
		/// Skip syncing before fetching UTXOs
		#[arg(long)]
		no_sync: bool,
	},
}

fn init_logging(verbose: bool, quiet: bool, datadir: &Path) -> anyhow::Result<()> {
	if verbose && quiet {
		bail!("Can't set both --verbose and --quiet");
	}

	let colors = fern::colors::ColoredLevelConfig::default();

	let dispatch = fern::Dispatch::new()
		.level_for("rusqlite", log::LevelFilter::Warn)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("reqwest", log::LevelFilter::Warn)
		.format(move |out, msg, rec| {
			let now = chrono::Local::now();
			let stamp = now.format("%Y-%m-%d %H:%M:%S.%3f");
			let lvl = colors.color(rec.level());
			if verbose {
				let module = rec.module_path().expect("no module");
				if module.starts_with("bark") {
					let file = rec.file().expect("our macro provides file");
					let file = file.split("bark/src/").last().unwrap();
					let line = rec.line().expect("our macro provides line");
					out.finish(format_args!(
						"[{stamp} {lvl: >5} {module} {file}:{line}] {msg}",
					))
				} else {
					out.finish(format_args!(
						"[{stamp} {lvl: >5} {module}] {msg}",
					))
				}
			} else {
				out.finish(format_args!(
					"[{stamp} {lvl: >5}] {msg}",
				))
			}
		});

	// one dispatch for the debug.log file
	let logfile = if datadir.exists() {
		if let Ok(mut file) = fern::log_file(datadir.join("debug.log")) {
			// try write a newline into the file to separate commands
			let _ = file.write_all("\n\n".as_bytes());
			fern::Dispatch::new()
				.level(log::LevelFilter::Trace)
				.level_for("bitcoincore_rpc", log::LevelFilter::Trace)
				.level_for("bitcoin_ext", log::LevelFilter::Trace)
				.chain(file)
		} else {
			fern::Dispatch::new()
		}
	} else {
		fern::Dispatch::new()
	};

	// then also one for terminal output
	let terminal = if verbose {
		fern::Dispatch::new()
			.level(log::LevelFilter::Trace)
			.level_for("bitcoincore_rpc", log::LevelFilter::Trace)
			.level_for("bitcoin_ext", log::LevelFilter::Trace)
	} else if quiet {
		fern::Dispatch::new()
	} else {
		fern::Dispatch::new()
			.level(log::LevelFilter::Info)
			.level_for("bitcoincore_rpc", log::LevelFilter::Warn)
	}.chain(std::io::stderr());

	dispatch.chain(logfile).chain(terminal).apply()
		.context("error applying logging configuration")?;
	Ok(())
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let datadir = PathBuf::from_str(&cli.datadir).unwrap();
	debug!("Using bark datadir at {}", datadir.display());

	if let Err(e) = init_logging(cli.verbose, cli.quiet, &datadir) {
		eprintln!("Error setting up logging: {}", e);
		process::exit(1);
	}

	// Handle create command differently.
	if let Command::Create ( create_opts ) = cli.command {
		create_wallet(&datadir, create_opts).await?;
		return Ok(())
	}

	let (mut wallet, mut onchain) = open_wallet(&datadir).await.context("error opening wallet")?;
	if let Err(e) = wallet.require_chainsource_version() {
		warn!("{}", e);
	}

	let net = wallet.properties()?.network;

	match cli.command {
		Command::Create { .. } => unreachable!(),
		Command::Config { config, dangerous } => {
			if let Some(new_cfg) = config {
				let mut cfg = wallet.config().clone();
				if !dangerous {
					if new_cfg.ark.is_some() {
						bail!("Changing the Ark server address can lead to loss of funds. \
							If you insist, use the --dangerous flag.");
					}
				}
				new_cfg.merge_into(&mut cfg).context("invalid configuration")?;
				wallet.set_config(cfg);
				wallet.persist_config().context("failed to persist config")?;
			}
			let config = wallet.config().clone();
			output_json(&bark_json::cli::Config {
				ark: config.server_address,
				bitcoind: config.bitcoind_address,
				bitcoind_cookie: config.bitcoind_cookiefile.map(|p| p.display().to_string()),
				bitcoind_user: config.bitcoind_user,
				bitcoind_pass: config.bitcoind_pass,
				esplora: config.esplora_address,
				vtxo_refresh_expiry_threshold: config.vtxo_refresh_expiry_threshold,
				fallback_fee_rate: config.fallback_fee_rate,
			})
		},
		Command::ArkInfo => {
			if let Some(info) = wallet.ark_info() {
				output_json(&bark_json::cli::ArkInfo {
					server_pubkey: info.server_pubkey.to_string(),
					round_interval: info.round_interval,
					nb_round_nonces: info.nb_round_nonces,
					vtxo_expiry_delta: info.vtxo_expiry_delta,
					vtxo_exit_delta: info.vtxo_exit_delta,
					max_vtxo_amount: info.max_vtxo_amount,
					max_arkoor_depth: info.max_arkoor_depth,
				});
			} else {
				warn!("Could not connect with Ark server.")
			}
		},
		Command::Onchain(cmd) => match cmd {
			OnchainCommand::Balance { no_sync } => {
				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = onchain.sync(&wallet.chain).await {
						warn!("Onchain sync error: {}", e)
					}
				}

				let balance = onchain.balance();
				let onchain_balance  = json::onchain::Balance {
					total: balance.total(),
					trusted_spendable: balance.trusted_spendable(),
					immature: balance.immature,
					trusted_pending: balance.trusted_pending,
					untrusted_pending: balance.untrusted_pending,
					confirmed: balance.confirmed,
				};
				output_json(&onchain_balance);
			},
			OnchainCommand::Address => {
				let address = onchain.address().expect("Wallet failed to generate address");
				let output = json::onchain::Address { address: address.into_unchecked() };
				output_json(&output);
			},
			OnchainCommand::Send { destination: address, amount, no_sync } => {
				let addr = address.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;

				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = onchain.sync(&wallet.chain).await {
						warn!("Sync error: {}", e)
					}
				}

				let fee_rate = wallet.chain.fee_rates().await.regular;
				let txid = onchain.send(&wallet.chain, addr, amount, fee_rate).await?;

				let output = json::onchain::Send { txid };
				output_json(&output);
			},
			OnchainCommand::Drain { destination: address, no_sync } => {
				let addr = address.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;

				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = onchain.sync(&wallet.chain).await {
						warn!("Sync error: {}", e)
					}
				}

				let fee_rate = wallet.chain.fee_rates().await.regular;
				let txid = onchain.drain(&wallet.chain, addr, fee_rate).await?;

				let output = json::onchain::Send { txid };
				output_json(&output);
			},
			OnchainCommand::SendMany { destinations, immediate, no_sync } => {
				let outputs = destinations
					.iter()
					.map(|dest| -> anyhow::Result<(bitcoin::Address, Amount)> {
						let mut parts = dest.splitn(2, ':');
						let addr = {
							let s = parts.next()
								.context("invalid destination format, expected address:amount")?;
							bitcoin::Address::from_str(s)?.require_network(net)
								.with_context(|| format!("invalid address: '{}'", s))?
						};
						let amount = {
							let s = parts.next()
								.context("invalid destination format, expected address:amount")?;
							Amount::from_str(s)
								.with_context(|| format!("invalid amount: '{}'", s))?
						};
						Ok((addr, amount))
					})
					.collect::<Result<Vec<_>, _>>()?;

				info!("Attempting to send the following:");
				for (address, amount) in &outputs {
					info!("{} to {}", amount, address);
				}

				if !immediate {
					info!("Will continue after 10 seconds...");
					tokio::time::sleep(Duration::from_secs(10)).await;
				}

				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = onchain.sync(&wallet.chain).await {
						warn!("Sync error: {}", e)
					}
				}

				let fee_rate = wallet.chain.fee_rates().await.regular;
				let txid = onchain.send_many(&wallet.chain, outputs, fee_rate).await?;

				let output = json::onchain::Send { txid };
				output_json(&output);
			},
			OnchainCommand::Utxos { no_sync } => {
				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = onchain.sync(&wallet.chain).await {
						warn!("Sync error: {}", e)
					}
				}

				let utxos = onchain.utxos()
					.into_iter()
					.map(UtxoInfo::from)
					.collect::<json::onchain::Utxos>();

				output_json(&utxos);
			},
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
				if let Err(e) = wallet.maintenance(&mut onchain).await {
					warn!("Sync error: {}", e)
				}
			}

			let balance = wallet.balance()?;
			output_json(&json::Balance {
				spendable: balance.spendable,
				pending_in_round: balance.pending_in_round,
				pending_lightning_send: balance.pending_lightning_send,
				pending_exit: balance.pending_exit,
			});
		},
		Command::Vtxos { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = wallet.maintenance(&mut onchain).await {
					warn!("Sync error: {}", e)
				}
			}

			let res = wallet.vtxos()?;
			let vtxos : json::Vtxos = res.into_iter().map(|v| v.into()).collect();
			output_json(&vtxos);
		},
		Command::Movements { page_index, page_size, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = wallet.sync().await {
					warn!("Sync error: {}", e)
				}
			}

			let pagination = Pagination {
				page_index: page_index.unwrap_or(DEFAULT_PAGE_INDEX),
				page_size: page_size.unwrap_or(DEFAULT_PAGE_SIZE),
			};

			let movements = wallet.movements(pagination)?.into_iter()
				.map(|mv| movement_to_json(&mv))
				.collect::<Vec<_>>();

			output_json(&movements);
		},
		Command::Refresh { vtxos, threshold_blocks, threshold_hours, counterparty, all, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = wallet.maintenance(&mut onchain).await {
					warn!("Sync error: {}", e)
				}
			}

			let vtxos = match (threshold_blocks, threshold_hours, counterparty, all, vtxos) {
				(None, None, false, false, None) => wallet.get_expiring_vtxos(wallet.config().vtxo_refresh_expiry_threshold).await?,
				(Some(b), None, false, false, None) => wallet.get_expiring_vtxos(b).await?,
				(None, Some(h), false, false, None) => wallet.get_expiring_vtxos(h*6).await?,
				(None, None, true, false, None) => {
					let filter = VtxoFilter::new(&wallet).counterparty();
					wallet.vtxos_with(&filter)?
				},
				(None, None, false, true, None) => wallet.vtxos()?,
				(None, None, false, false, Some(vs)) => {
					let vtxos = vs.iter()
						.map(|s| {
							let id = VtxoId::from_str(s)?;
							Ok(wallet.get_vtxo_by_id(id)?.vtxo)
						})
						.collect::<anyhow::Result<Vec<Vtxo>>>()
						.with_context(|| "Invalid vtxo_id")?;

					vtxos
				}
				_ => bail!("please provide either threshold vtxo, threshold_blocks, threshold_hours, counterparty or all"),
			};

			info!("Refreshing {} vtxos...", vtxos.len());
			let round_id = wallet.refresh_vtxos(vtxos).await?;
			let refresh_output = json::Refresh {
				participate_round: round_id.is_some(),
				round: round_id,
			};
			output_json(&refresh_output);
		},
		Command::Board { amount, all, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
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
			output_json(&board);
		},
		Command::Send { destination, amount, comment, no_sync } => {
			if let Ok(addr) = ark::Address::from_str(&destination) {
				let amount = amount.context("amount missing")?;
				if comment.is_some() {
					bail!("comment not supported for Ark address");
				}

				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = wallet.maintenance(&mut onchain).await {
						warn!("Sync error: {}", e)
					}
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
					if let Err(e) = wallet.maintenance(&mut onchain).await {
						warn!("Sync error: {}", e)
					}
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
					if let Err(e) = wallet.maintenance(&mut onchain).await {
						warn!("Sync error: {}", e)
					}
				}

				info!("Offboarding {} vtxos...", vtxos.len());
				wallet.offboard_vtxos(vtxos, address).await?
			} else if all {
				if !no_sync {
					info!("Syncing wallet...");
					if let Err(e) = wallet.sync().await {
						warn!("Sync error: {}", e)
					}
				}
				info!("Offboarding all off-chain funds...");
				wallet.offboard_all(address).await?
			} else {
				bail!("Either --vtxos or --all argument must be provided to offboard");
			};
			output_json(&ret);
		},
		Command::Exit(cmd) => {
			exit::execute_exit_command(cmd, &mut wallet, &mut onchain).await?;
		},
		Command::Lightning(cmd) => {
			lightning::execute_lightning_command(cmd, &mut wallet).await?;
		}
		// dev commands
		Command::DropVtxos => {
			wallet.drop_vtxos().await?;
			info!("Dropped all vtxos");
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
