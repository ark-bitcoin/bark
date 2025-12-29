#[macro_use] extern crate anyhow;

mod dev;
mod exit;
mod lightning;
mod onchain;
mod round;
mod util;
mod wallet;

use std::cmp::Ordering;
use std::{env, process};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, Network};
use clap::builder::BoolishValueParser;
use clap::Parser;
use ::lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use log::{debug, info, warn};

use ark::VtxoId;
use bark::{BarkNetwork, Config};
use bark::onchain::ChainSync;
use bark::vtxo::selection::VtxoFilter;
use bark::vtxo::state::VtxoStateKind;
use bark_json::{cli as json};
use bark_json::primitives::WalletVtxoInfo;

use bark_cli::wallet::open_wallet;
use bark_cli::log::init_logging;

use crate::util::output_json;
use crate::wallet::{CreateOpts, create_wallet};


const DEBUG_LOG_FILE: &str = "debug.log";


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

/// Options to define the initial bark config
#[derive(Clone, PartialEq, Eq, Default, clap::Args)]
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
}

impl ConfigOpts {
	/// Fill the default required config fields based on network
	fn fill_network_defaults(&mut self, net: BarkNetwork) {
		// Fallback to our default signet backend
		// Only do it when the user did *not* specify either --esplora or --bitcoind.
		if net == BarkNetwork::Signet && self.esplora.is_none() && self.bitcoind.is_none() {
			self.esplora = Some("https://esplora.signet.2nd.dev/".to_owned());
		}

		// Fallback to Mutinynet community Esplora
		// Only do it when the user did *not* specify either --esplora or --bitcoind.
		if net == BarkNetwork::Mutinynet && self.esplora.is_none() && self.bitcoind.is_none() {
			self.esplora = Some("https://mutinynet.com/api".to_owned());
		}
	}

	/// Validate the config options are sane
	fn validate(&self) -> anyhow::Result<()> {
		if self.esplora.is_none() && self.bitcoind.is_none() {
			bail!("You need to provide a chain source using either --esplora or --bitcoind");
		}

		match (
			self.bitcoind.is_some(),
			self.bitcoind_cookie.is_some(),
			self.bitcoind_user.is_some(),
			self.bitcoind_pass.is_some(),
		) {
			(false, false, false, false) => {},
			(false, _, _, _) => bail!("Provided bitcoind auth args without bitcoind address"),
			(_, true, false, false) => {},
			(_, true, _, _) => bail!("Bitcoind user/pass shouldn't be provided together with cookie file"),
			(_, _, true, true) => {},
			_ => bail!("When providing --bitcoind, you need to provide auth args as well."),
		}

		Ok(())
	}

	/// Will write the provided config options to the config
	///
	/// Will also load and return the config when loaded from the written file.
	fn write_to_file(&self, network: Network, path: impl AsRef<Path>) -> anyhow::Result<Config> {
		use std::fmt::Write;

		let mut conf = String::new();
		let ark = util::default_scheme("https", self.ark.as_ref().context("missing --ark arg")?)
			.context("invalid ark server URL")?;
		writeln!(conf, "server_address = \"{}\"", ark).unwrap();

		if let Some(ref v) = self.esplora {
			let url = util::default_scheme("https", v).context("invalid esplora URL")?;
			writeln!(conf, "esplora_address = \"{}\"", url).unwrap();
		}
		if let Some(ref v) = self.bitcoind {
			let url = util::default_scheme("http", v).context("invalid bitcoind URL")?;
			writeln!(conf, "bitcoind_address = \"{}\"", url).unwrap();
		}
		if let Some(ref v) = self.bitcoind_cookie {
			writeln!(conf, "bitcoind_cookiefile = \"{}\"", v).unwrap();
		}
		if let Some(ref v) = self.bitcoind_user {
			writeln!(conf, "bitcoind_user = \"{}\"", v).unwrap();
		}
		if let Some(ref v) = self.bitcoind_pass {
			writeln!(conf, "bitcoind_pass = \"{}\"", v).unwrap();
		}

		let path = path.as_ref();
		std::fs::write(path, conf).with_context(|| format!(
			"error writing new config file to {}", path.display(),
		))?;

		// new let's try load it to make sure it's sane
		Ok(Config::load(network, path).context("problematic config flags provided")?)
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
	#[command(alias="movements")]
	History {
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

	/// round-related commands
	#[command(subcommand)]
	Round(round::RoundCommand),

	/// Run wallet maintenence
	///
	/// This includes onchain sync, offchain sync, registering boards with the server,
	/// syncing Lightning VTXOs, syncing exits, and refreshing soon-to-expire VTXOs
	#[command()]
	Maintain,

	/// developer commands
	#[command(subcommand)]
	Dev(dev::DevCommand),
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
			if let Some(info) = wallet.ark_info().await? {
				output_json(&bark_json::cli::ArkInfo::from(info));
			} else {
				warn!("Could not connect with Ark server.")
			}
		},
		Command::Address { index } => {
			if let Some(index) = index {
				println!("{}", wallet.peak_address(index).await?)
			} else {
				println!("{}", wallet.new_address().await?)
			}
		},
		Command::Balance { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let balance = wallet.balance()?;
			output_json(&json::Balance::from(balance));
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

			output_json(&vtxos.into_iter().map(WalletVtxoInfo::from).collect::<Vec<_>>());
		},
		Command::History { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let mut movements = wallet.history()?.into_iter()
				.map(json::Movement::try_from)
				.collect::<Result<Vec<_>, _>>()?;

			// Movements are ordered from newest to oldest, so we reverse them to ensure the last
			// item in the terminal is the newest.
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
				output_json(&json::RoundStatus::from(res));
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
			output_json(&json::PendingBoardInfo::from(board));
		},
		Command::Send { destination, amount, comment, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			if let Ok(addr) = ark::Address::from_str(&destination) {
				let amount = amount.context("amount missing")?;
				if comment.is_some() {
					bail!("comment not supported for Ark address");
				}

				info!("Sending arkoor payment of {} to address {}", amount, addr);
				wallet.send_arkoor_payment(&addr, amount).await?;
			} else if let Ok(inv) = Bolt11Invoice::from_str(&destination) {
				if comment.is_some() {
					bail!("comment is not supported for BOLT-11 invoices");
				}
				wallet.pay_lightning_invoice(inv, amount).await?;
			} else if let Ok(offer) = Offer::from_str(&destination) {
				if comment.is_some() {
					bail!("comment is not supported for BOLT-12 offers");
				}
				wallet.pay_lightning_offer(offer, amount).await?;
			} else if let Ok(addr) = LightningAddress::from_str(&destination) {
				let amount = amount.context("amount is required for Lightning addresses")?;
				wallet.pay_lightning_address(&addr, amount, comment).await?;
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
			output_json(&json::RoundStatus::from(ret));
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
		Command::Round(cmd) => {
			round::execute_round_command(cmd, &mut wallet).await?;
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
