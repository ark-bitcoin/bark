#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;

mod create;
mod util;

use std::{env, io, process};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use ark::VtxoId;
use bitcoin::hex::DisplayHex;
use bitcoin::{address, Address, Amount};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;

use bark::{Wallet, Config};
use bark_json::cli as json;

use crate::create::{CreateOpts, create_wallet};
use crate::util::PrettyDuration;

fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

#[derive(Parser)]
#[command(author = "Steven Roose <steven@roose.io>", version, about)]
struct Cli {
	/// Enable verbose logging
	#[arg(long, short = 'v', global = true)]
	verbose: bool,

	/// Print output as JSON
	///
	/// Note that simple string values will still be output as raw strings
	#[arg(long, short = 'j', global = true)]
	json: bool,

	/// The datadir of the bark wallet
	#[arg(long, global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Args)]
struct ConfigOpts {
	#[arg(long)]
	asp: Option<String>,

	/// The esplora HTTP API endpoint
	#[arg(long)]
	esplora: Option<String>,
	#[arg(long)]
    /// The bitcoind address
	bitcoind: Option<String>,
	#[arg(long)]
	bitcoind_cookie: Option<String>,
	#[arg(long)]
	bitcoind_user: Option<String>,
	#[arg(long)]
	bitcoind_pass: Option<String>,
}

impl ConfigOpts {
	fn merge_info(self, cfg: &mut Config) -> anyhow::Result<()> {
		if let Some(v) = self.asp {
			cfg.asp_address = v;
		}
		if let Some(v) = self.esplora {
			cfg.esplora_address = if v == "" { None } else { Some(v) };
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
	Create (CreateOpts),

	/// Change the configuration of your bark wallet
	#[command()]
	Config {
		#[command(flatten)]
		config: Option<ConfigOpts>,
		#[arg(long, default_value_t = false)]
		dangerous: bool,
	},

	/// Use the built-in onchain wallet
	#[command(subcommand)]
	Onchain(OnchainCommand),

	/// The public key used to receive VTXOs
	#[command()]
	VtxoPubkey,

    /// Get the wallet balance
	#[command()]
	Balance,

	/// List the wallet's VTXOs
	#[command()]
	Vtxos,

	/// Refresh expiring VTXOs
	///
	/// By default the wallet's configured threshold is used
	#[command()]
	Refresh {
		/// Refresh VTXOs that expire within this amount of blocks
		#[arg(long)]
		threshold_blocks: Option<u32>,
		/// Refresh VTXOs that expire within this number of hours
		#[arg(long)]
		threshold_hours: Option<u32>,
		/// Force refresh all VTXOs regardless of expiry height
		#[arg(long)]
		all: bool,
	},

	/// Onboard from the onchain wallet into the Ark
	#[command()]
	Onboard {
		// Optional amount of on-chain funds to onboard. Either this or --all should be provided
		amount: Option<Amount>,
		// Whether or not all funds in on-chain wallet should be onboarded
		#[arg(long)]
		all: bool,
	},

	/// Send money using an Ark (out-of-round) transaction
	#[command()]
	Send {
		/// The destination
		destination: String,
		/// The amount to send (optional for bolt11)
		amount: Option<Amount>,
		/// An optional comment
		comment: Option<String>,
	},

	/// Send money from your vtxo's to an onchain address
	/// This method requires to wait for a round
	#[command()]
	SendOnchain {
		/// Destination for the payment, this can either be an on-chain address
		/// or an Ark VTXO public key
		destination: String,
		amount: Amount,
	},

	/// Turn VTXOs into UTXOs
	/// This command sends 
	#[command()]
	Offboard {
		/// Optional address to receive offboarded VTXOs. If no address is provided, it will be taken from onchain wallet
		#[arg(long)]
		address: Option<String>,
		/// Optional selection of VTXOs to offboard. Either this or --all should be provided
		#[arg(long)]
		vtxos: Option<Vec<String>>,
		/// Whether or not all VTXOs should be offboarded. Either this or --vtxos should be provided
		#[arg(long)]
		all: bool,
	},

	/// Perform a unilateral exit from the Ark
	#[command()]
	Exit {
		/// If set, only try to make progress on pending exits and don't
		/// initiate exits on VTXOs in wallet
		#[arg(long)]
		only_progress: bool,

		/// Keep running until the entire exit is finished. This can take several hours
		#[arg(long)]
		wait: bool,

		//TODO(stevenroose) add a option to claim claimable exits while others are not claimable
		//yet
	},

	/// Dev command to drop the vtxo database
	#[command(hide = true)]
	DropVtxos,
}

#[derive(clap::Subcommand)]
enum OnchainCommand {
	/// Get the on-chain balance
	#[command()]
	Balance,

	/// Get an on-chain address
	#[command()]
	Address,

	/// Send using the on-chain wallet
	#[command()]
	Send {
		destination: Address<address::NetworkUnchecked>,
		amount: Amount,
	},

	/// List our wallet's UTXOs
	#[command()]
	Utxos,
}

fn init_logging(verbose: bool) {
	let colors = fern::colors::ColoredLevelConfig::default();

	let mut l = fern::Dispatch::new()
		.level_for("rusqlite", log::LevelFilter::Warn)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("reqwest", log::LevelFilter::Warn);
	if verbose {
		l = l
			.level(log::LevelFilter::Trace)
			.level_for("bitcoincore_rpc", log::LevelFilter::Trace);
	} else {
		l = l
			.level(log::LevelFilter::Info)
			.level_for("bitcoincore_rpc", log::LevelFilter::Warn);
	}
	l
		.format(move |out, msg, rec| {
			let now = chrono::Local::now();
			// only time, not date
			let stamp = now.format("%H:%M:%S.%3f");
			if verbose {
				let module = rec.module_path().expect("no module");
				if module.starts_with("bark::") {
					let file = rec.file().expect("our macro provides file");
					let file = file.strip_prefix("bark/").unwrap_or(file);
					let line = rec.line().expect("our macro provides line");
					out.finish(format_args!("[{stamp} {: >5} {module} {file}:{line}] {}",
						colors.color(rec.level()), msg,
					))
				} else {
					out.finish(format_args!("[{stamp} {: >5} {module}] {}",
						colors.color(rec.level()), msg,
					))
				}
			} else {
				out.finish(format_args!("[{stamp} {: >5}] {}", colors.color(rec.level()), msg))
			}
		})
		.chain(std::io::stderr())
		.apply().expect("error setting up logging");
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	init_logging(cli.verbose);

	let datadir =PathBuf::from_str(&cli.datadir).unwrap();

	// Handle create command differently.
	if let Command::Create ( create_opts ) = cli.command {
		create_wallet(&datadir, create_opts).await?;
		return Ok(())
	}

	let mut w = Wallet::open(&datadir).await.context("error opening wallet")?;
	if let Err(e) = w.require_chainsource_version() {
		warn!("{}", e);
	}

	let net = w.config().network;

	match cli.command {
		Command::Create { .. } => unreachable!(),
		Command::Config { config, dangerous } => {
			if let Some(new_cfg) = config {
				let mut cfg = w.config().clone();
				if !dangerous {
					if new_cfg.asp.is_some() {
						bail!("Changing the ASP address can lead to loss of funds. \
							If you insist, use the --dangerous flag.");
					}
				}
				new_cfg.merge_info(&mut cfg).context("invalid configuration")?;
				w.set_config(cfg);
				w.persist_config().context("failed to persist config")?;
			}
			println!("{:#?}", w.config());
		},
		Command::Onchain(cmd) => match cmd {
			OnchainCommand::Balance => {
				w.sync_onchain().await.context("sync error")?;
				let res = w.onchain_balance();
				if cli.json {
					println!("{}", res.to_sat());
				} else {
					println!("{}", res);
				}
			},
			OnchainCommand::Address => println!("{}", w.get_new_onchain_address()?),
			OnchainCommand::Send { destination: address, amount } => {
				let addr = address.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;
				w.sync_onchain().await.context("sync error")?;
				w.send_onchain(addr, amount).await?;
			},
			OnchainCommand::Utxos => {
				w.sync_onchain().await.context("sync error")?;
				for op in w.onchain_utxos() {
					println!("{op}");
				}
			},
		},
		Command::VtxoPubkey => println!("{}", w.vtxo_pubkey()),
		Command::Balance => {
			if let Err(e) = w.sync().await.context("sync error") {
				warn!("Failed to sync balance. {}", e)
			}

			let onchain = w.onchain_balance();
			let offchain =  w.offchain_balance().await?;
			let pending_exit = {
				let exit = w.get_exit()?.unwrap_or_default();
				exit.total_pending_amount()
			};
			if cli.json {
				serde_json::to_writer(io::stdout(), &json::Balance {
					onchain, offchain, pending_exit,
				}).unwrap();
			} else {
				info!("Onchain balance: {}", onchain);
				info!("Offchain balance: {}", offchain);
				if pending_exit > Amount::ZERO {
					info!("An exit process is pending for {}", pending_exit);
				}
			}
		},
		Command::Vtxos => {
			if let Err(e) = w.sync_ark().await.context("sync error") {
				warn!("Failed to sync with ASP. Some inbound VTXOs might not be shown. {}", e)
			}

			let res = w.vtxos()?;
			if cli.json {
				let json = res.into_iter().map(|v| v.into()).collect::<Vec<json::VtxoInfo>>();
				serde_json::to_writer(io::stdout(), &json).unwrap();
			} else {
				info!("Our wallet has {} VTXO(s):", res.len());
				let tip = w.chain_tip_height().await.context("bitcoin chain source error")?;
				for v in res {
					let expiry = v.spec().expiry_height;
					if let Some(diff) = expiry.checked_sub(tip) {
						let time_left = Duration::from_secs(60 * 10 * diff as u64);
						info!("  {} ({}): {}; expires at height {} (in about {})",
							v.id(), v.vtxo_type(), v.amount(), expiry, PrettyDuration(time_left),
						);
					} else {
						info!("  {} ({}): {}; already expired", v.id(), v.vtxo_type(), v.amount());
					}
				}
			}
		},
		Command::Refresh { threshold_blocks, threshold_hours, all } => {
			let threshold = match (threshold_blocks, threshold_hours, all) {
				(None, None, false) => Some(w.config().vtxo_refresh_threshold),
				(Some(b), None, false) => Some(b),
				(None, Some(h), false) => Some(h * 6),
				(None, None, true) => None,
				_ => bail!("please provide either threshold blocks, hour or all"),
			};

			if let Some(th) = threshold {
				info!("Refreshing VTXOs expiring within the next {} blocks...", th);
			} else {
				info!("Refreshing all VTXOs...");
			}
			w.sync_ark().await.context("sync error")?;
			w.refresh_vtxos(threshold).await?;
		},
		Command::Onboard { amount, all } => {
			w.sync_onchain().await.context("sync error")?;
			match (amount, all) {
				(Some(a), false) => w.onboard_amount(a).await?,
				(None, true) => w.onboard_all().await?,
				_ => bail!("please provide either an amount or --all"),
			}
		}
		Command::Send { destination, amount, comment } => {
			if let Ok(pk) = PublicKey::from_str(&destination) {
				let amount = amount.context("amount missing")?;
				if comment.is_some() {
					bail!("comment not supported for VTXO pubkey");
				}

				info!("Sending arkoor payment of {} to pubkey {}", amount, pk);
				w.sync_ark().await.context("sync error")?;
				w.send_oor_payment(pk, amount).await?;
			} else if let Ok(inv) = Bolt11Invoice::from_str(&destination) {
				let inv_amount = inv.amount_milli_satoshis()
					.map(|v| Amount::from_sat(v.div_ceil(1000)));
				if let (Some(_), Some(inv)) = (amount, inv_amount) {
					bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
				}
				let final_amount = amount.or(inv_amount)
					.context("amount required on invoice without amount")?;
				if comment.is_some() {
					bail!("comment not supported for bolt11 invoice");
				}

				info!("Sending bolt11 payment to invoice {}", inv);
				w.sync_ark().await.context("sync error")?;
				info!("Sending bolt11 payment of {} to invoice {}", final_amount, inv);
				let preimage = w.send_bolt11_payment(&inv, amount).await?;
				info!("Payment preimage received: {}", preimage.as_hex());
			} else if let Ok(addr) = LightningAddress::from_str(&destination) {
				let amount = amount.context("amount missing")?;

				info!("Sending {} to lightning address {}", amount, addr);
				w.sync_ark().await.context("sync error")?;
				let comment = comment.as_ref().map(|c| c.as_str());
				let (inv, preimage) = w.send_lnaddr(&addr, amount, comment).await?;
				info!("Paid invoice {}", inv);
				info!("Payment preimage received: {}", preimage.as_hex());
			} else {
				bail!("Argument is not a valid destination. Supported are: \
					VTXO pubkeys, bolt11 invoices, lightning addresses",
				);
			}
			info!("Success");
		},
		Command::SendOnchain { destination, amount } => {
			if let Ok(addr) = Address::from_str(&destination) {
				let addr = addr.require_network(net).with_context(|| {
					format!("address is not valid for configured network {}", net)
				})?;
				debug!("Sending to on-chain address {}", addr);
				w.sync_ark().await.context("sync error")?;
				w.send_round_onchain_payment(addr, amount).await?;
			} else {
				bail!("Invalid destination");
			}
		},
		Command::Offboard { address, vtxos , all} => {
			let address = address
			.map(|address| {
				let address = Address::from_str(&address)?
					.require_network(net)
					.with_context(|| {
						format!("address is not valid for configured network {}", net)
					})?;

				debug!("Sending to on-chain address {}", address);

				Ok::<Address, anyhow::Error>(address)
			})
			.transpose()?;

			if let Some(vtxos) = vtxos {
				let vtxos = vtxos
					.into_iter()
					.map(|vtxo| {
						VtxoId::from_str(&vtxo).with_context(|| format!("invalid vtxoid: {}", vtxo))
					})
					.collect::<anyhow::Result<_>>()?;

				w.offboard_vtxos(vtxos, address).await?;
			} else if all {
				w.offboard_all(address).await?;
			} else {
				bail!("Either --vtxos or --all argument must be provided to offboard");
			}
		},
		Command::Exit { only_progress, wait } => {
			if !only_progress {
				w.start_exit_for_entire_wallet().await
					.context("error starting exit process for existing vtxos")?;
			}

			let mut wallet = Some(w);
			loop {
				if let Err(e) = wallet.as_mut().unwrap().sync_onchain().await {
					warn!("Failed to perform on-chain sync before progressing exit: {}", e);
				}

				let res = wallet.as_mut().unwrap().progress_exit().await
					.context("error making progress on exit process")?;
				if cli.json {
					let ret = match res {
						bark::ExitStatus::Done => {
							json::ExitStatus { done: true, height: None }
						},
						bark::ExitStatus::NeedMoreTxs => {
							json::ExitStatus { done: false, height: None }
						},
						bark::ExitStatus::WaitingForHeight(h) => {
							json::ExitStatus { done: false, height: Some(h) }
						},
					};
					serde_json::to_writer(io::stdout(), &ret).unwrap();
				} else {
					match res {
						bark::ExitStatus::Done => {
							info!("Exit succesful!");
						}
						bark::ExitStatus::NeedMoreTxs => {
							if wait {
								info!("More transactions need to be confirmed.");
							} else {
								info!("More transactions need to be confirmed, \
									keep calling this command.");
							}
						},
						bark::ExitStatus::WaitingForHeight(h)=> {
							if wait {
								info!("All transactions are confirmed, \
									waiting for block height {}.", h);
							} else {
								info!("All transactions are confirmed, call command again \
									to claim them all at block height {}.", h);
							}
						}
					}
				}

				if !wait || res == bark::ExitStatus::Done {
					break;
				}

				info!("Sleeping for a minute, then will continue...");

				drop(wallet.take());
				tokio::time::sleep(Duration::from_secs(60)).await;
				'w: loop {
					match Wallet::open(&datadir).await {
						Ok(w) => {
							wallet = Some(w);
							break 'w;
						},
						Err(e) => {
							debug!("Error re-opening wallet, waiting a little... ({})", e);
							tokio::time::sleep(Duration::from_secs(2)).await;
						},
					}
				}
			}
		},

		// dev commands

		Command::DropVtxos => {
			w.drop_vtxos().await?;
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
		eprintln!();

		if verbose {
			eprintln!();
			eprintln!("Stack backtrace:");
			eprintln!("{}", e.backtrace());
		}
		process::exit(1);
	}
}
