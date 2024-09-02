
#[macro_use] extern crate anyhow;
#[macro_use] extern crate log;

use std::{env, fs, io, process};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{address, Address, Amount};
use bitcoin::secp256k1::PublicKey;
use clap::Parser;

use bark::{Wallet, Config};
use bark_json::cli as json;

const SIGNET_ASP_CERT: &'static [u8] = include_bytes!("signet.asp.21m.dev.cert.pem");

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
	/// Enable verbose logging.
	#[arg(long, short = 'v', global = true)]
	verbose: bool,

	/// Print output as JSON.
	///
	/// Note that simple string values will still be outputted as raw strings.
	#[arg(long, short = 'j', global = true)]
	json: bool,

	/// The datadir of the bark wallet.
	#[arg(long, global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create a new wallet.
	///
	/// Configuration will pass in default values when --signet is used, but will
	/// require full configuration for regtest.
	#[command()]
	Create {
		/// Force re-create the wallet even if it already exists.
		#[arg(long)]
		force: bool,

		/// Use regtest network.
		#[arg(long)]
		regtest: bool,
		/// Use signet network.
		#[arg(long)]
		signet: bool,

		#[arg(long)]
		asp: Option<String>,
		#[arg(long)]
		asp_cert: Option<String>,

		/// The esplora HTTP API endpoint.
		#[arg(long)]
		esplora: Option<String>,
		#[arg(long)]
		bitcoind: Option<String>,
		#[arg(long)]
		bitcoind_cookie: Option<PathBuf>,
		#[arg(long)]
		bitcoind_user: Option<String>,
		#[arg(long)]
		bitcoind_pass: Option<String>,
	},
	/// use the built-in onchain wallet
	#[command(subcommand)]
	Onchain(OnchainCommand),
	/// The the public key used to receive vtxos.
	#[command()]
	VtxoPubkey,
	#[command()]
	Balance,
	/// list the wallet's VTXOs
	#[command()]
	Vtxos,
	/// refresh expiring VTXOs
	///
	/// By default the wallet's configured threshold is used.
	#[command()]
	Refresh {
		threshold_blocks: Option<u32>,
		threshold_hours: Option<u32>,
	},
	/// onboard from the onchain wallet into the Ark
	#[command()]
	Onboard {
		amount: Amount,
	},
	/// send money using an Ark (out-of-round) transaction
	#[command()]
	Send {
		/// the destination
		destination: String,
		amount: Amount,
	},
	/// send money by participating in an Ark round
	#[command()]
	SendRound {
		/// Destination for the payment, this can either be an on-chain address
		/// or an Ark VTXO public key.
		destination: String,
		amount: Amount,
	},
	#[command()]
	OffboardAll,
	#[command()]
	StartExit,
	#[command()]
	ClaimExit,

	/// Dev command to drop the vtxo database.
	#[command(hide = true)]
	DropVtxos,
}

#[derive(clap::Subcommand)]
enum OnchainCommand {
	/// get the on-chain balance
	#[command()]
	Balance,
	/// get an on-chain address
	#[command()]
	Address,
	/// send using the on-chain wallet
	#[command()]
	Send {
		destination: Address<address::NetworkUnchecked>,
		amount: Amount,
	},
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let mut logbuilder = env_logger::builder();
	logbuilder.target(env_logger::Target::Stderr);
	if cli.verbose {
		logbuilder
			.filter_module("sled", log::LevelFilter::Warn)
			.filter_module("rustls", log::LevelFilter::Warn)
			.filter_module("reqwest", log::LevelFilter::Warn)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Debug)
			.filter_level(log::LevelFilter::Trace);
	} else {
		logbuilder
			.filter_module("sled", log::LevelFilter::Off)
			.filter_module("rustls", log::LevelFilter::Off)
			.filter_module("reqwest", log::LevelFilter::Off)
			.filter_module("bitcoincore_rpc", log::LevelFilter::Off)
			.filter_level(log::LevelFilter::Info);
	}
	logbuilder.init();

	let datadir = {
		let datadir = PathBuf::from(cli.datadir);
		if !datadir.exists() {
			fs::create_dir_all(&datadir).context("failed to create datadir")?;
		}
		datadir.canonicalize().context("canonicalizing path")?
	};

	// Handle create command differently.
	if let Command::Create {
		force, regtest, signet, mut asp, asp_cert, mut esplora, bitcoind, bitcoind_cookie, bitcoind_user,
		bitcoind_pass,
	} = cli.command {
		let net = if regtest && !signet {
			bitcoin::Network::Regtest
		} else if signet && !regtest {
			bitcoin::Network::Signet
		} else {
			bail!("Need to user either --signet and --regtest");
		};

		let mut asp_cert = asp_cert.map(|p|
			fs::read(p).context("failed to read ASP cert file")
		).transpose()?;

		if signet {
			if asp.is_none() {
				asp = Some("https://signet.asp.21m.dev:35035".into());
				if asp_cert.is_none() {
					asp_cert = Some(SIGNET_ASP_CERT.to_vec());
				}
			}
			if esplora.is_none() && bitcoind.is_none() {
				esplora = Some("http://signet.21m.dev:3003".into());
			}
		}

		//TODO(stevenroose) somehow pass this in
		let cfg = Config {
			network: net,
			asp_address: asp.context("missing ASP address")?,
			asp_cert: None,
			esplora_address: esplora,
			bitcoind_address: bitcoind,
			bitcoind_cookiefile: bitcoind_cookie,
			bitcoind_user: bitcoind_user,
			bitcoind_pass: bitcoind_pass,
			..Default::default()
		};

		if force {
			fs::remove_dir_all(&datadir)?;
		}

		fs::create_dir_all(&datadir).context("failed to create datadir")?;
		let mut w = Wallet::create(&datadir, cfg, asp_cert).await.context("error creating wallet")?;
		info!("Onchain address: {}", w.get_new_onchain_address()?);
		return Ok(());
	}

	let mut w = Wallet::open(&datadir).await.context("error opening wallet")?;
	let net = w.config().network;

	match cli.command {
		Command::Create { .. } => unreachable!(),
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
		},
		Command::VtxoPubkey => println!("{}", w.vtxo_pubkey()),
		Command::Balance => {
			w.sync().await.context("sync error")?;
			let onchain = w.onchain_balance();
			let offchain =  w.offchain_balance().await?;
			let (available, unavailable) = w.unclaimed_exits().await?;
			let onchain_available_exit = available.iter().map(|i| i.spec.amount).sum::<Amount>();
			let onchain_pending_exit = unavailable.iter().map(|i| i.spec.amount).sum::<Amount>();
			if cli.json {
				serde_json::to_writer(io::stdout(), &json::Balance {
					onchain, offchain, onchain_available_exit, onchain_pending_exit
				}).unwrap();
			} else {
				info!("Onchain balance: {}", onchain);
				info!("Offchain balance: {}", offchain);
				if !available.is_empty() {
					info!("Got {} claimable exits with total value of {}",
						available.len(), onchain_available_exit,
					);
				}
				if !unavailable.is_empty() {
					info!("Got {} unclaimable exits with total value of {}",
						unavailable.len(), onchain_pending_exit,
					);
				}
			}
		},
		Command::Vtxos => {
			w.sync_ark().await.context("sync error")?;
			let res = w.vtxos()?;
			if cli.json {
				let json = res.into_iter().map(|v| v.into()).collect::<Vec<json::VtxoInfo>>();
				serde_json::to_writer(io::stdout(), &json).unwrap();
			} else {
				info!("Our wallet has {} VTXO(s):", res.len());
				for v in res {
					info!("  {}: {}; expires at height {}",
						v.id(), v.amount(), v.spec().expiry_height,
					);
				}
			}
		},
		Command::Refresh { threshold_blocks, threshold_hours } => {
			let threshold = match (threshold_blocks, threshold_hours) {
				(None, None) => w.config().vtxo_refresh_threshold,
				(Some(b), None) => b,
				(None, Some(h)) => h * 6,
				(Some(_), Some(_)) => bail!("can't provide both block and hour threshold"),
			};

			info!("Refreshing VTXOs expiring within the next {} blocks...", threshold);
			w.refresh_vtxos(threshold).await?;
		},
		Command::Onboard { amount } => w.onboard(amount).await?,
		Command::Send { destination, amount } => {
			let pk = PublicKey::from_str(&destination).context("invalid pubkey")?;
			w.sync_ark().await.context("sync error")?;
			w.send_oor_payment(pk, amount).await?;
			info!("Success");
		},
		Command::SendRound { destination, amount } => {
			if let Ok(pk) = PublicKey::from_str(&destination) {
				debug!("Sending to Ark public key {}", pk);
				w.sync_ark().await.context("sync error")?;
				w.send_round_payment(pk, amount).await?;
			} else if let Ok(addr) = Address::from_str(&destination) {
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
		Command::OffboardAll => w.offboard_all().await?,
		Command::StartExit => w.start_unilateral_exit().await?,
		Command::ClaimExit => w.claim_unilateral_exit().await?,

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
