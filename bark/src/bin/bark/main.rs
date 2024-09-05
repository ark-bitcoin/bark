
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
	/// Perform a unilateral exit from the Ark.
	#[command()]
	Exit {
		/// If set, only try to make progress on pending exits and don't
		/// initiate exits on VTXOs in wallet.
		#[arg(long)]
		only_progress: bool,

		/// Force overwriting the exit lock before starting.
		/// Use this only if you are sure no other process is accessing this wallet.
		#[arg(long)]
		force_lock: bool,

		//TODO(stevenroose) add a option to claim claimable exits while others are not claimable
		//yet
	},

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

fn init_logging(verbose: bool) {
	let mut l = fern::Dispatch::new()
		.level_for("sled", log::LevelFilter::Warn)
		.level_for("rustls", log::LevelFilter::Warn)
		.level_for("reqwest", log::LevelFilter::Warn);
	if verbose {
		l = l
			.level(log::LevelFilter::Trace)
			.level_for("bitcoincore_rpc", log::LevelFilter::Debug);
	} else {
		l = l
			.level(log::LevelFilter::Info)
			.level_for("bitcoincore_rpc", log::LevelFilter::Warn);
	}
	l
		.format(|out, msg, rec| {
			let now = chrono::Local::now();
			// only time, not date
			let stamp = now.format("%H:%M:%S.%3f");
			out.finish(format_args!("[{} {: >5}] {}", stamp, rec.level(), msg))
		})
		.chain(std::io::stderr())
		.apply().expect("error setting up logging");
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	init_logging(cli.verbose);

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
		Command::Exit { only_progress, force_lock } => {
			if force_lock {
				w.release_exit_lock().context("couldn't release exit lock")?;
			}

			fn print_exit_lock_msg<T>(res: anyhow::Result<T>) -> anyhow::Result<T> {
				if let Result::Err(ref err) = res {
					if let Some(_) = err.downcast_ref::<bark::ExitLockError>() {
						error!("ERROR: Failed to take the exit lock. \
							If you are sure no other process is accessing this wallet, \
							run the same command with --force-lock to resolve this issue.");
					}
				}
				res
			}

			if !only_progress {
				print_exit_lock_msg(w.start_exit_for_entire_wallet().await)
					.context("error starting exit process for existing vtxos")?;
			}

			let res = print_exit_lock_msg(w.progress_exit().await)
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
					bark::ExitStatus::Done => info!("Exit done!"),
					bark::ExitStatus::NeedMoreTxs => {
						info!("More transactions need to be confirmed, keep calling this command.");
					},
					bark::ExitStatus::WaitingForHeight(h)=> {
						info!("All transactions are confirmed, \
							you can claim them all at block height {}.", h);
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
