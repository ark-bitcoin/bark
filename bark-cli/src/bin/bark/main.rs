#[macro_use] extern crate anyhow;

mod dev;
mod exit;
mod lightning;
mod onchain;
mod round;

use std::cmp::Ordering;
use std::{env, process};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bark::movement::PaymentMethod;
use bark::secret::Secret;
use bark_cli::VERSION_DEV_MARKER;
use bitcoin::{Amount};
use bitcoin::secp256k1;
use bitcoin_ext::BlockHeight;
use clap::builder::BoolishValueParser;
use clap::Parser;
use futures::StreamExt;
use log::{debug, info, warn};

use ark::{ProtocolEncoding, VtxoId};
use bark::PaymentInitOutput;
use bark::vtxo::{VtxoFilter, VtxoStateKind};
use bark_json as json;
use bark_json::primitives::WalletVtxoInfo;

use bark_cli::wallet::{CreateOpts, create_wallet, open_wallet};
use bark_cli::log::init_logging;
use bark_cli::util::output_json;


fn default_datadir() -> String {
	home::home_dir().or_else(|| {
		env::current_dir().ok()
	}).unwrap_or_else(|| {
		"./".into()
	}).join(".bark").display().to_string()
}

/// The full version string we show in our binary.
/// (BARK_VERSION and GIT_HASH are set in build.rs)
const FULL_VERSION: &str = concat!(env!("BARK_VERSION"), " (", env!("GIT_HASH"), ")");

/// Wire-level client identity sent in `x-user-agent` on every RPC.
pub const USER_AGENT: &str = concat!("bark/", env!("BARK_VERSION"));

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

	/// Write the debug log to this file instead of the default
	/// `<datadir>/debug.log`
	#[arg(long, env = "BARK_LOGFILE", global = true, conflicts_with = "no_logfile")]
	logfile: Option<PathBuf>,
	/// Disable the debug log file entirely
	#[arg(
		long,
		env = "BARK_NO_LOGFILE",
		global = true,
		conflicts_with = "logfile",
		value_parser = BoolishValueParser::new(),
	)]
	no_logfile: bool,

	/// The datadir of the bark wallet
	#[arg(long, env = "BARK_DATADIR", global = true, default_value_t = default_datadir())]
	datadir: String,

	#[command(subcommand)]
	command: Command,
}


#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct AddressLookupFilter {
	/// The Ark address to look up
	#[arg(long)]
	address: Option<ark::Address>,
	/// Address pubkey index to look up
	#[arg(long)]
	index: Option<u32>,
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
struct VerifyMessageKey {
	/// The public key to verify the signature against
	#[arg(long)]
	pubkey: Option<secp256k1::PublicKey>,
	/// The Ark address whose user pubkey to verify the signature against
	#[arg(long)]
	address: Option<ark::Address>,
}

#[derive(clap::Subcommand)]
enum AddressCommand {
	/// Look up receives for an Ark address
	Lookup {
		#[clap(flatten)]
		filter: AddressLookupFilter,
	},
}

#[derive(clap::Subcommand)]
enum MessageCommand {
	/// Sign an arbitrary message with the key of the provided Ark address
	Sign {
		/// The message to sign
		message: String,
		/// The Ark address to sign the message with
		address: ark::Address,
	},

	/// Verify a signed message
	///
	/// Exits with an error if the signature is not valid.
	Verify {
		/// The message that was signed
		message: String,
		/// The signature, in hex
		signature: secp256k1::schnorr::Signature,
		#[clap(flatten)]
		key: VerifyMessageKey,
	},
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
		/// Address pubkey index to peek
		#[arg(long)]
		index: Option<u32>,

		#[command(subcommand)]
		subcommand: Option<AddressCommand>,
	},

	/// Sign and verify messages
	#[command(subcommand)]
	Message(MessageCommand),

	/// Generate a BIP 321 payment string
	#[command()]
	Bip321 {
		/// The amount to receive
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		///
		/// Optional. If omitted, the builder will skip generating a BOLT11 invoice.
		#[arg(long)]
		amount: Option<Amount>,
		/// The label to add to the payment
		#[arg(long)]
		label: Option<String>,
		/// The message to add to the payment
		#[arg(long)]
		message: Option<String>,
		/// Whether to include all payment methods
		#[arg(long)]
		all: bool,
		/// Whether to include an onchain address in the payment
		#[arg(long)]
		onchain: bool,
		/// Whether to include a Lightning invoice in the payment
		#[arg(long)]
		lightning: bool,
		/// Whether to include an Ark address in the payment
		#[arg(long)]
		ark: bool,
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
		/// Returns all VTXOs regardless of their state
		#[arg(long)]
		all: bool,
		/// Skip syncing before fetching VTXOs
		#[arg(long)]
		no_sync: bool,
	},

	/// get a raw VTXO in hex
	#[command()]
	RawVtxo {
		vtxo_id: String,
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
		/// Perform the refresh in delegated (non-interactive) mode
		#[arg(long)]
		delegated: bool,
		/// Schedule the delegated refresh at this block height instead of the next round.
		/// Requires --delegated.
		#[arg(long, requires = "delegated")]
		height: Option<u32>,
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

	/// Send a payment to an Ark, Lightning, Bitcoin or BIP-321 destination
	#[command()]
	Send {
		/// Supported destinations are:
		/// - Ark address
		/// - BOLT11 invoice
		/// - BOLT12 offer
		/// - Lightning address
		/// - Bitcoin address
		/// - BIP321 payment URI
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
		/// Wait for the payment to be completed
		#[arg(long)]
		wait: bool,
		/// In case the BIP 321 payment URI has multiple valid payment methods,
		/// select the method by index. Allow using this CLI in non-interactive
		/// mode. It is ignored if the destination has only one valid payment method.
		#[arg(long)]
		method_index: Option<u32>,
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

	/// Watch the wallet for updates
	#[command()]
	Watch,

	/// Run wallet maintenence
	///
	/// This includes onchain sync, offchain sync, registering boards with the server,
	/// syncing Lightning VTXOs, syncing exits, and refreshing soon-to-expire VTXOs
	#[command()]
	Maintain {
		/// Perform the maintenance in delegated (non-interactive) mode
		#[arg(long)]
		delegated: bool,
	},

	/// developer commands
	#[command(subcommand)]
	Dev(dev::DevCommand),
}


async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let datadir = PathBuf::from_str(&cli.datadir).unwrap();

	init_logging(cli.verbose, cli.quiet, &datadir, cli.logfile.clone(), cli.no_logfile);

	info!("Starting bark version {} with datadir {}", FULL_VERSION, datadir.display());

	if env!("BARK_VERSION").contains(VERSION_DEV_MARKER) {
		warn!("You're running a custom build of bark, which might cause unexpected issues. \
			Consider building at one of the tagged versions or using the release builds.");
	}

	// Handle create command differently.
	if let Command::Create(opts) = cli.command {
		create_wallet(&datadir, USER_AGENT, opts).await?;
		return Ok(())
	}

	if let Command::Dev(cmd) = cli.command {
		return dev::execute_dev_command(cmd, datadir).await;
	}

	// Message verification is stateless, so it doesn't need a wallet.
	if let Command::Message(MessageCommand::Verify { message, signature, key }) = cli.command {
		let pubkey = if let Some(pubkey) = key.pubkey {
			pubkey
		} else if let Some(address) = key.address {
			address.policy().user_pubkey()
		} else {
			unreachable!("clap requires --pubkey or --address");
		};
		if !ark::message::verify(pubkey, message.as_bytes(), &signature) {
			bail!("invalid signature");
		}
		output_json(&json::cli::MessageVerification { valid: true });
		return Ok(())
	}

	let mut wallet = open_wallet(&datadir, USER_AGENT).await
		.context("error opening wallet")?
		.context("No wallet found")?;

	let net = wallet.network().await?;

	match cli.command {
		Command::Create { .. } | Command::Dev(_) | Command::Message(MessageCommand::Verify { .. }) => {
			unreachable!("handled earlier")
		},
		Command::Config => {
			let mut config = wallet.config().clone();
			// The Secret wrapper only redacts Debug output; JSON
			// serialization passes through, so swap the value here.
			config.bitcoind_pass = config.bitcoind_pass
				.map(|_| Secret::new("[redacted]".to_owned()));
			output_json(&config)
		},
		Command::ArkInfo => {
			match wallet.require_ark_info().await {
				Ok(info) => output_json(&bark_json::cli::ArkInfo::from(info)),
				Err(_) => warn!("Could not connect with Ark server."),
			}
		},
		Command::Address { index, subcommand } => {
			match subcommand {
				Some(AddressCommand::Lookup { filter: AddressLookupFilter { address, index } }) => {
					let address = if let Some(address) = address {
						address
					} else if let Some(index) = index {
						wallet.peek_address(index).await?
					} else {
						unreachable!("clap requires --address or --index");
					};
					let pm = PaymentMethod::Ark(address);
					let movements = wallet.history_by_payment_method(&pm).await?.into_iter()
						.map(json::movements::Movement::from)
						.collect::<Vec<_>>();
					output_json(&movements);
				},
				None => {
					if let Some(index) = index {
						println!("{}", wallet.peek_address(index).await?)
					} else {
						println!("{}", wallet.new_address().await?)
					}
				},
			}
		},
		Command::Message(MessageCommand::Sign { message, address }) => {
			let signature = wallet.sign_message(message.as_bytes(), &address).await?
				.context("address does not belong to this wallet or its key has not been derived")?;
			output_json(&json::cli::SignedMessage { signature });
		},
		Command::Bip321 {
			amount, label, message,
			onchain: onchain_enabled,
			lightning: lightning_enabled,
			ark: ark_enabled,
			all: all_enabled,
		} => {
			let onchain = wallet.onchain();
			let mut onchain_guard = match onchain.as_ref() {
				Some(onchain) => Some(onchain.write().await),
				None => None,
			};

			let mut builder = wallet.bip321_uri();
			if let Some(amount) = amount {
				builder = builder.amount(amount);
			}

			if let Some(label) = label {
				builder = builder.label(label);
			}
			if let Some(message) = message {
				builder = builder.message(message);
			}

			if all_enabled {
				let onchain = onchain_guard.as_mut()
					.context("no onchain wallet configured")?;
				builder = builder
					.onchain_wallet(&mut **onchain)
					.lightning_bolt11(true)
					.ark(true);
			} else {
				let enabled_count = [onchain_enabled, lightning_enabled, ark_enabled]
					.iter().filter(|e| **e).count();
				if enabled_count == 0 {
					bail!("at least one payment method must be enabled");
				}

				// The builder enables all methods by default,
				// so first disable them and re-enable the selected ones.
				builder = builder.disable_all();
				if onchain_enabled {
					let onchain = onchain_guard.as_mut()
						.context("no onchain wallet configured")?;
					builder = builder.onchain_wallet(&mut **onchain);
				}
				if lightning_enabled { builder = builder.lightning_bolt11(true); }
				if ark_enabled { builder = builder.ark(true); }
			}

			println!("{}", builder.build().await?);
		},
		Command::Balance { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let balance = wallet.balance().await?;
			output_json(&json::cli::Balance::from(balance));
		},
		Command::Vtxos { all, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let mut vtxos = if all {
				wallet.all_vtxos().await?
			} else {
				wallet.vtxos().await?
			};

			vtxos.sort_by(|a, b| {
				match (a.state.kind(), b.state.kind()) {
					(VtxoStateKind::Spent, b) if b != VtxoStateKind::Spent => Ordering::Less,
					(VtxoStateKind::Spendable, a) if a != VtxoStateKind::Spendable => Ordering::Greater,
					_ => a.expiry_height().cmp(&b.expiry_height()),
				}
			});

			output_json(&vtxos.iter().map(WalletVtxoInfo::from).collect::<Vec<_>>());
		},
		Command::RawVtxo { vtxo_id } => {
			let v = wallet.get_full_vtxo(vtxo_id.parse().context("invalid VTXO ID")?).await?;
			println!("{}", v.serialize_hex());
		}
		Command::History { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let mut movements = wallet.history().await?.into_iter()
				.map(json::movements::Movement::try_from)
				.collect::<Result<Vec<_>, _>>()?;

			// Movements are ordered from newest to oldest, so we reverse them to ensure the last
			// item in the terminal is the newest.
			movements.reverse();

			output_json(&movements);
		},
		Command::Refresh {
			vtxos, threshold_blocks, threshold_hours, counterparty, all, delegated,
			height, no_sync,
		} => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let vtxos = match (threshold_blocks, threshold_hours, counterparty, all, vtxos) {
				(None, None, false, false, None) => wallet.get_expiring_vtxos(
					wallet.config().vtxo_refresh_expiry_threshold as BlockHeight,
				).await?,
				(Some(b), None, false, false, None) => wallet.get_expiring_vtxos(b).await?,
				(None, Some(h), false, false, None) => wallet.get_expiring_vtxos(h*6).await?,
				(None, None, true, false, None) => {
					let filter = VtxoFilter::new(&wallet).counterparty();
					wallet.spendable_vtxos_with(&filter).await?
				},
				(None, None, false, true, None) => wallet.spendable_vtxos().await?,
				(None, None, false, false, Some(vs)) => {
					let mut vtxos = vec![];
					for s in vs {
						let id = VtxoId::from_str(&s)?;
						vtxos.push(wallet.get_vtxo_by_id(id).await?);
					}
					vtxos
				}
				_ => bail!("please provide either threshold vtxo, threshold_blocks, threshold_hours, counterparty or all"),
			};

			info!("Refreshing {} vtxos...", vtxos.len());
			if delegated {
				let res = match height {
					Some(height) => wallet.refresh_vtxos_scheduled(vtxos, height).await?,
					None => wallet.refresh_vtxos_delegated(vtxos).await?,
				};

				if let Some(res) = res {
					output_json(&json::cli::RoundStateInfo {
						round_state_id: res.id().0,
					});
				} else {
					info!("No round happened");
				}
			} else {
				if let Some(res) = wallet.refresh_vtxos(vtxos).await? {
					output_json(&json::cli::RoundStatus::from(res));
				} else {
					info!("No round happened");
				}
			}
		},
		Command::Board { amount, all, no_sync } => {
			if !no_sync {
				info!("Syncing onchain wallet...");
				if let Err(e) = wallet.sync_onchain().await {
					warn!("Sync error: {}", e)
				}
			}
			let board = match (amount, all) {
				(Some(a), false) => {
					info!("Boarding {}...", a);
					wallet.board_amount(a).await?
				},
				(None, true) => {
					info!("Boarding total balance...");
					wallet.board_all().await?
				},
				_ => bail!("please provide either an amount or --all"),
			};
			output_json(&json::cli::PendingBoardInfo::from(board));
		},
		Command::Send { destination, amount, comment, no_sync, wait, method_index } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let parsed_payment = wallet.parse_payment_request(&destination).await?;
			let effective_amount = amount.or(parsed_payment.amount);

			let mut valid = Vec::with_capacity(parsed_payment.options.len());
			let mut invalid = Vec::with_capacity(parsed_payment.options.len());

			for option in parsed_payment.options {
				let fee_str = if let Some(amt) = effective_amount {
					match wallet.estimate_payment_fee(&option, amt).await {
						Ok(fee) => format!("fee ~{}", fee.fee),
						Err(_) => "unknown fee".to_string(),
					}
				} else {
					"unknown fee".to_string()
				};

				let err_str = if option.errors.is_empty() {
					String::new()
				} else {
					let msgs: Vec<_> = option.errors.iter()
						.map(|e| e.to_string()).collect();
					format!(" ({})", msgs.join(", "))
				};

				let label = format!("{} ({}){}", option.method.type_str(), fee_str, err_str);
				if err_str.is_empty() {
					valid.push((option, label));
				} else {
					invalid.push((option, label));
				}
			}

			for (_, label) in invalid {
				info!("Ignoring invalid payment method: {}", label);
			}

			if valid.is_empty() {
				bail!("no valid payment methods found");
			}

			// If payment string has more than one valid method,
			// prompt the user to select one.
			let selected_method = if valid.len() == 1 {
				info!("{} is only method supported, auto selected", valid[0].1);
				&valid[0].0.method
			} else if let Some(index) = method_index {
				let (option, _) = &valid.get(index as usize)
					.context("Could not pick method by index")?;
				&option.method
			} else {
				let options = valid.iter()
					.map(|(_, label)| label.clone())
					.collect::<Vec<String>>();

				let selection = dialoguer::Select::new()
					.with_prompt("Select payment method")
					.items(&options)
					.default(0)
					.interact()
					.context("failed to read user selection")?;

				let (option, _) = &valid[selection];
				&option.method
			};

			// Ask for an amount when the selected method needs one
			// and none was provided.
			let effective_amount = match effective_amount {
				None if selected_method.requires_amount() => {
					let amount = dialoguer::Input::<Amount>::new()
						.with_prompt("Amount to send (e.g. 250000 sats)")
						.interact_text()
						.context("failed to read amount")?;
					Some(amount)
				},
				other => other,
			};

			// Send the payment.
			let output = wallet.send_payment(
				selected_method, effective_amount, comment, wait
			).await?;

			// Wait for lightning payment settlement if requested.
			if let PaymentInitOutput::Lightning(invoice) = output {
				if wait {
					info!("Payment completed: hash = {}", invoice.payment_hash());
				} else {
					info!("Payment initiated: hash = {}", invoice.payment_hash());
				}
			}
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

				info!("Sending on-chain payment of {} to {}", amount, addr);
				let offboard_txid = wallet.send_onchain(addr, amount).await?;
				output_json(&json::cli::OffboardResult { offboard_txid });
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
				wallet.onchain().context("no onchain wallet configured")?.write().await.address().await?
			};

			let offboard_txid = if let Some(vtxos) = vtxos {
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
			output_json(&json::cli::OffboardResult { offboard_txid });
		},
		Command::Onchain(onchain_command) => {
			onchain::execute_onchain_command(onchain_command, &wallet).await?;
		},
		Command::Exit(cmd) => {
			exit::execute_exit_command(cmd, &mut wallet).await?;
		},
		Command::Lightning(cmd) => {
			lightning::execute_lightning_command(cmd, &mut wallet).await?;
		},
		Command::Round(cmd) => {
			round::execute_round_command(cmd, &mut wallet).await?;
		},
		Command::Watch => {
			let mut stream = wallet.subscribe_notifications();
			let _daemon = wallet.start_daemon()
				.context("failed to start bark daemon")?;
			while let Some(notif) = stream.next().await {
				output_json(&json::notifications::WalletNotification::from(notif));
			}
			info!("Notification stream closed");
		},
		Command::Maintain { delegated } => {
			if delegated {
				wallet.maintenance_delegated().await?;
			} else {
				wallet.maintenance().await?;
			}
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
