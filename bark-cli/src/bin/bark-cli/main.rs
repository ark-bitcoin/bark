//! The bark-cli binary: a thin client driving barkd over its REST API.
//!
//! Every wallet command talks to the barkd running on the shared datadir
//! (at its default listen address, or an explicit --url), authenticates
//! with the datadir's bearer token and prints the same bark-json models
//! the in-process CLI prints. The in-process wallet lives on as
//! `bark-legacy` (still shipped as `bark`) until bark-cli replaces it.

#[macro_use] extern crate anyhow;

mod connect;
mod daemon;
mod exit;
mod lightning;
mod onchain;
mod round;

use std::{env, process};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{address, Amount};
use bitcoin::secp256k1;
use clap::builder::BoolishValueParser;
use clap::Parser;
use log::{info, warn};

use bark_cli::VERSION_DEV_MARKER;
use bark_cli::log::init_logging;
use bark_cli::util::output_json;
use bark_json::primitives::VtxoStateInfo;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::{
	bitcoin_api, boards_api, history_api, message_api, notifications_api, wallet_api,
};
use bark_rest_client::models;
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::connect::RestResultExt;

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

/// Client identity sent as the User-Agent header on every request.
pub const USER_AGENT: &str = concat!("bark-cli/", env!("BARK_VERSION"));

/// The parse only checks the address format; barkd validates the network.
fn addr_string(addr: bitcoin::Address<address::NetworkUnchecked>) -> String {
	addr.assume_checked().to_string()
}

#[derive(Parser)]
#[command(name = "bark-cli", author = "Team Second <hello@second.tech>", version = FULL_VERSION, about)]
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

	/// Connect to a barkd at this URL instead of the default listen
	/// address of the barkd on this datadir.
	#[arg(long, env = "BARK_URL", global = true)]
	url: Option<String>,

	/// Bearer token to authenticate with. Defaults to the token in the
	/// datadir (`auth_token`).
	#[arg(long, env = "BARK_TOKEN", global = true)]
	token: Option<String>,

	#[command(subcommand)]
	command: Command,
}

#[derive(clap::Args)]
struct CreateOpts {
	/// Force re-create the wallet even if it already exists.
	/// Any funds in the old wallet will be lost
	#[arg(long)]
	force: bool,

	/// Use bitcoin mainnet
	#[arg(long)]
	mainnet: bool,
	/// Use regtest network
	#[arg(long)]
	regtest: bool,
	/// Use the official signet network
	#[arg(long)]
	signet: bool,
	/// Use mutinynet
	#[arg(long)]
	mutinynet: bool,

	/// Recover a wallet with an existing mnemonic.
	/// This currently only works for on-chain funds.
	#[arg(long)]
	mnemonic: Option<bip39::Mnemonic>,

	/// The wallet/mnemonic's birthday blockheight to start syncing when recovering.
	#[arg(long)]
	birthday_height: Option<BlockHeight>,

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

	/// How many consecutive unused key indices a VTXO key scan may cross before
	/// it concludes the wallet doesn't own a recovered/imported VTXO.
	#[arg(long)]
	gap_limit: Option<u32>,
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

#[derive(Clone, Copy, clap::ValueEnum)]
enum PaymentMethodArg {
	Ark,
	Lightning,
	Onchain,
}

#[derive(clap::Subcommand)]
enum Command {
	/// Create a new wallet
	///
	/// Configuration will pass in default values when --signet is used, but will
	/// require full configuration for regtest
	#[command()]
	Create(CreateOpts),

	/// Prints information related to the Ark Server
	#[command()]
	ArkInfo,

	/// Print wallet information that helps to debug issues
	#[command()]
	DebugInfo,

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
	///
	/// It always includes an Ark address, and a BOLT11 invoice when an amount
	/// is given.
	#[command()]
	Bip321 {
		/// The amount to receive
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		///
		/// Optional. If omitted, no BOLT11 invoice is generated.
		#[arg(long)]
		amount: Option<Amount>,
		/// The label to add to the payment
		#[arg(long)]
		label: Option<String>,
		/// The message to add to the payment
		#[arg(long)]
		message: Option<String>,
		/// Whether to include an onchain address in the payment
		#[arg(long)]
		onchain: bool,
	},

	/// Get the wallet balance
	#[command()]
	Balance,

	/// List the wallet's VTXOs
	#[command()]
	Vtxos {
		/// Returns all VTXOs regardless of their state
		#[arg(long)]
		all: bool,
	},

	/// get a raw VTXO in hex
	#[command()]
	RawVtxo {
		vtxo_id: String,
	},

	/// List the wallet's payments
	#[command(alias="movements")]
	History,

	/// Refresh expiring VTXOs
	///
	/// Select the VTXOs to refresh with exactly one of --vtxo,
	/// --threshold-blocks, --threshold-hours, --counterparty or --all
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
	},

	/// Send a payment to an Ark, Lightning, Bitcoin or BIP-321 destination
	#[command()]
	Send {
		/// Supported destinations are:
		/// - Ark address
		/// - BOLT11 invoice
		/// - BOLT12 offer
		/// - Lightning address
		/// - LNURL
		/// - Bitcoin address
		/// - BIP321 payment URI
		destination: String,
		/// The amount to send (optional for bolt11)
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		amount: Option<Amount>,
		/// An optional comment
		comment: Option<String>,
		/// Wait for the payment to be completed
		#[arg(long)]
		wait: bool,
		/// In case the destination offers several payment methods, such as a
		/// BIP 321 URI, the kind of method to pay with. Without it, barkd picks
		/// Ark, then Lightning, then on-chain.
		#[arg(long, value_enum)]
		method: Option<PaymentMethodArg>,
		/// For lightning payments, how many seconds the server should keep
		/// trying to pay, capped to the server's maximum. Defaults to the
		/// server's choice.
		#[arg(long = "retry-for", value_name = "SECONDS")]
		retry_for_secs: Option<u64>,
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

	/// Show whether a barkd is running for this datadir
	#[command()]
	Status,
}

fn create_opts_to_request(opts: CreateOpts) -> anyhow::Result<models::CreateWalletRequest> {
	let network = match (opts.mainnet, opts.signet, opts.regtest, opts.mutinynet) {
		(true,  false, false, false) => models::BarkNetwork::Mainnet,
		(false, true,  false, false) => models::BarkNetwork::Signet,
		(false, false, true,  false) => models::BarkNetwork::Regtest,
		(false, false, false, true ) => models::BarkNetwork::Mutinynet,
		_ => bail!("Specify exactly one of --mainnet, --signet, --regtest or --mutinynet"),
	};

	let chain_source = match (opts.esplora, opts.bitcoind) {
		(Some(url), None) => Some(models::ChainSourceConfig::Esplora { url }),
		(None, Some(bitcoind)) => {
			let auth = match (opts.bitcoind_cookie, opts.bitcoind_user, opts.bitcoind_pass) {
				(Some(cookie), None, None) => models::BitcoindAuth::Cookie { cookie },
				(None, Some(user), Some(pass)) => models::BitcoindAuth::UserPass { user, pass },
				_ => bail!("provide either --bitcoind-cookie or both \
					--bitcoind-user and --bitcoind-pass"),
			};
			Some(models::ChainSourceConfig::Bitcoind { bitcoind, bitcoind_auth: auth })
		},
		(None, None) => None,
		(Some(_), Some(_)) => bail!("provide either --esplora or --bitcoind, not both"),
	};

	#[allow(deprecated)]
	Ok(models::CreateWalletRequest {
		ark_server: opts.ark,
		ark_server_access_token: None,
		chain_source,
		mnemonic: opts.mnemonic.map(|m| m.to_string()),
		network,
		birthday_height: opts.birthday_height.map(BlockHeight::to_u32),
		gap_limit: opts.gap_limit,
		force: opts.force,
	})
}

async fn execute_command(command: Command, config: &Configuration) -> anyhow::Result<()> {
	match command {
		Command::Create(_) | Command::Status =>
			unreachable!("handled before dispatch"),
		Command::ArkInfo => {
			let info = wallet_api::ark_info(config).await.rest()
				.context("could not get the Ark server info")?;
			output_json(&info);
		},
		Command::DebugInfo => {
			output_json(&wallet_api::debug_info(config).await.rest()?);
		},
		Command::Address { index, subcommand } => {
			match subcommand {
				Some(AddressCommand::Lookup { filter: AddressLookupFilter { address, index } }) => {
					let address = if let Some(address) = address {
						address.to_string()
					} else if let Some(index) = index {
						wallet_api::peek_address(
							config, index.try_into().context("index overflow")?,
						).await.rest()?.address
					} else {
						unreachable!("clap requires --address or --index");
					};
					let movements = history_api::list(config, Some("ark"), Some(&address)).await.rest()?;
					output_json(&movements);
				},
				None => {
					let resp = if let Some(index) = index {
						wallet_api::peek_address(
							config, index.try_into().context("index overflow")?,
						).await.rest()?
					} else {
						wallet_api::address(config).await.rest()?
					};
					println!("{}", resp.address);
				},
			}
		},
		Command::Message(msg_cmd) => match msg_cmd {
			MessageCommand::Sign { message, address } => {
				let req = models::SignMessageRequest {
					message,
					address: address.to_string(),
				};
				let resp = message_api::sign_message(config, req).await.rest()?;
				output_json(&resp);
			},
			MessageCommand::Verify { message, signature, key } => {
				let req = models::VerifyMessageRequest {
					message,
					signature: signature.to_string(),
					pubkey: key.pubkey.map(|p| p.to_string()),
					address: key.address.map(|a| a.to_string()),
				};
				let resp = message_api::verify_message(config, req).await.rest()?;
				if !resp.valid {
					bail!("invalid signature");
				}
				output_json(&resp);
			},
		},
		Command::Bip321 { amount, label, message, onchain } => {
			let req = models::Bip321UriRequest {
				amount_sat: amount.map(|a| a.to_sat()),
				onchain: Some(onchain),
				label,
				message,
			};
			let resp = wallet_api::bip321_uri(config, req, None).await.rest()?;
			println!("{}", resp.bip321);
		},
		Command::Balance => {
			let balance = wallet_api::balance(config).await.rest()?;
			output_json(&balance);
		},
		Command::Vtxos { all } => {
			let mut vtxos = wallet_api::vtxos(config, Some(all)).await.rest()?;

			// Spent first and spendable last, each by expiry.
			vtxos.sort_by_key(|v| {
				let rank = match v.state {
					VtxoStateInfo::Spent => 0,
					VtxoStateInfo::Exited | VtxoStateInfo::Locked { .. } => 1,
					VtxoStateInfo::Spendable => 2,
				};
				(rank, v.vtxo.expiry_height)
			});

			output_json(&vtxos);
		},
		Command::RawVtxo { vtxo_id } => {
			let resp = wallet_api::get_vtxo_encoded(config, &vtxo_id).await.rest()?;
			println!("{}", resp.encoded.0);
		},
		Command::History => {
			let mut movements = history_api::list(config, None, None).await.rest()?;
			// Movements are ordered from newest to oldest, so we reverse them to ensure the last
			// item in the terminal is the newest.
			movements.reverse();
			output_json(&movements);
		},
		Command::Refresh {
			vtxos, threshold_blocks, threshold_hours, all, counterparty, delegated, height,
		} => {
			if delegated {
				let vtxos = match (threshold_blocks, threshold_hours, counterparty, all, vtxos) {
					(Some(b), None, false, false, None) => expiring_vtxo_ids(config, b).await?,
					(None, Some(h), false, false, None) => expiring_vtxo_ids(config, h.saturating_mul(6)).await?,
					(None, None, false, true, None) => spendable_vtxo_ids(config).await?,
					(None, None, false, false, Some(vtxos)) => vtxos,
					(None, None, true, false, None) => bail!(
						"--counterparty cannot be combined with --delegated",
					),
					_ => bail!("provide exactly one of --vtxo, --threshold-blocks, \
						--threshold-hours, --counterparty or --all"),
				};
				if vtxos.is_empty() {
					info!("No round happened");
					return Ok(());
				}
				info!("Refreshing {} vtxos...", vtxos.len());
				let req = models::DelegatedRefreshRequest { vtxos, height };
				let resp = wallet_api::refresh_delegated(config, req).await.rest()?;
				output_json(&resp);
				return Ok(());
			}
			let resp = match (threshold_blocks, threshold_hours, counterparty, all, vtxos) {
				(Some(b), None, false, false, None) => refresh_expiring(config, b).await?,
				(None, Some(h), false, false, None) => refresh_expiring(config, h.saturating_mul(6)).await?,
				(None, None, true, false, None) => {
					Some(wallet_api::refresh_counterparty(config).await.rest()?)
				},
				(None, None, false, true, None) => {
					Some(wallet_api::refresh_all(config).await.rest()?)
				},
				(None, None, false, false, Some(vtxos)) => {
					info!("Refreshing {} vtxos...", vtxos.len());
					let req = models::RefreshRequest { vtxos };
					Some(wallet_api::refresh_vtxos(config, req).await.rest()?)
				},
				_ => bail!("provide exactly one of --vtxo, --threshold-blocks, \
					--threshold-hours, --counterparty or --all"),
			};
			match resp {
				Some(resp) => output_json(&resp),
				None => info!("No round happened"),
			}
		},
		Command::Board { amount, all } => {
			let board = match (amount, all) {
				(Some(a), false) => {
					info!("Boarding {}...", a);
					let req = models::BoardRequest { amount_sat: a.to_sat() };
					boards_api::board_amount(config, req).await.rest()?
				},
				(None, true) => {
					info!("Boarding total balance...");
					boards_api::board_all(config).await.rest()?
				},
				_ => bail!("please provide either an amount or --all"),
			};
			output_json(&board);
		},
		Command::Send { destination, amount, comment, wait, method, retry_for_secs } => {
			let req = models::SendRequest {
				destination,
				amount_sat: amount.map(|a| a.to_sat()),
				comment,
				retry_for_secs,
				method: method.map(|m| match m {
					PaymentMethodArg::Ark => models::PaymentMethodKind::Ark,
					PaymentMethodArg::Lightning => models::PaymentMethodKind::Lightning,
					PaymentMethodArg::Onchain => models::PaymentMethodKind::Onchain,
				}),
			};
			let resp = wallet_api::send(config, req).await.rest()?;
			match resp.payment_hash {
				Some(hash) => {
					info!("Payment initiated: hash = {}", hash);
					if wait {
						lightning::wait_for_lightning_send(config, &hash.to_string()).await?;
					}
				},
				None => info!("{}", resp.message),
			}
		},
		Command::SendOnchain { destination, amount } => {
			info!("Sending on-chain payment of {} to {}", amount, destination);
			let req = models::SendOnchainRequest {
				destination,
				amount_sat: amount.to_sat(),
			};
			let resp = wallet_api::send_onchain(config, req).await.rest()?;
			output_json(&resp);
		},
		Command::Offboard { address, vtxos, all } => {
			let resp = match (vtxos, all) {
				(Some(vtxos), false) => {
					info!("Offboarding {} vtxos...", vtxos.len());
					let req = models::OffboardVtxosRequest { address, vtxos };
					wallet_api::offboard_vtxos(config, req).await.rest()?
				},
				(None, true) => {
					info!("Offboarding all off-chain funds...");
					let req = models::OffboardAllRequest { address };
					wallet_api::offboard_all(config, req).await.rest()?
				},
				_ => bail!("Either --vtxos or --all argument must be provided to offboard"),
			};
			output_json(&resp);
		},
		Command::Onchain(cmd) => onchain::execute_onchain_command(cmd, config).await?,
		Command::Exit(cmd) => exit::execute_exit_command(cmd, config).await?,
		Command::Lightning(cmd) => lightning::execute_lightning_command(cmd, config).await?,
		Command::Round(cmd) => round::execute_round_command(cmd, config).await?,
		Command::Watch => {
			// Only notifications from now on, like the in-process watch. The
			// `since` bound is exclusive, so none is printed twice.
			let mut since = chrono::Utc::now();
			loop {
				let resp = notifications_api::wait_notification(config, Some(since.fixed_offset()))
					.await.rest()?;
				for notification in &resp.notifications {
					output_json(notification);
				}
				if let Some(last) = resp.last_pushed_at {
					since = last;
				}
			}
		},
	}
	Ok(())
}

/// Client-side equivalent of the wallet's `get_expiring_vtxos`: the IDs of
/// the spendable VTXOs expiring within `threshold` blocks of the current tip.
async fn expiring_vtxo_ids(
	config: &Configuration,
	threshold: u32,
) -> anyhow::Result<Vec<String>> {
	let threshold = BlockDelta::try_from(threshold).context("refresh threshold too large")?;
	let tip = BlockHeight::new(bitcoin_api::tip(config).await.rest()?.tip_height);
	Ok(wallet_api::vtxos(config, Some(false)).await.rest()?
		.into_iter()
		.filter(|v| {
			matches!(v.state, VtxoStateInfo::Spendable)
				&& v.vtxo.expiry_height < tip + threshold
		})
		.map(|v| v.vtxo.id.to_string())
		.collect())
}

/// The IDs of every spendable VTXO.
async fn spendable_vtxo_ids(config: &Configuration) -> anyhow::Result<Vec<String>> {
	Ok(wallet_api::vtxos(config, Some(false)).await.rest()?
		.into_iter()
		.filter(|v| matches!(v.state, VtxoStateInfo::Spendable))
		.map(|v| v.vtxo.id.to_string())
		.collect())
}

/// Refresh the spendable VTXOs expiring within `threshold` blocks of the
/// current tip. Returns `None` if there is nothing to refresh.
async fn refresh_expiring(
	config: &Configuration,
	threshold: u32,
) -> anyhow::Result<Option<models::PendingRoundInfo>> {
	let vtxos = expiring_vtxo_ids(config, threshold).await?;
	if vtxos.is_empty() {
		return Ok(None);
	}
	info!("Refreshing {} vtxos...", vtxos.len());
	let req = models::RefreshRequest { vtxos };
	Ok(Some(wallet_api::refresh_vtxos(config, req).await.rest()?))
}

async fn inner_main(cli: Cli) -> anyhow::Result<()> {
	let datadir = PathBuf::from_str(&cli.datadir).unwrap();

	// No log file: the datadir's debug.log belongs to barkd.
	init_logging(cli.verbose, cli.quiet, &datadir, None, true);

	if env!("BARK_VERSION").contains(VERSION_DEV_MARKER) {
		warn!("You're running a custom build of bark, which might cause unexpected issues. \
			Consider building at one of the tagged versions or using the release builds.");
	}

	// The barkd lifecycle commands work without an authenticated client.
	match cli.command {
		Command::Status => return daemon::print_status(&datadir),
		_ => {},
	}

	// Talk to the default listen address unless --url overrides; either
	// way the bearer token comes from --token or the datadir.
	let url = match &cli.url {
		Some(url) => url.clone(),
		None => {
			daemon::require_up(&datadir)?;
			connect::base_url_for_datadir(&datadir)?
		},
	};
	let token = match cli.token.clone() {
		Some(token) => Some(token),
		None => connect::load_token(&datadir)?,
	};
	if token.is_none() {
		info!("No auth token in the datadir; assuming barkd runs without auth");
	}
	let config = connect::configuration(&url, token)?;

	if let Command::Create(opts) = cli.command {
		let req = create_opts_to_request(opts)?;
		// barkd refuses to create over a loaded wallet, so --force means
		// deleting that wallet first.
		if req.force {
			let existing = wallet_api::wallet_exists(&config).await.rest()
				.context("failed to check for an existing wallet")?;
			if let Some(fingerprint) = existing.fingerprint {
				warn!("Deleting the existing wallet (fingerprint {}); \
					any funds in it will be lost", fingerprint);
				let delete = models::WalletDeleteRequest { dangerous: true, fingerprint };
				wallet_api::wallet_delete(&config, delete).await.rest()
					.context("failed to delete the existing wallet")?;
			}
		}
		let resp = wallet_api::create_wallet(&config, req).await.rest()
			.context("failed to create wallet")?;
		info!("Wallet created (fingerprint {})", resp.fingerprint);
		return Ok(());
	}

	execute_command(cli.command, &config).await
}

#[tokio::main]
async fn main() {
	// bark-rest-client's rustls comes without a crypto provider, and reqwest
	// needs one to build any client, even for plain HTTP.
	#[cfg(any(feature = "tls-native-roots", feature = "tls-webpki-roots"))]
	let _ = rustls::crypto::ring::default_provider().install_default();

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
