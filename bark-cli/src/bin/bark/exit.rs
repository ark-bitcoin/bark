use std::collections::HashSet;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bitcoin::{address, Address, FeeRate};
use clap;
use log::{warn, info};

use ark::VtxoId;
use bark::Wallet;
use bark::onchain::{ChainSync, OnchainWallet};
use bark::vtxo::{FilterVtxos, VtxoFilter};
use bark_json::cli::{ExitProgressStatus, ExitTransactionStatus};
use bitcoin_ext::FeeRateExt;

use bark_cli::util::output_json;

#[derive(clap::Subcommand)]
pub enum ExitCommand {
	/// Gets the current status for the given VTXO
	#[command()]
	Status(StatusExitOpts),
	/// Lists every in-progress, completed and failed exit
	#[command()]
	List(ListExitsOpts),
	/// To start an exit of a specific set of VTXO's or all offchain funds
	#[command()]
	Start(StartExitOpts),
	/// Progress the exit until it completes
	#[command()]
	Progress(ProgressExitOpts),
	/// Claim exited VTXOs
	#[command()]
	Claim {
		destination: Address<address::NetworkUnchecked>,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
		/// The ID of an exited VTXO to be claimed, can be specified multiple times.
		#[arg(long = "vtxo", value_name = "VTXO_ID")]
		vtxos: Option<Vec<String>>,
		/// Claim all exited VTXOs
		#[arg(long)]
		all: bool,
	},
}

#[derive(clap::Args)]
pub struct StatusExitOpts {
	/// The VTXO to check the exit status of
	vtxo: VtxoId,

	/// Whether to include the detailed history of the exit process
	#[arg(long)]
	history: bool,

	/// Whether to include the exit transactions and their CPFP children
	#[arg(long)]
	transactions: bool,

	/// Skip syncing wallet
	#[arg(long)]
	no_sync: bool,
}

#[derive(clap::Args)]
pub struct ListExitsOpts {
	/// Whether to include the detailed history of the exit process
	#[arg(long)]
	history: bool,

	/// Whether to include the exit transactions and their CPFP children
	#[arg(long)]
	transactions: bool,

	/// Skip syncing wallet
	#[arg(long)]
	no_sync: bool,
}

#[derive(clap::Args)]
pub struct StartExitOpts{
	/// The ID of a VTXO to unilaterally exit, can be specified multiple times.
	#[arg(long = "vtxo", value_name = "VTXO_ID")]
	vtxos: Vec<VtxoId>,
	/// Whether to exit all VTXO's, either this or --vtxo must be specificed
	#[arg(long)]
	all: bool,
}

#[derive(clap::Args)]
pub struct ProgressExitOpts {
	/// Wait until the exit is completed
	/// This might take several hours or days.
	#[arg(long)]
	wait: bool,
	/// Sets the desired fee-rate in sats/kvB to use broadcasting exit transactions. Note that due
	/// to rules imposed by the network with regard to RBF fee bumping, replaced transactions may
	/// have a slightly higher fee rate than you specify here.
	///
	/// Example for 1 sat/vB: --fee-rate 1000
	#[arg(long)]
	fee_rate: Option<u64>,
}

pub async fn execute_exit_command(
	exit_command: ExitCommand,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	match exit_command {
		ExitCommand::Status(opts) => {
			get_exit_status(opts, wallet, onchain).await
		},
		ExitCommand::List(opts) => {
			list_exits(opts, wallet, onchain).await
		},
		ExitCommand::Start(opts) => {
			start_exit(opts, wallet, onchain).await
		},
		ExitCommand::Progress(opts) => {
			progress_exit(opts, wallet, onchain).await
		},
		ExitCommand::Claim { destination, no_sync, vtxos, all } => {
			claim_exits(destination, no_sync, vtxos, all, wallet, onchain).await
		},
	}
}

pub async fn get_exit_status(
	args: StatusExitOpts,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	if !args.no_sync {
		info!("Starting exit sync");
		wallet.sync_exits(onchain).await?;
	}

	match wallet.exit.get_mut().get_exit_status(args.vtxo, args.history, args.transactions).await? {
		None => bail!("VTXO not found: {}", args.vtxo),
		Some(status) => output_json(&ExitTransactionStatus::from(status)),
	}
	Ok(())
}

pub async fn list_exits(
	args: ListExitsOpts,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	if !args.no_sync {
		info!("Starting exit sync");
		wallet.sync_exits(onchain).await?;
	}

	let exit = wallet.exit.get_mut();
	let mut statuses = Vec::with_capacity(exit.get_exit_vtxos().len());
	for e in exit.get_exit_vtxos() {
		statuses.push(exit.get_exit_status(
			e.id(),
			args.history,
			args.transactions,
		).await?.unwrap());
	}

	let statuses = statuses.into_iter()
		.map(ExitTransactionStatus::from).collect::<Vec<_>>();

	output_json(&statuses);
	Ok(())
}

pub async fn start_exit(
	args: StartExitOpts,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	if !args.all && args.vtxos.is_empty() {
		bail!("No exit to start. Use either the --vtxo or --all flag.")
	}
	info!("Starting onchain sync");
	if let Err(err) = onchain.sync(&wallet.chain).await {
		warn!("Failed to perform onchain sync: {}", err.to_string());
	}
	info!("Starting offchain sync");
	wallet.sync().await;
	info!("Starting exit");

	if args.all {
		wallet.exit.get_mut().start_exit_for_entire_wallet().await
	} else {
		let filter = VtxoFilter::new(wallet).include_many(args.vtxos);

		let spendable = wallet.spendable_vtxos_with(&filter).await
			.context("Error parsing vtxos")?;
		let inround = {
			let mut buf = wallet.pending_round_input_vtxos().await?;
			filter.filter_vtxos(&mut buf).await?;
			buf
		};

		let vtxos = spendable.into_iter().chain(inround)
			.map(|v| v.vtxo).collect::<Vec<_>>();

		wallet.exit.get_mut().start_exit_for_vtxos(&vtxos).await
	}
}

pub async fn progress_exit(
	args: ProgressExitOpts,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	let fee_rate = args.fee_rate.map(FeeRate::from_sat_per_kvb_ceil);
	let exit_status = if args.wait {
		loop {
			let exit_status = progress_once(wallet, onchain, fee_rate).await?;
			if exit_status.done {
				break exit_status
			} else {
				info!("Sleeping for a minute, then will continue...");
				tokio::time::sleep(Duration::from_secs(60)).await;
			}
		}
	} else {
		progress_once(wallet, onchain, fee_rate).await?
	};
	output_json(&exit_status);
	Ok(())
}

async fn progress_once(
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
	fee_rate: Option<FeeRate>,
) -> anyhow::Result<bark_json::cli::ExitProgressResponse> {
	info!("Starting onchain sync");
	if let Err(error) = onchain.sync(&wallet.chain).await {
		warn!("Failed to perform onchain sync: {}", error)
	}
	info!("Wallet sync completed");
	info!("Start progressing exit");

	let mut exit = wallet.exit.write().await;
	exit.sync_no_progress(onchain).await.context("unable to sync exit process")?;
	let result = exit.progress_exits(wallet, onchain, fee_rate).await
		.context("error making progress on exit process")?;

	let done = !exit.has_pending_exits();
	let claimable_height = exit.all_claimable_at_height().await;
	let exits = result.unwrap_or_default()
		.into_iter().map(ExitProgressStatus::from).collect::<Vec<_>>();

	Ok(bark_json::cli::ExitProgressResponse { done, claimable_height, exits, })
}

pub async fn claim_exits(
	address: Address<address::NetworkUnchecked>,
	no_sync: bool,
	vtxos: Option<Vec<String>>,
	all: bool,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	if !no_sync {
		info!("Syncing wallet...");
		wallet.sync().await;
		if let Err(e) = onchain.sync(&wallet.chain).await {
			warn!("Sync error: {}", e)
		}
	}

	let network = wallet.network().await?;
	let address = address.require_network(network).with_context(|| {
		format!("address is not valid for configured network {}", network)
	})?;

	let exit = wallet.exit.read().await;
	let vtxos = match (vtxos, all) {
		(Some(vtxo_ids), false) => {
			let mut vtxo_ids = vtxo_ids.iter().map(|s| {
				VtxoId::from_str(s).with_context(|| format!("invalid vtxo id: {}", s))
			}).collect::<anyhow::Result<HashSet<_>>>()?;
			let vtxos = exit.list_claimable().into_iter()
				.filter(|v| vtxo_ids.remove(&v.id()))
				.collect::<Vec<_>>();
			for id in vtxo_ids {
				bail!("Unspendable VTXO provided: {}", id);
			}
			vtxos
		},
		(None, true) => exit.list_claimable(),
		(None, false) => bail!("Either --vtxo or --all must be specified"),
		(Some(_), true) => bail!("Cannot specify both --vtxo and --all"),
	};

	let address_spk = address.script_pubkey();

	let fee_rate = wallet.chain.fee_rates().await.regular;
	let psbt = exit.drain_exits(&vtxos, &wallet, address, Some(fee_rate)).await.unwrap();
	let tx = psbt.extract_tx()?;
	wallet.chain.broadcast_tx(&tx).await?;
	info!("Drain transaction broadcasted: {}", tx.compute_txid());

	// Commit the transaction to the wallet if the claim destination is ours
	if onchain.is_mine(address_spk) {
		info!("Adding claim transaction to wallet: {}", tx.compute_txid());
		let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
		onchain.apply_unconfirmed_txs([(tx, timestamp)]);
	}
	Ok(())
}
