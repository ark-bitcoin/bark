use std::time::Duration;

use anyhow::Context;
use bitcoin::{address, Address};
use clap;
use log::{warn, info};

use ark::VtxoId;
use bark::Wallet;
use bark::onchain::TxBuilderExt;
use bark::vtxo_selection::VtxoFilter;
use bark::onchain::OnchainWallet;

use crate::util::output_json;

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
}

#[derive(clap::Args)]
pub struct ListExitsOpts {
	/// Whether to include the detailed history of the exit process
	#[arg(long)]
	history: bool,

	/// Whether to include the exit transactions and their CPFP children
	#[arg(long)]
	transactions: bool,
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
}

pub async fn execute_exit_command(
	exit_command: ExitCommand,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	match exit_command {
		ExitCommand::Status(opts) => {
			get_exit_status(opts, wallet).await
		},
		ExitCommand::List(opts) => {
			list_exits(opts, wallet).await
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
	wallet: &Wallet,
) -> anyhow::Result<()> {
	match wallet.exit.get_exit_status(args.vtxo, args.history, args.transactions).await? {
		None => bail!("VTXO not found: {}", args.vtxo),
		Some(status) => output_json(&status),
	}
	Ok(())
}

pub async fn list_exits(
	args: ListExitsOpts,
	wallet: &Wallet,
) -> anyhow::Result<()> {
	let mut statuses = Vec::with_capacity(wallet.exit.get_exit_vtxos().len());
	for exit in wallet.exit.get_exit_vtxos() {
		statuses.push(wallet.exit.get_exit_status(
			exit.id(),
			args.history,
			args.transactions,
		).await?.unwrap());
	}
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
	if let Err(err) = wallet.sync().await {
		warn!("Failed to perform ark sync: {}", err.to_string());
	}
	info!("Starting exit");

	if args.all {
		wallet.exit.start_exit_for_entire_wallet(onchain).await
	} else {
		let vtxo_ids = args.vtxos;
		let filter = VtxoFilter::new(wallet).include_many(vtxo_ids);
		let vtxos = wallet.vtxos_with(filter)
			.context("Error parsing vtxos")?;

		wallet.exit.start_exit_for_vtxos(&vtxos, onchain).await
	}
}

pub async fn progress_exit(
	args: ProgressExitOpts,
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<()> {
	let exit_status = if args.wait {
		loop {
			let exit_status = progress_once(wallet, onchain).await?;
			if exit_status.done {
				break exit_status
			} else {
				info!("Sleeping for a minute, then will continue...");
				tokio::time::sleep(Duration::from_secs(60)).await;
			}
		}
	} else {
		progress_once(wallet, onchain).await?
	};
	output_json(&exit_status);
	Ok(())
}

async fn progress_once(
	wallet: &mut Wallet,
	onchain: &mut OnchainWallet,
) -> anyhow::Result<bark_json::cli::ExitProgressResponse> {
	info!("Starting onchain sync");
	if let Err(error) = onchain.sync(&wallet.chain).await {
		warn!("Failed to perform onchain sync: {}", error)
	}
	info!("Wallet sync completed");
	info!("Start progressing exit");

	let result = wallet.exit.progress_exit(onchain).await
		.context("error making progress on exit process")?;

	let done = !wallet.exit.has_pending_exits();
	let spendable_height = wallet.exit.all_spendable_at_height().await;
	let exits = result.unwrap_or_default();
	Ok(bark_json::cli::ExitProgressResponse { done, spendable_height, exits, })
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
		if let Err(e) = wallet.sync().await {
			warn!("Sync error: {}", e)
		}
		if let Err(e) = onchain.sync(&wallet.chain).await {
			warn!("Sync error: {}", e)
		}
	}

	let network = wallet.properties()?.network;
	let address = address.require_network(network).with_context(|| {
		format!("address is not valid for configured network {}", network)
	})?;

	let psbt = match (vtxos, all) {
		(Some(vtxo_ids), false) => {
			let vtxos = wallet.exit.list_spendable()?
				.into_iter()
				.filter(|v| vtxo_ids.contains(&v.id().to_string()))
				.collect::<Vec<_>>();

			let mut tx_builder = onchain.build_tx();
			tx_builder.add_exit_claim_inputs(&vtxos)?;
			tx_builder.drain_to(address.script_pubkey());

			let mut psbt = tx_builder.finish()?;
			wallet.exit.sign_exit_claim_inputs(&mut psbt, wallet)?;
			Ok(psbt)
		},
		(None, true) => {
			let fee_rate = wallet.chain.fee_rates().await.regular;
			wallet.exit.drain_spendable_outputs(&wallet, address, fee_rate)
		},
		(None, false) => bail!("Either --vtxo or --all must be specified"),
		(Some(_), true) => bail!("Cannot specify both --vtxo and --all"),
	}?;

	let tx = psbt.extract_tx()?;

	wallet.chain.broadcast_tx(&tx).await?;
	info!("Drain transaction broadcasted: {}", tx.compute_txid());

	Ok(())
}