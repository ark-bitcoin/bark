use std::time::Duration;

use anyhow::Context;
use clap;

use ark::VtxoId;
use bark::Wallet;
use bark::vtxo_selection::VtxoFilter;
use log::{warn, info};

use crate::util::output_json;


#[derive(clap::Subcommand)]
pub enum ExitCommand {
	/// To start an exit of a specific set of VTXO's or all offchain funds
	#[command()]
	Start(StartExitOpts),
	/// Progress the exit until it completes
	#[command()]
	Progress(ProgressExitOpts),
}

#[derive(clap::Args)]
pub struct StartExitOpts{
	/// A list of VtxoId's
	#[arg(long)]
	vtxos: Vec<VtxoId>,
	/// To exit all vtxo's
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
) -> anyhow::Result<()> {
	match exit_command {
		ExitCommand::Start(opts) => {
			start_exit(opts, wallet).await
		},
		ExitCommand::Progress(opts) => {
			progress_exit(opts, wallet).await
		},
	}
}

pub async fn start_exit(
	args: StartExitOpts,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	if !args.all && args.vtxos.len() == 0 {
		bail!("No exit to start. Use either the --vtxos or --all flag.")
	}
	info!("Starting onchain sync");
	if let Err(err) = wallet.onchain.sync().await {
		warn!("Failed to perform onchain sync: {}", err.to_string());
	}
	info!("Starting offchain sync");
	if let Err(err) = wallet.sync_ark().await {
		warn!("Failed to perform ark sync: {}", err.to_string());
	}
	info!("Starting exit");

	if args.all {
		wallet.exit.start_exit_for_entire_wallet(
			&mut wallet.onchain
		).await
	} else {
		let vtxo_ids = args.vtxos;
		let filter = VtxoFilter::new(wallet).include_many(vtxo_ids);
		let vtxos = wallet.vtxos_with(filter)
			.context("Error parsing vtxos")?;

		wallet.exit.start_exit_for_vtxos(
			&vtxos,
			&mut wallet.onchain,
		).await
	}
}

pub async fn progress_exit(
	args: ProgressExitOpts,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	if args.wait {
		loop {
			let exit_status = progress_once(wallet).await?;
			output_json(&exit_status);

			if exit_status.done {
				return Ok(())
			} else {
				info!("Sleeping for a minute, then will continue...");
				tokio::time::sleep(Duration::from_secs(60)).await;
			}
		}
	} else {
		let exit_status = progress_once(wallet).await?;
		output_json(&exit_status)
	};

	Ok(())
}

async fn progress_once(
	wallet: &mut Wallet,
) -> anyhow::Result<bark_json::cli::ExitStatus> {
	info!("Starting onchain sync");
	if let Err(error) = wallet.onchain.sync().await {
		warn!("Failed to perform onchain sync: {}", error)
	}
	info!("Starting sync exit");
	if let Err(error) = wallet.sync_exits().await {
		warn!("Failed to sync exits: {}", error);
	}
	info!("Wallet sync completed");
	info!("Start progressing exit");


	wallet.exit.progress_exit(&mut wallet.onchain).await
		.context("error making progress on exit process")?;

	let done = wallet.exit.list_pending_exits().await?.is_empty();
	let height = wallet.exit.all_spendable_at_height().await;

	Ok(
		bark_json::cli::ExitStatus { done, height }
	)
}
