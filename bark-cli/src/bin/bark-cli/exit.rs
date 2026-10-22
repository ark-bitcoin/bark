use std::time::Duration;

use bitcoin::{address, Address};
use log::info;

use ark::VtxoId;
use bark_cli::util::output_json;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::exits_api;
use bark_rest_client::models;

use crate::addr_string;
use crate::connect::RestResultExt;

#[derive(clap::Subcommand)]
pub enum ExitCommand {
	/// Gets the current status for the given VTXO
	#[command()]
	Status(StatusExitOpts),
	/// Lists unilateral exits
	#[command()]
	List(ListExitsOpts),
	/// To start an exit of a specific set of VTXO's or all offchain funds
	#[command()]
	Start(StartExitOpts),
	/// Progress the exit until it completes
	#[command()]
	Progress(ProgressExitOpts),
	/// Cancel a unilateral exit that hasn't broadcast its final transaction yet
	#[command()]
	Cancel(CancelExitOpts),
	/// Claim exited VTXOs
	#[command()]
	Claim {
		destination: Address<address::NetworkUnchecked>,
		/// The ID of an exited VTXO to be claimed, can be specified multiple times.
		#[arg(long = "vtxo", value_name = "VTXO_ID")]
		vtxos: Option<Vec<String>>,
		/// Claim all exited VTXOs
		#[arg(long)]
		all: bool,
	},
	/// Estimate the on-chain fees to unilaterally (emergency) exit a set of VTXOs
	#[command()]
	EstimateFee(EstimateFeeOpts),
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

	/// Also include exits that reached a terminal state: claimed, aborted because the VTXO
	/// was already spent, or canceled.
	#[arg(long)]
	include_finished: bool,
}

#[derive(clap::Args)]
pub struct CancelExitOpts {
	/// The VTXO whose unilateral exit should be canceled
	vtxo: VtxoId,
}

#[derive(clap::Args)]
pub struct StartExitOpts {
	/// The ID of a VTXO to unilaterally exit, can be specified multiple times.
	#[arg(long = "vtxo", value_name = "VTXO_ID")]
	vtxos: Vec<VtxoId>,
	/// Whether to exit all VTXO's, either this or --vtxo must be specificed
	#[arg(long)]
	all: bool,
}

#[derive(clap::Args)]
pub struct EstimateFeeOpts {
	/// The ID of a VTXO to estimate the exit for, can be specified multiple times.
	#[arg(long = "vtxo", value_name = "VTXO_ID")]
	vtxos: Vec<VtxoId>,
	/// Estimate exiting all VTXOs, either this or --vtxo must be specified
	#[arg(long)]
	all: bool,
	/// Sets the desired fee-rate in sats/kvB to price the estimate. Defaults to the
	/// fast rate for broadcast and the regular rate for claim.
	///
	/// Example for 1 sat/vB: --fee-rate 1000
	#[arg(long)]
	fee_rate: Option<u64>,
	/// The claim destination address. Only affects the claim-fee weight; a placeholder is used
	/// when omitted.
	#[arg(long)]
	destination: Option<Address<address::NetworkUnchecked>>,
	/// Scales the broadcast leg to cover fee-rate movement and UTXO consolidation.
	/// Must be finite and non-negative. Defaults to 1.2.
	#[arg(long)]
	fee_margin: Option<f64>,
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
	config: &Configuration,
) -> anyhow::Result<()> {
	match exit_command {
		ExitCommand::Status(opts) => {
			get_exit_status(opts, config).await
		},
		ExitCommand::List(opts) => {
			list_exits(opts, config).await
		},
		ExitCommand::Start(opts) => {
			start_exit(opts, config).await
		},
		ExitCommand::Progress(opts) => {
			progress_exit(opts, config).await
		},
		ExitCommand::Cancel(opts) => {
			cancel_exit(opts, config).await
		},
		ExitCommand::Claim { destination, vtxos, all } => {
			claim_exits(destination, vtxos, all, config).await
		},
		ExitCommand::EstimateFee(opts) => {
			estimate_exit_fee(opts, config).await
		},
	}
}

/// Cancels a unilateral exit while it's still in its abortable window. We deliberately don't sync
/// or progress first: that could broadcast the exit transactions and defeat the cancellation.
pub async fn cancel_exit(
	args: CancelExitOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	let resp = exits_api::exit_cancel(config, &args.vtxo.to_string()).await.rest()?;
	info!("{}", resp.message);
	Ok(())
}

pub async fn get_exit_status(
	args: StatusExitOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	let status = exits_api::get_exit_status_by_vtxo_id(
		config, &args.vtxo.to_string(), Some(args.history), Some(args.transactions),
	).await.rest()?;
	output_json(&status);
	Ok(())
}

pub async fn list_exits(
	args: ListExitsOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	let statuses = if args.include_finished {
		exits_api::get_all_exit_status(
			config, Some(args.history), Some(args.transactions),
		).await.rest()?
	} else {
		exits_api::get_live_exit_status(
			config, Some(args.history), Some(args.transactions),
		).await.rest()?
	};
	output_json(&statuses);
	Ok(())
}

pub async fn start_exit(
	args: StartExitOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	if !args.all && args.vtxos.is_empty() {
		bail!("No exit to start. Use either the --vtxo or --all flag.")
	}
	let resp = if args.all {
		exits_api::exit_start_all(config).await.rest()?
	} else {
		let vtxos = args.vtxos.iter().map(|v| v.to_string()).collect();
		let req = models::ExitStartRequest { vtxos };
		exits_api::exit_start_vtxos(config, req).await.rest()?
	};
	info!("{}", resp.message);
	Ok(())
}

pub async fn progress_exit(
	args: ProgressExitOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	let exit_status = if args.wait {
		loop {
			let exit_status = progress_once(config, args.fee_rate).await?;
			if exit_status.done {
				break exit_status
			} else {
				info!("Sleeping for a minute, then will continue...");
				tokio::time::sleep(Duration::from_secs(60)).await;
			}
		}
	} else {
		progress_once(config, args.fee_rate).await?
	};
	output_json(&exit_status);
	Ok(())
}

async fn progress_once(
	config: &Configuration,
	fee_rate: Option<u64>,
) -> anyhow::Result<models::ExitProgressResponse> {
	let req = models::ExitProgressRequest { wait: None, fee_rate };
	exits_api::exit_progress(config, req).await.rest()
}

pub async fn claim_exits(
	address: Address<address::NetworkUnchecked>,
	vtxos: Option<Vec<String>>,
	all: bool,
	config: &Configuration,
) -> anyhow::Result<()> {
	let resp = match (vtxos, all) {
		(Some(vtxos), false) => {
			let req = models::ExitClaimVtxosRequest {
				destination: addr_string(address),
				vtxos,
				fee_rate: None,
			};
			exits_api::exit_claim_vtxos(config, req).await.rest()?
		},
		(None, true) => {
			let req = models::ExitClaimAllRequest {
				destination: addr_string(address),
				fee_rate: None,
			};
			exits_api::exit_claim_all(config, req).await.rest()?
		},
		(None, false) => bail!("Either --vtxo or --all must be specified"),
		(Some(_), true) => bail!("Cannot specify both --vtxo and --all"),
	};
	info!("{}", resp.message);
	Ok(())
}

pub async fn estimate_exit_fee(
	opts: EstimateFeeOpts,
	config: &Configuration,
) -> anyhow::Result<()> {
	// The endpoint takes the IDs as one comma-separated query param and
	// omitting it means estimating all spendable VTXOs.
	let vtxo_ids = match (opts.vtxos.is_empty(), opts.all) {
		(false, false) => Some(opts.vtxos.iter()
			.map(|v| v.to_string()).collect::<Vec<_>>().join(",")),
		(true, true) => None,
		(true, false) => bail!("Either --vtxo or --all must be specified"),
		(false, true) => bail!("Cannot specify both --vtxo and --all"),
	};
	let fee_rate = opts.fee_rate.map(|kvb| kvb as f64 / 1000.0);
	let destination = opts.destination.map(addr_string);
	let resp = exits_api::emergency_exit_fee(
		config, vtxo_ids.as_deref(), fee_rate, destination.as_deref(), opts.fee_margin,
	).await.rest()?;
	output_json(&resp);
	Ok(())
}
