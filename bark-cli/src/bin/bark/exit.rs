use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

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

	/// Also include exits that reached a terminal state: claimed, aborted because the VTXO
	/// was already spent, or canceled.
	#[arg(long)]
	include_finished: bool,

	/// Skip syncing wallet
	#[arg(long)]
	no_sync: bool,
}

#[derive(clap::Args)]
pub struct CancelExitOpts {
	/// The VTXO whose unilateral exit should be canceled
	vtxo: VtxoId,
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
		ExitCommand::Cancel(opts) => {
			cancel_exit(opts, wallet).await
		},
		ExitCommand::Claim { destination, no_sync, vtxos, all } => {
			claim_exits(destination, no_sync, vtxos, all, wallet, onchain).await
		},
	}
}

/// Cancels a unilateral exit while it's still in its abortable window. We deliberately don't sync
/// or progress first: that could broadcast the exit transactions and defeat the cancellation.
pub async fn cancel_exit(
	args: CancelExitOpts,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	wallet.exit_mgr().cancel_exit(args.vtxo).await?;
	info!("Canceled unilateral exit for VTXO {}", args.vtxo);
	Ok(())
}

pub async fn get_exit_status(
	args: StatusExitOpts,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	if !args.no_sync {
		info!("Starting exit sync");
		wallet.sync_exits().await?;
	}

	match wallet.exit_mgr().get_exit_status(args.vtxo, args.history, args.transactions).await? {
		None => bail!("VTXO not found: {}", args.vtxo),
		Some(status) => output_json(&ExitTransactionStatus::from(status)),
	}
	Ok(())
}

pub async fn list_exits(
	args: ListExitsOpts,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	if !args.no_sync {
		info!("Starting exit sync");
		wallet.sync_exits().await?;
	}

	let mut statuses = wallet.exit_mgr().list_live(args.history, args.transactions).await?
		.into_iter().map(ExitTransactionStatus::from).collect::<Vec<_>>();

	if args.include_finished {
		statuses.extend(
			wallet.exit_mgr().list_finished(args.history, args.transactions).await?
				.into_iter().map(ExitTransactionStatus::from),
		);
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
	if let Err(err) = onchain.sync(wallet.chain()).await {
		warn!("Failed to perform onchain sync: {}", err.to_string());
	}
	info!("Starting offchain sync");
	wallet.sync().await;
	info!("Starting exit");

	if args.all {
		wallet.exit_mgr().start_exit_for_entire_wallet().await
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

		wallet.exit_mgr().start_exit_for_vtxos(&vtxos).await
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
	if let Err(error) = onchain.sync(wallet.chain()).await {
		warn!("Failed to perform onchain sync: {}", error)
	}
	info!("Wallet sync completed");
	info!("Start progressing exit");

	// If progress fails at a level that isn't attributable to a specific exit (e.g. the
	// chain source going away), surface it on the response rather than blowing up the CLI
	// with a plain stderr message. Callers that scrape the JSON output (tests, scripts)
	// can then react to known transient errors and retry.
	let progress_result = wallet.exit_mgr()
		.progress_exits_with_bdk(wallet, onchain, fee_rate).await;

	let done = !wallet.exit_mgr().has_pending_exits().await;
	let claimable_height = wallet.exit_mgr().all_claimable_at_height().await;

	let (exits, error) = match progress_result {
		Ok(result) => {
			let exits = result.unwrap_or_default()
				.into_iter().map(ExitProgressStatus::from).collect::<Vec<_>>();
			(exits, None)
		},
		Err(e) => {
			warn!("Exit progress failed: {:#}", e);
			// Walk the anyhow chain to recover the typed ExitError if present so the
			// caller can match on the variant rather than parsing a free-form string.
			let exit_err = e.chain()
				.find_map(|cause| cause.downcast_ref::<bark::exit::ExitError>())
				.cloned()
				.map(bark_json::exit::error::ExitError::from)
				.unwrap_or_else(|| bark_json::exit::error::ExitError::InternalError {
					error: format!("{:#}", e),
				});
			(Vec::new(), Some(exit_err))
		},
	};

	Ok(bark_json::cli::ExitProgressResponse { done, claimable_height, exits, error })
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
		if let Err(e) = onchain.sync(wallet.chain()).await {
			warn!("Sync error: {}", e)
		}
	}

	let network = wallet.network().await?;
	let address = address.require_network(network).with_context(|| {
		format!("address is not valid for configured network {}", network)
	})?;

	let claimable = wallet.exit_mgr().list_claimable().await;
	let vtxos = match (vtxos, all) {
		(Some(vtxo_ids), false) => {
			let mut vtxo_ids = vtxo_ids.iter().map(|s| {
				VtxoId::from_str(s).with_context(|| format!("invalid vtxo id: {}", s))
			}).collect::<anyhow::Result<HashSet<_>>>()?;
			let vtxos = claimable.into_iter()
				.filter(|v| vtxo_ids.remove(&v.id()))
				.collect::<Vec<_>>();
			for id in vtxo_ids {
				bail!("Unspendable VTXO provided: {}", id);
			}
			vtxos
		},
		(None, true) => claimable,
		(None, false) => bail!("Either --vtxo or --all must be specified"),
		(Some(_), true) => bail!("Cannot specify both --vtxo and --all"),
	};

	let address_spk = address.script_pubkey();

	let fee_rate = wallet.chain().fee_rates().await.regular;
	let psbt = wallet.exit_mgr().drain_exits(&vtxos, &wallet, address, Some(fee_rate)).await.unwrap();
	let tx = psbt.extract_tx()?;
	wallet.chain().broadcast_tx(&tx).await?;
	info!("Drain transaction broadcasted: {}", tx.compute_txid());

	// Commit the transaction to the wallet if the claim destination is ours
	if onchain.is_mine(address_spk) {
		info!("Adding claim transaction to wallet: {}", tx.compute_txid());
		onchain.apply_unconfirmed_txs([(tx, bark::time::timestamp_secs())]);
	}
	Ok(())
}
