
use clap;

use bark::Wallet;
use bark::persist::models::RoundStateId;
use bark_json as json;

use bark_cli::util::output_json;


#[derive(clap::Subcommand)]
pub enum RoundCommand {
	/// cancel a pending round
	#[command()]
	Cancel {
		#[clap(long)]
		round: Option<u32>,
		#[clap(long)]
		all: bool,
	},
	/// progress all rounds
	#[command()]
	Progress {
		/// keep continuing until finished
		#[clap(long = "continue")]
		cont: bool,
	},
	/// list pending round participations
	#[command()]
	List,
}

pub async fn execute_round_command(
	cmd: RoundCommand,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	match cmd {
		RoundCommand::Cancel { round, all } => {
			if all {
				wallet.cancel_all_pending_rounds().await?;
			} else if let Some(id) = round {
				wallet.cancel_pending_round(RoundStateId(id)).await?;
			} else {
				bail!("must provide either a round id or --all");
			}
		},
		RoundCommand::Progress { cont } => {
			if cont {
				wallet.participate_ongoing_rounds().await?;
			} else {
				wallet.progress_pending_rounds(None).await?;
			}
			//TODO(stevenroose) consider printing statuses afterwards
		},
		RoundCommand::List => {
			let infos = wallet.pending_round_states().await?.iter()
				.map(json::web::PendingRoundInfo::from_state)
				.collect::<Vec<_>>();
			output_json(&infos);
		},
	}

	Ok(())
}

