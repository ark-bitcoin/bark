use bark_cli::util::output_json;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::wallet_api;

use crate::connect::RestResultExt;

#[derive(clap::Subcommand)]
pub enum RoundCommand {
	/// list pending round participations
	#[command()]
	List,
}

pub async fn execute_round_command(
	round_command: RoundCommand,
	config: &Configuration,
) -> anyhow::Result<()> {
	match round_command {
		RoundCommand::List => {
			let rounds = wallet_api::pending_rounds(config).await.rest()?;
			output_json(&rounds);
		},
	}

	Ok(())
}
