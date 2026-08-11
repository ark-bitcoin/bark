use bitcoin::{address, Amount};

use bark_cli::util::output_json;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::onchain_api;
use bark_rest_client::models;

use crate::addr_string;
use crate::connect::RestResultExt;

#[derive(clap::Subcommand)]
pub enum OnchainCommand {
	/// Get the on-chain balance
	#[command()]
	Balance,

	/// Get an on-chain address
	#[command()]
	Address,

	/// Send using the on-chain wallet
	#[command()]
	Send {
		destination: bitcoin::Address<address::NetworkUnchecked>,
		/// Amount to send
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any
		/// amount denomination. Example: `250000 sats`.
		amount: Amount,
	},

	#[command(
		about = "\
			Send using the on-chain wallet to multiple destinations. \n\
			Example usage: send-many --destination bc1pfq...:10000sat --destination bc1pke...:20000sat\n\
			This will send 10,000 sats to bc1pfq... and 20,000 sats to bc1pke...",
	)]
	SendMany {
		/// Adds an output to the given address, this can be specified multiple times.
		/// The format is address:amount, e.g. bc1pfq...:10000sat
		#[arg(long = "destination", required = true)]
		destinations: Vec<String>,

		/// Sends the transaction immediately instead of printing the summary before continuing
		#[arg(long)]
		immediate: bool,
	},

	/// Send all wallet funds to provided destination
	#[command()]
	Drain {
		destination: bitcoin::Address<address::NetworkUnchecked>,
	},

	/// List our wallet's UTXOs
	#[command()]
	Utxos,

	/// List our wallet's transactions
	#[command()]
	Transactions,
}

pub async fn execute_onchain_command(
	onchain_command: OnchainCommand,
	config: &Configuration,
) -> anyhow::Result<()> {
	match onchain_command {
		OnchainCommand::Balance => {
			let balance = onchain_api::onchain_balance(config).await.rest()?;
			output_json(&balance);
		},
		OnchainCommand::Address => {
			let address = onchain_api::onchain_address(config).await.rest()?;
			output_json(&address);
		},
		OnchainCommand::Send { destination, amount } => {
			let req = models::OnchainSendRequest {
				destination: addr_string(destination),
				amount_sat: amount.to_sat(),
			};
			let resp = onchain_api::onchain_send(config, req).await.rest()?;
			output_json(&resp);
		},
		OnchainCommand::SendMany { destinations, immediate } => {
			let req = models::OnchainSendManyRequest {
				destinations,
				immediate: Some(immediate),
			};
			let resp = onchain_api::onchain_send_many(config, req).await.rest()?;
			output_json(&resp);
		},
		OnchainCommand::Drain { destination } => {
			let req = models::OnchainDrainRequest { destination: addr_string(destination) };
			let resp = onchain_api::onchain_drain(config, req).await.rest()?;
			output_json(&resp);
		},
		OnchainCommand::Utxos => {
			let utxos = onchain_api::onchain_utxos(config).await.rest()?;
			output_json(&utxos);
		},
		OnchainCommand::Transactions => {
			let transactions = onchain_api::onchain_transactions(config).await.rest()?;
			output_json(&transactions);
		},
	}
	Ok(())
}
