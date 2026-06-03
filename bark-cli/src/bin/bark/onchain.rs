
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::{address, Amount};
use log::{info, warn};

use bark::Wallet;
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bark_json::{cli as json, primitives};
use bark_cli::util::output_json;


/// Cast an [OnchainWalletTrait] to an [OnchainWallet]
fn cast_bdk(w: &dyn OnchainWalletTrait) -> anyhow::Result<&OnchainWallet> {
	(w as &dyn std::any::Any).downcast_ref::<OnchainWallet>()
		.context("onchain wallet is not a BDK wallet")
}

/// Cast a mutable [OnchainWalletTrait] to an [OnchainWallet]
fn cast_bdk_mut(w: &mut dyn OnchainWalletTrait) -> anyhow::Result<&mut OnchainWallet> {
	(w as &mut dyn std::any::Any).downcast_mut::<OnchainWallet>()
		.context("onchain wallet is not a BDK wallet")
}

#[derive(clap::Subcommand)]
pub enum OnchainCommand {
	/// Get the on-chain balance
	#[command()]
	Balance {
		/// Skip syncing before computing balance
		#[arg(long)]
		no_sync: bool,
	},

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
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
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

		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// Send all wallet funds to provided destination
	#[command()]
	Drain {
		destination: bitcoin::Address<address::NetworkUnchecked>,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},

	/// List our wallet's UTXOs
	#[command()]
	Utxos {
		/// Skip syncing before fetching UTXOs
		#[arg(long)]
		no_sync: bool,
	},

	/// List our wallet's transactions
	#[command()]
	Transactions {
		/// Skip syncing before fetching transactions
		#[arg(long)]
		no_sync: bool,
	},
}

pub async fn execute_onchain_command(onchain_command: OnchainCommand, wallet: &Wallet) -> anyhow::Result<()> {
	let net = wallet.network().await?;
	let onchain = wallet.onchain().context("no onchain wallet configured")?;

	match onchain_command {
		OnchainCommand::Balance { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Onchain sync error: {}", e)
				}
			}

			let guard = onchain.read().await;
			let balance = cast_bdk(&*guard)?.balance();
			let onchain_balance = json::onchain::OnchainBalance::from(balance);
			output_json(&onchain_balance);
		},
		OnchainCommand::Address => {
			let address = onchain.write().await.address().await?;
			let output = json::onchain::Address { address: address.into_unchecked() };
			output_json(&output);
		},
		OnchainCommand::Send { destination: address, amount, no_sync } => {
			let addr = address.require_network(net).with_context(|| {
				format!("address is not valid for configured network {}", net)
			})?;

			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Sync error: {}", e)
				}
			}

			let fee_rate = wallet.chain().fee_rates().await.regular;
			let txid = cast_bdk_mut(&mut *onchain.write().await)?.send(wallet.chain(), addr, amount, fee_rate).await?;

			let output = json::onchain::Send { txid };
			output_json(&output);
		},
		OnchainCommand::Drain { destination: address, no_sync } => {
			let addr = address.require_network(net).with_context(|| {
				format!("address is not valid for configured network {}", net)
			})?;

			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Sync error: {}", e)
				}
			}

			let fee_rate = wallet.chain().fee_rates().await.regular;
			let txid = cast_bdk_mut(&mut *onchain.write().await)?.drain(wallet.chain(), addr, fee_rate).await?;

			let output = json::onchain::Send { txid };
			output_json(&output);
		},
		OnchainCommand::SendMany { destinations, immediate, no_sync } => {
			let outputs = destinations
				.iter()
				.map(|dest| -> anyhow::Result<(bitcoin::Address, Amount)> {
					let mut parts = dest.splitn(2, ':');
					let addr = {
						let s = parts.next()
							.context("invalid destination format, expected address:amount")?;
						bitcoin::Address::from_str(s)?.require_network(net)
							.with_context(|| format!("invalid address: '{}'", s))?
					};
					let amount = {
						let s = parts.next()
							.context("invalid destination format, expected address:amount")?;
						Amount::from_str(s)
							.with_context(|| format!("invalid amount: '{}'", s))?
					};
					Ok((addr, amount))
				})
				.collect::<Result<Vec<_>, _>>()?;

			info!("Attempting to send the following:");
			for (address, amount) in &outputs {
				info!("{} to {}", amount, address);
			}

			if !immediate {
				info!("Will continue after 10 seconds...");
				tokio::time::sleep(Duration::from_secs(10)).await;
			}

			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Sync error: {}", e)
				}
			}

			let fee_rate = wallet.chain().fee_rates().await.regular;
			let txid = cast_bdk_mut(&mut *onchain.write().await)?.send_many(wallet.chain(), &outputs, fee_rate).await?;

			let output = json::onchain::Send { txid };
			output_json(&output);
		},
		OnchainCommand::Utxos { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Sync error: {}", e)
				}
			}

			let guard = onchain.read().await;
			let utxos = cast_bdk(&*guard)?.utxos()
				.into_iter()
				.map(primitives::UtxoInfo::from)
				.collect::<Vec<_>>();

			output_json(&utxos);
		},
		OnchainCommand::Transactions { no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				if let Err(e) = onchain.write().await.sync(wallet.chain()).await {
					warn!("Sync error: {}", e)
				}
			}

			let guard = onchain.read().await;
			let mut transactions = cast_bdk(&*guard)?.list_transaction_infos()?;
			// transactions are ordered from newest to oldest,
			// so we reverse them so last terminal item is newest
			transactions.reverse();

			let transactions = transactions.into_iter()
				.map(primitives::WalletTxInfo::from)
				.collect::<Vec<_>>();

			output_json(&transactions);
		},
	}

	Ok(())
}
