use std::str::FromStr;

use anyhow::Context;
use bitcoin::hex::DisplayHex;
use bitcoin::Amount;
use clap;
use lightning_invoice::Bolt11Invoice;
use log::{info, warn};
use bark::{SqliteClient, Wallet};

#[derive(clap::Subcommand)]
pub enum LightningCommand {
	/// Pay a bolt11 invoice
	#[command()]
	Pay {
		/// The invoice to pay
		invoice: String,
		/// Conditionnally required if invoice doesn't have amount defined
		///
		/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
		amount: Option<Amount>,
		/// An optional comment
		comment: Option<String>,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},
}

pub async fn execute_lightning_command(
	lightning_command: LightningCommand,
	wallet: &mut Wallet<SqliteClient>,
) -> anyhow::Result<()> {
	match lightning_command {
		LightningCommand::Pay { invoice, amount, comment, no_sync } => {
			let invoice = Bolt11Invoice::from_str(&invoice)
				.context("argument is not a valid bolt11 invoice")?;

			pay(invoice, amount, comment, no_sync, wallet).await
		},
	}
}

pub async fn pay(
	invoice: Bolt11Invoice,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &mut Wallet<SqliteClient>,
) -> anyhow::Result<()> {
	let inv_amount = invoice.amount_milli_satoshis()
		.map(|v| Amount::from_sat(v.div_ceil(1000)));
	if let (Some(_), Some(inv)) = (amount, inv_amount) {
		bail!("Invoice has amount of {} encoded. Please omit amount argument", inv);
	}
	let final_amount = amount.or(inv_amount)
		.context("amount required on invoice without amount")?;
	if comment.is_some() {
		bail!("comment not supported for bolt11 invoice");
	}

	if !no_sync {
		info!("Syncing wallet...");
		if let Err(e) = wallet.sync_ark().await {
			warn!("Sync error: {}", e)
		}
	}

	info!("Sending bolt11 payment of {} to invoice {}", final_amount, invoice);
	let preimage = wallet.send_bolt11_payment(&invoice, amount).await?;
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(())
}
