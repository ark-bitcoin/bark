use std::str::FromStr;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::hex::DisplayHex;
use clap;
use lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use log::{info, warn};

use ark::lightning::{Invoice, PaymentHash, Preimage};
use bark::Wallet;
use bark_json::InvoiceInfo;

use crate::util::output_json;

#[derive(clap::Subcommand)]
pub enum LightningCommand {
	/// pay a bolt11 invoice
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
	/// creates a bolt11 invoice with the provided amount
	///
	/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
	#[command()]
	Invoice {
		amount: Amount,
		/// Wait for the incoming payment to settle
		#[arg(long)]
		wait: bool,
	},
	/// get the status of an invoice
	#[command()]
	Status {
		/// payment hash or invoice string
		filter: Option<String>,
		/// filter by preimage
		#[arg(long)]
		preimage: Option<Preimage>,
	},
	/// list all generated invoices
	#[command()]
	Invoices,
	/// claim the receipt of an invoice
	#[command()]
	Claim {
		/// payment hash or invoice to claim; claiming all pending payments if absent
		payment: Option<String>,
		/// Wait for the incoming payment to settle
		#[arg(long)]
		wait: bool,
	},
}

fn payment_hash_from_filter(filter: &str) -> anyhow::Result<PaymentHash> {
	if let Ok(h) = PaymentHash::from_str(&filter) {
		Ok(h)
	} else if let Ok(i) = Bolt11Invoice::from_str(&filter) {
		Ok(i.into())
	} else {
		bail!("filter is not valid payment hash nor invoice");
	}
}

pub async fn execute_lightning_command(
	lightning_command: LightningCommand,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	match lightning_command {
		LightningCommand::Pay { invoice, amount, comment, no_sync } => {
			if let Ok(invoice) = Bolt11Invoice::from_str(&invoice) {
				pay_invoice(invoice, amount, comment, no_sync, wallet).await?
			} else if let Ok(offer) = Offer::from_str(&invoice) {
				pay_offer(offer, amount, comment, no_sync, wallet).await?
			} else if let Ok(lnaddr) = LightningAddress::from_str(&invoice) {
				pay_lnaddr(lnaddr, amount, comment, no_sync, wallet).await?
			} else {
				bail!("argument is not a valid bolt11 invoice, bolt12 offer or lightning address");
			}
		},
		LightningCommand::Invoice { amount, wait } => {
			let invoice = wallet.bolt11_invoice(amount).await?;
			output_json(&InvoiceInfo { invoice: invoice.to_string() });
			if wait {
				wallet.check_and_claim_ln_receive(invoice.into(), true).await?;
			}
		},
		LightningCommand::Status { filter, preimage } => {
			let payment_hash = match (filter, preimage) {
				(Some(filter), None) => payment_hash_from_filter(&filter)?,
				(None, Some(p)) => p.into(),
				(None, None) => bail!("need to provide a filter"),
				(Some(_), Some(_)) => bail!("cannot provide both filter and preimage"),
			};
			if let Some(ret) = wallet.lightning_receive_status(payment_hash)? {
				output_json(&ret);
			} else {
				info!("No invoice found");
			}
		},
		LightningCommand::Invoices => {
			let mut receives = wallet.lightning_receives()?;
			// receives are ordered from newest to oldest, so we reverse them so last terminal item is newest
			receives.reverse();
			output_json(&receives);
		},
		LightningCommand::Claim { payment, wait } => {
			if let Some(payment) = payment {
				let payment_hash = match PaymentHash::from_str(&payment) {
					Ok(h) => h,
					Err(_) => match Bolt11Invoice::from_str(&payment) {
						Ok(i) => i.into(),
						Err(_) => bail!("invalid invoice or payment hash"),
					}
				};

				wallet.check_and_claim_ln_receive(payment_hash, wait).await?;
			} else {
				info!("no invoice provided, trying to claim all open invoices");
				wallet.check_and_claim_all_open_ln_receives(wait).await?;
			}
		},
	}

	Ok(())
}

pub async fn pay_invoice(
	invoice: Bolt11Invoice,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &mut Wallet,
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
		if let Err(e) = wallet.sync().await {
			warn!("Sync error: {}", e)
		}
	}
	info!("Sending bolt11 payment of {} to invoice {}", final_amount, invoice);
	let preimage = wallet.send_lightning_payment(Invoice::Bolt11(invoice), amount).await?;
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(())
}

pub async fn pay_offer(
	offer: Offer,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	if comment.is_some() {
		bail!("comment not supported for bolt12 offer");
	}

	if !no_sync {
		info!("Syncing wallet...");
		if let Err(e) = wallet.sync().await {
			warn!("Sync error: {}", e)
		}
	}

	info!("Sending bolt12 payment of {:?} to offer {}", amount, offer);
	let (invoice, preimage) = wallet.pay_offer(offer, amount).await?;
	info!("Paid invoice: {:?}", invoice);
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(())
}

pub async fn pay_lnaddr(
	lnaddr: LightningAddress,
	amount: Option<Amount>,
	comment: Option<String>,
	no_sync: bool,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	let amount = amount.context("amount missing")?;

	if !no_sync {
		info!("Syncing wallet...");
		if let Err(e) = wallet.sync().await {
			warn!("Sync error: {}", e)
		}
	}
	info!("Sending {} to lightning address {}", amount, lnaddr);
	let comment = comment.as_ref().map(|c| c.as_str());
	let (inv, preimage) = wallet.send_lnaddr(&lnaddr, amount, comment).await?;
	info!("Paid invoice {}", inv);
	info!("Payment preimage received: {}", preimage.as_hex());

	Ok(())
}

