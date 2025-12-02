use std::str::FromStr;

use bitcoin::Amount;
use clap;
use lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use log::info;

use ark::lightning::{PaymentHash, Preimage};
use bark::lightning::{pay_invoice, pay_lnaddr, pay_offer};
use bark::Wallet;
use bark_json::cli::{InvoiceInfo, LightningReceiveInfo};

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
		/// Wait for the payment to be settled
		#[arg(long)]
		wait: bool,
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
		/// Provide a lightning receive token for authentication of this claim if the server requires one
		/// and there are no existing spendable VTXOs to prove ownership of
		#[arg(long)]
		token: Option<String>,
	},
	/// get the status of an invoice
	#[command()]
	Status {
		#[clap(flatten)]
		filter_args: LightningStatusFilterGroup,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
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
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
		/// Provide a lightning receive token for authentication of this claim if the server requires one
		/// and there are no existing spendable VTXOs to prove ownership of
		#[arg(long)]
		token: Option<String>,
	},
}

#[derive(clap::Args)]
#[group(required = true, multiple = false)]
pub struct LightningStatusFilterGroup {
	/// payment hash or invoice string
	filter: Option<String>,
	/// filter by preimage
	#[arg(long)]
	preimage: Option<Preimage>,
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
		LightningCommand::Pay { invoice, amount, comment, no_sync, wait } => {
			let payment = if let Ok(invoice) = Bolt11Invoice::from_str(&invoice) {
				pay_invoice(invoice, amount, comment, no_sync, wallet).await?
			} else if let Ok(offer) = Offer::from_str(&invoice) {
				pay_offer(offer, amount, comment, no_sync, wallet).await?
			} else if let Ok(lnaddr) = LightningAddress::from_str(&invoice) {
				pay_lnaddr(lnaddr, amount, comment, no_sync, wallet).await?
			} else {
				bail!("argument is not a valid bolt11 invoice, bolt12 offer or lightning address");
			};

			if wait {
				let payment_hash = payment.invoice.payment_hash();
				wallet.check_lightning_payment(payment_hash, true).await?;
			}
		},
		LightningCommand::Invoice { amount, wait, token } => {
			let invoice = wallet.bolt11_invoice(amount).await?;
			output_json(&InvoiceInfo { invoice: invoice.to_string() });
			if wait {
				let token = token.as_ref().map(|c| c.as_str());
				wallet.try_claim_lightning_receive(invoice.into(), true, token).await?;
			}
		},
		LightningCommand::Status { filter_args: LightningStatusFilterGroup { filter, preimage }, no_sync } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			let payment_hash = match (filter, preimage) {
				(Some(filter), None) => payment_hash_from_filter(&filter)?,
				(None, Some(p)) => p.into(),
				(None, None) => bail!("need to provide a filter"),
				(Some(_), Some(_)) => bail!("cannot provide both filter and preimage"),
			};
			if let Some(ret) = wallet.lightning_receive_status(payment_hash)? {
				output_json(&LightningReceiveInfo::from(ret));
			} else {
				info!("No invoice found");
			}
		},
		LightningCommand::Invoices => {
			let mut receives = wallet.pending_lightning_receives()?;
			// receives are ordered from newest to oldest, so we reverse them so last terminal item is newest
			receives.reverse();
			output_json(&receives.into_iter().map(LightningReceiveInfo::from).collect::<Vec<_>>());
		},
		LightningCommand::Claim { payment, wait, no_sync, token } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			if let Some(payment) = payment {
				let payment_hash = match PaymentHash::from_str(&payment) {
					Ok(h) => h,
					Err(_) => match Bolt11Invoice::from_str(&payment) {
						Ok(i) => i.into(),
						Err(_) => bail!("invalid invoice or payment hash"),
					}
				};

				let token = token.as_ref().map(|c| c.as_str());
				wallet.try_claim_lightning_receive(payment_hash, wait, token).await?;
			} else {
				info!("no invoice provided, trying to claim all open invoices");
				wallet.try_claim_all_lightning_receives(wait).await?;
			}
		},
	}

	Ok(())
}
