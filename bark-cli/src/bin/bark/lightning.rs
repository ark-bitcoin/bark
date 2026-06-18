use std::str::FromStr;

use anyhow::Context;
use bitcoin::Amount;
use clap;
use lightning::offers::offer::Offer;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use log::info;

use bitcoin::hex::DisplayHex;
use serde::Serialize;

use ark::lightning::{PaymentHash, Preimage};
use bark::Wallet;
use bark::actions::lightning::pay::{LightningSendState, Progress};
use bark_json::cli::{InvoiceInfo, LightningReceiveInfo};

use bark_cli::util::output_json;

#[derive(Serialize)]
struct LightningSendStatus {
	payment_hash: String,
	state: &'static str,
	invoice: Option<String>,
	preimage: Option<String>,
}

impl LightningSendStatus {
	fn from_state(hash: PaymentHash, state: &LightningSendState) -> Self {
		match state {
			LightningSendState::Unknown => LightningSendStatus {
				payment_hash: hash.to_string(),
				state: "unknown",
				invoice: None,
				preimage: None,
			},
			LightningSendState::Paid(paid) => LightningSendStatus {
				payment_hash: paid.payment_hash.to_string(),
				state: "paid",
				invoice: None,
				preimage: Some(paid.preimage.as_hex().to_string()),
			},
			LightningSendState::InProgress(send) => {
				let phase = match send.progress {
					Progress::Start => "start",
					Progress::HtlcReceived(_) => "htlc-received",
					Progress::PaymentInitiated(_) => "payment-initiated",
					Progress::RevocableHtlcs { .. } => "revocable-htlcs",
					Progress::RevocationStuck { .. } => "revocation-stuck",
				};
				LightningSendStatus {
					payment_hash: send.invoice.payment_hash().to_string(),
					state: phase,
					invoice: Some(send.invoice.to_string()),
					preimage: None,
				}
			},
		}
	}
}

#[derive(clap::Subcommand)]
pub enum LightningCommand {
	/// Pay a bolt11 invoice or check payment status
	#[command(subcommand)]
	Pay(PayCommand),
	/// Get the status of an incoming lightning payment
	#[command(subcommand)]
	Receive(ReceiveCommand),
	/// Creates a bolt11 invoice with the provided amount
	///
	/// Provided value must match format `<amount> <unit>`, where unit can be any amount denomination. Example: `250000 sats`.
	#[command()]
	Invoice {
		amount: Amount,
		/// Optional description to embed in the invoice as its memo
		#[arg(long)]
		description: Option<String>,
		/// Wait for the incoming payment to settle
		#[arg(long)]
		wait: bool,
		/// Provide a lightning receive token for authentication of this claim if the server requires one
		/// and there are no existing spendable VTXOs to prove ownership of
		#[arg(long)]
		token: Option<String>,
	},
	/// List all generated invoices
	#[command()]
	Invoices,
	/// Claim the receipt of an invoice
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

#[derive(clap::Subcommand)]
pub enum PayCommand {
	/// Pay a bolt11 invoice
	#[command()]
	Invoice {
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
	/// Get the status of an outgoing lightning payment
	#[command()]
	Status {
		#[clap(flatten)]
		filter_args: LightningStatusFilterGroup,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},
}

#[derive(clap::Subcommand)]
pub enum ReceiveCommand {
	/// Get the status of an incoming lightning payment
	#[command()]
	Status {
		#[clap(flatten)]
		filter_args: LightningStatusFilterGroup,
		/// Skip syncing wallet
		#[arg(long)]
		no_sync: bool,
	},
	/// Cancel a pending lightning receive
	#[command()]
	Cancel {
		/// payment hash or invoice to cancel
		payment: String,
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
		LightningCommand::Pay(pay_cmd) => {
			execute_pay_command(pay_cmd, wallet).await?;
		},
		LightningCommand::Receive(receive_cmd) => {
			execute_receive_command(receive_cmd, wallet).await?;
		},
		LightningCommand::Invoice { amount, description, wait, token } => {
			let invoice = wallet.bolt11_invoice(amount, description).await?;
			output_json(&InvoiceInfo { invoice: invoice.to_string() });
			if wait {
				let token = token.as_ref().map(|c| c.as_str());
				wallet.try_claim_lightning_receive(invoice.into(), true, token).await?;
			}
		},
		LightningCommand::Invoices => {
			let mut receives = wallet.pending_lightning_receives().await?;
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

async fn execute_pay_command(
	pay_command: PayCommand,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	match pay_command {
		PayCommand::Invoice { invoice, amount, comment, no_sync, wait } => {
			if !no_sync {
				info!("Syncing wallet...");
				wallet.sync().await;
			}

			if let Ok(invoice) = Bolt11Invoice::from_str(&invoice) {
				if comment.is_some() {
					bail!("comment is not supported for BOLT-11 invoices");
				}
				wallet.pay_lightning_invoice(invoice, amount, wait).await?;
			} else if let Ok(offer) = Offer::from_str(&invoice) {
				if comment.is_some() {
					bail!("comment is not supported for BOLT-12 offers");
				}
				wallet.pay_lightning_offer(offer, amount, wait).await?;
			} else if let Ok(lnaddr) = LightningAddress::from_str(&invoice) {
				let amount = amount.context("amount is required for Lightning addresses")?;
				wallet.pay_lightning_address(&lnaddr, amount, comment, wait).await?;
			} else if let Ok(lnurl) = LnUrl::from_str(&invoice) {
				let amount = amount.context("amount is required for LNURL")?;
				wallet.pay_lnurl(&lnurl, amount, comment, wait).await?;
			} else {
				bail!("argument is not a valid BOLT-11 invoice, BOLT-12 offer, \
					Lightning address or LNURL");
			}
		},
		PayCommand::Status { filter_args: LightningStatusFilterGroup { filter, preimage }, no_sync } => {
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

			let state = wallet.check_lightning_payment(payment_hash, false).await?;
			output_json(&LightningSendStatus::from_state(payment_hash, &state));
		},
	}

	Ok(())
}

async fn execute_receive_command(
	receive_command: ReceiveCommand,
	wallet: &mut Wallet,
) -> anyhow::Result<()> {
	match receive_command {
		ReceiveCommand::Status { filter_args: LightningStatusFilterGroup { filter, preimage }, no_sync } => {
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

			if let Some(ret) = wallet.lightning_receive_status(payment_hash).await? {
				output_json(&LightningReceiveInfo::from(ret));
			} else {
				info!("No incoming payment found for this payment hash");
			}
		},
		ReceiveCommand::Cancel { payment } => {
			let payment_hash = payment_hash_from_filter(&payment)?;
			wallet.cancel_lightning_receive(payment_hash).await?;
			info!("Lightning receive canceled successfully");
		},
	}

	Ok(())
}
