use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Amount;
use clap;
use lightning_invoice::Bolt11Invoice;
use log::info;

use ark::lightning::{PaymentHash, Preimage};
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::{lightning_api, Error};
use bark_rest_client::models;
use bark_rest_client::models::{
	LightningReceiveStateKind as ReceiveState, LightningSendStateKind as SendState,
};

use bark_cli::util::output_json;

use crate::connect::RestResultExt;

/// How often to poll a lightning payment or receive when `--wait` is given.
const WAIT_POLL_INTERVAL: Duration = Duration::from_secs(2);

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
		/// How many seconds the invoice can be paid for, at most the server's
		/// invoice expiry. Defaults to the server's invoice expiry.
		#[arg(long = "expiry", value_name = "SECONDS")]
		expiry_secs: Option<u64>,
		/// Wait for the incoming payment to settle
		#[arg(long)]
		wait: bool,
		/// Provide a lightning receive token for authentication of this claim if the server requires one
		/// and there are no existing spendable VTXOs to prove ownership of
		#[arg(long)]
		token: Option<String>,
	},
	/// Creates a bolt11 invoice that forwards the received Ark VTXO to an Ark address
	#[command()]
	InvoiceForAddress {
		/// Ark address that will receive the claimed VTXO
		address: ark::Address,
		/// Invoice amount
		amount: Amount,
		/// Optional description to embed in the invoice as its memo
		#[arg(long)]
		description: Option<String>,
		/// How many seconds the invoice can be paid for, at most the server's
		/// invoice expiry. Defaults to the server's invoice expiry.
		#[arg(long = "expiry", value_name = "SECONDS")]
		expiry_secs: Option<u64>,
		/// Wait for the incoming payment to settle and be delivered
		#[arg(long)]
		wait: bool,
	},
	/// List all generated invoices
	#[command()]
	Invoices,
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
		/// Wait for the payment to be settled
		#[arg(long)]
		wait: bool,
		/// How many seconds the server should keep trying to pay, capped to the
		/// server's maximum. Defaults to the server's choice.
		#[arg(long = "retry-for", value_name = "SECONDS")]
		retry_for_secs: Option<u64>,
	},
	/// Get the status of an outgoing lightning payment
	#[command()]
	Status {
		#[clap(flatten)]
		filter_args: LightningStatusFilterGroup,
	},
}

#[derive(clap::Subcommand)]
pub enum ReceiveCommand {
	/// Get the status of an incoming lightning payment
	#[command()]
	Status {
		#[clap(flatten)]
		filter_args: LightningStatusFilterGroup,
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
	config: &Configuration,
) -> anyhow::Result<()> {
	match lightning_command {
		LightningCommand::Pay(pay_cmd) => {
			execute_pay_command(pay_cmd, config).await?;
		},
		LightningCommand::Receive(receive_cmd) => {
			execute_receive_command(receive_cmd, config).await?;
		},
		LightningCommand::Invoice { amount, description, expiry_secs, wait, token } => {
			let req = models::LightningInvoiceRequest {
				amount_sat: amount.to_sat(),
				description,
				expiry_secs,
				token,
			};
			let resp = lightning_api::generate_invoice(config, req).await.rest()?;
			let invoice = resp.invoice.clone();
			output_json(&resp);
			if wait {
				wait_for_lightning_receive(config, &invoice).await?;
			}
		},
		LightningCommand::InvoiceForAddress { address, amount, description, expiry_secs, wait } => {
			let req = models::LightningInvoiceForAddressRequest {
				amount_sat: amount.to_sat(),
				address: address.to_string(),
				description,
				expiry_secs,
			};
			let resp = lightning_api::generate_invoice_for_address(config, req).await.rest()?;
			let invoice = resp.invoice.clone();
			output_json(&resp);
			if wait {
				wait_for_lightning_receive(config, &invoice).await?;
			}
		},
		LightningCommand::Invoices => {
			let mut receives = lightning_api::list_receive_statuses(config).await.rest()?;
			// receives are ordered from newest to oldest, so we reverse them so last terminal item is newest
			receives.reverse();
			output_json(&receives);
		},
	}

	Ok(())
}

async fn execute_pay_command(
	pay_command: PayCommand,
	config: &Configuration,
) -> anyhow::Result<()> {
	match pay_command {
		PayCommand::Invoice { invoice, amount, comment, wait, retry_for_secs } => {
			let req = models::LightningPayRequest {
				destination: invoice,
				amount_sat: amount.map(|a| a.to_sat()),
				comment,
				retry_for_secs,
			};
			let resp = lightning_api::pay(config, req).await.rest()?;
			let hash = resp.payment_hash
				.context("barkd did not report a payment hash")?;
			info!("Payment initiated: hash = {}", hash);
			if wait {
				wait_for_lightning_send(config, &hash.to_string()).await?;
			}
		},
		PayCommand::Status { filter_args: LightningStatusFilterGroup { filter, preimage } } => {
			let payment_hash = match (filter, preimage) {
				(Some(filter), None) => payment_hash_from_filter(&filter)?,
				(None, Some(p)) => p.into(),
				(None, None) => bail!("need to provide a filter"),
				(Some(_), Some(_)) => bail!("cannot provide both filter and preimage"),
			};

			let status = lightning_api::get_send_status(config, &payment_hash.to_string())
				.await.rest()?;
			output_json(&status);
		},
	}

	Ok(())
}

async fn execute_receive_command(
	receive_command: ReceiveCommand,
	config: &Configuration,
) -> anyhow::Result<()> {
	match receive_command {
		ReceiveCommand::Status { filter_args: LightningStatusFilterGroup { filter, preimage } } => {
			let payment_hash = match (filter, preimage) {
				(Some(filter), None) => payment_hash_from_filter(&filter)?,
				(None, Some(p)) => p.into(),
				(None, None) => bail!("need to provide a filter"),
				(Some(_), Some(_)) => bail!("cannot provide both filter and preimage"),
			};

			let status = lightning_api::get_receive_status(config, &payment_hash.to_string())
				.await.rest()?;
			output_json(&status);
		},
		ReceiveCommand::Cancel { payment } => {
			let payment_hash = payment_hash_from_filter(&payment)?;
			lightning_api::cancel_receive(config, &payment_hash.to_string()).await.rest()?;
			info!("Lightning receive canceled successfully");
		},
	}

	Ok(())
}

/// Poll the receive status until the incoming payment settles; barkd
/// claims the receive in the background.
async fn wait_for_lightning_receive(config: &Configuration, invoice: &str) -> anyhow::Result<()> {
	loop {
		let status = match lightning_api::get_receive_status(config, invoice).await {
			// barkd drops a receive that ends without settling.
			Err(Error::ResponseError(resp)) if resp.status == 404 => {
				bail!("lightning receive ended without settling: invoice = {}", invoice);
			},
			res => res.rest()?,
		};
		match status.state {
			ReceiveState::Settled => {
				info!("Payment received: hash = {}", status.payment_hash);
				return Ok(());
			},
			ReceiveState::AwaitingPayment | ReceiveState::HtlcsReady
				| ReceiveState::PreimageRevealed | ReceiveState::Delivering
				| ReceiveState::Other => tokio::time::sleep(WAIT_POLL_INTERVAL).await,
		}
	}
}

/// Poll the send status until the payment settles or the wallet loses
/// track of it; barkd drives the payment forward in the background.
pub async fn wait_for_lightning_send(config: &Configuration, hash: &str) -> anyhow::Result<()> {
	loop {
		let status = lightning_api::get_send_status(config, hash).await.rest()?;
		match status.state {
			SendState::Paid => {
				info!("Payment completed: hash = {}", status.payment_hash);
				return Ok(());
			},
			// The wallet has no trace anymore: the payment failed and its
			// HTLCs were revoked.
			SendState::Unknown => bail!("payment failed: hash = {}", hash),
			SendState::RevocationStuck => bail!("payment failed and revoking its HTLCs is stuck; \
				barkd keeps retrying, consider an emergency exit: hash = {}", hash),
			SendState::Start | SendState::InputsLocked | SendState::HtlcReceived
				| SendState::PaymentInitiated | SendState::RevocableHtlcs
				| SendState::Other => tokio::time::sleep(WAIT_POLL_INTERVAL).await,
		}
	}
}
