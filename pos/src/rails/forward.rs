//! The Lightning rail: a forwarding invoice from a private barkd.
//!
//! barkd holds the preimage, claims the payment straight to the owner's Ark
//! key and posts the claim to the owner's mailbox. A forwarded receive is
//! `settled` only after that post, so `settled` means delivered.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bark_json::cli::LightningReceiveStateKind;
use bark_json::web::LightningInvoiceForAddressRequest;
use bark_rest_client::apis::configuration::Configuration;
use bark_rest_client::apis::{self, lightning_api};
use bitcoin::Amount;
use lightning_invoice::Bolt11Invoice;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::config;


pub struct Forwarder {
	client: Configuration,
}

/// What barkd reports about a forwarding invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardStatus {
	/// Not paid, or paid and not yet delivered.
	Pending,
	/// Delivered to the owner's mailbox.
	Delivered(Amount),
	/// Canceled, or expired unpaid.
	Gone,
}

impl Forwarder {
	pub fn new(cfg: &config::Barkd) -> anyhow::Result<Forwarder> {
		let mut headers = HeaderMap::new();
		if let Some(token) = &cfg.token {
			headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token))?);
		}
		let client = reqwest::Client::builder()
			.default_headers(headers)
			.timeout(Duration::from_secs(30))
			.build()?;
		let client = Configuration {
			base_path: cfg.url.trim_end_matches('/').to_string(),
			client,
			..Configuration::default()
		};
		Ok(Forwarder { client })
	}

	/// Creates an invoice that barkd claims to `address`.
	pub async fn create_invoice(
		&self,
		amount: Amount,
		address: &ark::Address,
		description: Option<String>,
		expiry: Duration,
	) -> anyhow::Result<Bolt11Invoice> {
		let req = LightningInvoiceForAddressRequest {
			amount_sat: amount.to_sat(),
			address: address.to_string(),
			description,
			expiry_secs: Some(expiry.as_secs()),
		};
		let resp = lightning_api::generate_invoice_for_address(&self.client, req).await
			.map_err(|e| anyhow::anyhow!("barkd failed to create a forwarding invoice: {}", fmt_err(&e)))?;
		Bolt11Invoice::from_str(&resp.invoice).context("barkd returned an invalid invoice")
	}

	pub async fn status(&self, payment_hash: &str) -> anyhow::Result<ForwardStatus> {
		match lightning_api::get_receive_status(&self.client, payment_hash).await {
			Ok(info) => Ok(match info.state {
				LightningReceiveStateKind::Settled => ForwardStatus::Delivered(info.amount),
				_ => ForwardStatus::Pending,
			}),
			// barkd answers 404 for a receive that ended unsettled.
			Err(apis::Error::ResponseError(r)) if r.status == reqwest::StatusCode::NOT_FOUND => {
				Ok(ForwardStatus::Gone)
			},
			Err(e) => Err(anyhow::anyhow!("barkd status check failed: {}", fmt_err(&e))),
		}
	}

	/// Cancels an unpaid invoice. barkd refuses once it revealed the
	/// preimage; the payment is then delivered and counted as excess.
	pub async fn cancel(&self, payment_hash: &str) -> anyhow::Result<()> {
		lightning_api::cancel_receive(&self.client, payment_hash).await
			.map_err(|e| anyhow::anyhow!("barkd refused to cancel the invoice: {}", fmt_err(&e)))
	}
}

fn fmt_err<T>(e: &apis::Error<T>) -> String {
	match e {
		apis::Error::ResponseError(r) => format!("status {}: {}", r.status, r.content),
		other => other.to_string(),
	}
}
