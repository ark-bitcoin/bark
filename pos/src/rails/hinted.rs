//! The Ark rail: a hinted invoice with the owner's claim key.
//!
//! The Ark server puts the owner's Ark address in the invoice route hints. A
//! scuttle wallet on the same server pays that address by arkoor, and the
//! server settles the invoice in the same step. The server reports the
//! invoice settled before the payer delivers the VTXOs, so the sale is paid
//! only when the server's delivery receipt shows them in the owner's
//! mailbox.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, bail};
use ark::ArkInfo;
use ark::encode::ProtocolEncoding;
use ark::lightning::{Bolt11InvoiceExt, PaymentHash, Preimage};
use bitcoin::Amount;
use bitcoin_ext::BlockDelta;
use lightning_invoice::Bolt11Invoice;
use server_rpc::{ServerConnection, protos};

use crate::config;
use crate::database::{self, PgPool};


/// The CLTV margins bark adds for a receive: its default VTXO exit margin,
/// HTLC claim delta and claim preparation delta.
const RECEIVE_CLTV_MARGIN: u16 = 12 + 18 + 2;

pub struct ArkServer {
	conn: ServerConnection,
	receipts: PgPool,
}

/// A delivery receipt from the Ark server.
#[derive(Debug, Clone)]
pub struct Receipt {
	pub amount: Amount,
	pub vtxo_ids: Vec<String>,
}

impl ArkServer {
	pub async fn connect(cfg: &config::Config) -> anyhow::Result<ArkServer> {
		let conn = ServerConnection::builder()
			.address(&cfg.ark_server_url)
			.network(cfg.network)
			.user_agent(format!("posd/{}", env!("CARGO_PKG_VERSION")))
			.connect().await
			.context("failed to connect to the Ark server")?;
		if !conn.expiry_payouts().await {
			bail!("the Ark server does not run in expiry payout mode, which the delivery receipt needs");
		}
		let receipts = database::pool(&cfg.ark_server_postgres).await
			.context("failed to connect to the Ark server database")?;
		Ok(ArkServer { conn, receipts })
	}

	pub async fn ark_info(&self) -> ArkInfo {
		self.conn.ark_info().await
	}

	/// Asks the Ark server for an invoice that the owner's Ark address
	/// can be paid through.
	pub async fn create_invoice(
		&self,
		amount: Amount,
		claim_pubkey: &str,
		mailbox_id: &str,
		description: Option<String>,
		expiry: Duration,
	) -> anyhow::Result<Bolt11Invoice> {
		let info = self.ark_info().await;
		let min_cltv_delta = info.vtxo_exit_delta
			.checked_add(info.htlc_expiry_delta)
			.and_then(|d| d.checked_add(BlockDelta::new(RECEIVE_CLTV_MARGIN)))
			.context("CLTV delta overflow")?;

		let claim_pubkey = bitcoin::secp256k1::PublicKey::from_str(claim_pubkey)
			.context("store has an invalid claim key")?;
		let mailbox_id = ark::mailbox::MailboxIdentifier::from_str(mailbox_id)
			.context("store has an invalid mailbox id")?;
		// Nobody claims this invoice over Lightning, so the preimage is
		// discarded. A Lightning payer is refunded when the invoice expires.
		let payment_hash = Preimage::random().compute_payment_hash();
		let req = protos::StartLightningReceiveRequest {
			payment_hash: payment_hash.to_vec(),
			amount_sat: amount.to_sat(),
			min_cltv_delta: min_cltv_delta.into(),
			mailbox_id: Some(mailbox_id.serialize()),
			description,
			expiry_secs: Some(expiry.as_secs()),
			claim_pubkey: Some(claim_pubkey.serialize().to_vec()),
			ark_address_hint: true,
		};
		let resp = self.conn.client.clone().start_lightning_receive(req).await
			.context("the Ark server refused the hinted invoice")?
			.into_inner();
		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("the Ark server returned an invalid invoice")?;
		if PaymentHash::from(*invoice.payment_hash()) != payment_hash {
			bail!("the Ark server returned an invoice for another payment hash");
		}
		if invoice.ark_address().is_none() {
			bail!("the Ark server returned an invoice without the Ark address route hint; \
				enable ln_receive_ark_address_hints on the server");
		}
		Ok(invoice)
	}

	/// The Ark server's delivery receipt for a hinted invoice, if every
	/// output reached the owner's mailbox.
	pub async fn receipt(
		&self,
		payment_hash: &str,
		claim_pubkey: &str,
		mailbox_id: &str,
		min_amount: Amount,
	) -> anyhow::Result<Option<Receipt>> {
		let server_pubkey = self.ark_info().await.server_pubkey.to_string();
		let conn = self.receipts.get().await?;
		let row = conn.query_opt("
			SELECT amount_sat, vtxo_ids FROM v_arkoor_receive_delivery
			WHERE payment_hash = $1 AND claim_pubkey = $2 AND receiver_mailbox_id = $3
				AND server_pubkey = $4 AND amount_sat >= $5
		", &[
			&payment_hash, &claim_pubkey, &mailbox_id, &server_pubkey,
			&(min_amount.to_sat() as i64),
		]).await.context("delivery receipt query failed")?;
		Ok(row.map(|row| Receipt {
			amount: Amount::from_sat(row.get::<_, i64>("amount_sat") as u64),
			vtxo_ids: row.get("vtxo_ids"),
		}))
	}
}
