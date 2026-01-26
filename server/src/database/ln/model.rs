
use std::fmt;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::Amount;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;
use postgres_types::{FromSql, ToSql};
use server_rpc::protos;
use tokio_postgres::Row;

use ark::VtxoId;
use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::{AmountExt, BlockHeight};

use super::ClnNodeId;


#[derive(Debug, Clone, Default)]
pub struct LightningIndexes {
	pub created_index: u64,
	pub updated_index: u64,
}

/// The status of a lightning invoice payment.
///
/// Once the server receives a payment request, its status is `Requested`.
/// The server will pass on the payment to a lightning node which changes the status to `Submitted`.
/// The lightning node payment will either fail or succeed,
/// updating the status to `Failed` or `Succeeded` respectively.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq)]
#[postgres(name = "lightning_payment_status")]
pub enum LightningPaymentStatus {
	#[postgres(name = "requested")]
	Requested,
	#[postgres(name = "submitted")]
	Submitted,
	#[postgres(name = "succeeded")]
	Succeeded,
	#[postgres(name = "failed")]
	Failed,
}

impl LightningPaymentStatus {
	pub fn is_final(&self) -> bool {
		match self {
			LightningPaymentStatus::Requested => false,
			LightningPaymentStatus::Submitted => false,
			LightningPaymentStatus::Succeeded => true,
			LightningPaymentStatus::Failed => true,
		}
	}
}

impl fmt::Display for LightningPaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LightningPaymentStatus::Requested => f.write_str("requested"),
			LightningPaymentStatus::Submitted => f.write_str("submitted"),
			LightningPaymentStatus::Succeeded => f.write_str("succeeded"),
			LightningPaymentStatus::Failed => f.write_str("failed"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct LightningInvoice {
	pub id: i64,
	pub invoice: Invoice,
	pub payment_hash: PaymentHash,
	pub final_amount_msat: Option<u64>,
	pub preimage: Option<Preimage>,
	pub last_attempt_status: Option<LightningPaymentStatus>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl TryFrom<Row> for LightningInvoice {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(LightningInvoice {
			id: row.get("id"),
			invoice: Invoice::from_str(row.get("invoice"))
				.context("error decoding invoice from db")?,
			payment_hash: PaymentHash::try_from(row.get::<_, &[u8]>("payment_hash"))
				.context("error decoding payment hash from db")?,
			final_amount_msat: row.get::<_, Option<i64>>("final_amount_msat").map(|i| i as u64),
			preimage: row.get::<_, Option<&[u8]>>("preimage").map(|b| {
				b.try_into().context("invalid preimage, not 32 bytes")
			}).transpose()?,
			last_attempt_status: row.get::<_, Option<LightningPaymentStatus>>("status"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct LightningPaymentAttempt {
	pub id: i64,
	pub lightning_invoice_id: i64,
	pub lightning_node_id: ClnNodeId,
	pub amount_msat: u64,
	pub status: LightningPaymentStatus,
	pub is_self_payment: bool,
	pub error: Option<String>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl From<Row> for LightningPaymentAttempt {
	fn from(row: Row) -> Self {
		LightningPaymentAttempt {
			id: row.get("id"),
			lightning_invoice_id: row.get("lightning_invoice_id"),
			lightning_node_id: row.get("lightning_node_id"),
			amount_msat: row.get::<_, i64>("amount_msat") as u64,
			is_self_payment: row.get::<_, bool>("is_self_payment"),
			status: row.get("status"),
			error: row.get("error"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		}
	}
}

/// The status of a lightning htlc subscription
///
/// Once the server receives an invoice subscription request, its status is `Started`.
/// The server will monitor this invoice for incoming HTLCs
/// Once one of the HTLCs got accepted, the subscription is set to `Completed`
/// If no HTLC is accepted within the subscription lifetime, subscription will
/// get automatically `Terminated`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, ToSql, FromSql, PartialEq, Eq)]
#[postgres(name = "lightning_htlc_subscription_status")]
pub enum LightningHtlcSubscriptionStatus {
	/// The invoice was created and received HTLCs does not match the invoice yet
	#[postgres(name = "created")]
	Created,
	/// The sender has setup a route of HTLCs towards our node that matches this invoice
	#[postgres(name = "accepted")]
	Accepted,
	/// We created HTLCs for the user and are waiting for him to reveal the preimage
	#[postgres(name = "htlcs-ready")]
	HtlcsReady,
	/// The invoice preimage was revealed and the invoice was settled
	#[postgres(name = "settled")]
	Settled,
	/// The subscription was canceled
	///
	/// Can be set either manually by the user or automatically by the
	/// server after `invoice_expiry` or when the invoice is accepted (HTLCs are held)
	/// for longer than `receive_htlc_forward_timeout`.
	#[postgres(name = "canceled")]
	Canceled,
}

impl fmt::Display for LightningHtlcSubscriptionStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LightningHtlcSubscriptionStatus::Created => f.write_str("created"),
			LightningHtlcSubscriptionStatus::Accepted => f.write_str("accepted"),
			LightningHtlcSubscriptionStatus::HtlcsReady => f.write_str("htlcs-ready"),
			LightningHtlcSubscriptionStatus::Settled => f.write_str("settled"),
			LightningHtlcSubscriptionStatus::Canceled => f.write_str("canceled"),
		}
	}
}

impl From<LightningHtlcSubscriptionStatus> for protos::LightningReceiveStatus {
	fn from(v: LightningHtlcSubscriptionStatus) -> Self {
	    match v {
			LightningHtlcSubscriptionStatus::Created => Self::Created,
			LightningHtlcSubscriptionStatus::Accepted => Self::Accepted,
			LightningHtlcSubscriptionStatus::HtlcsReady => Self::HtlcsReady,
			LightningHtlcSubscriptionStatus::Settled => Self::Settled,
			LightningHtlcSubscriptionStatus::Canceled => Self::Canceled,
		}
	}
}

#[derive(Debug, Clone)]
pub struct LightningHtlcSubscription {
	pub id: i64,
	pub lightning_invoice_id: i64,
	pub lightning_node_id: ClnNodeId,
	pub invoice: Bolt11Invoice,
	pub status: LightningHtlcSubscriptionStatus,
	pub lowest_incoming_htlc_expiry: Option<BlockHeight>,
	pub accepted_at: Option<DateTime<Local>>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
	/// NB this field is not always provided by all queries
	pub htlc_vtxos: Vec<VtxoId>,
}

impl LightningHtlcSubscription {
	/// Get the effective amount
	pub fn amount(&self) -> Amount {
		Amount::from_msat_floor(self.invoice.amount_milli_satoshis()
			.expect("invoice generated by us should have amount"))
	}
}

impl <'a>TryFrom<&'a Row> for LightningHtlcSubscription {
	type Error = anyhow::Error;

	fn try_from(row: &'a Row) -> Result<Self, Self::Error> {
		let invoice = Bolt11Invoice::from_str(row.get("invoice"))?;

		Ok(LightningHtlcSubscription {
			id: row.get("id"),
			lightning_invoice_id: row.get("lightning_invoice_id"),
			lightning_node_id: row.get("lightning_node_id"),
			invoice: invoice,
			status: row.get("status"),
			lowest_incoming_htlc_expiry: row.get::<_, Option<i64>>("lowest_incoming_htlc_expiry").map(|i| i as BlockHeight),
			accepted_at: row.try_get("accepted_at").ok(),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
			htlc_vtxos: if let Some(raw) = row.try_get::<_, Vec<&str>>("htlc_vtxos").ok() {
				raw.into_iter()
					.map(|s| s.parse::<VtxoId>())
					.collect::<Result<Vec<_>, _>>()?
			} else {
				vec![]
			},
		})
	}
}
