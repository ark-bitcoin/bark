
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
use ark::lightning::PaymentHash;
use bitcoin_ext::{AmountExt, BlockHeight};

use super::LightningNodeId;


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
	/// NB: this is NOT authoritative for settlement. The lightning node can
	/// settle a payment without this status write committing (a lost
	/// optimistic-lock race, or a crash between recording the preimage and
	/// updating the status), so the status may still read `Submitted` or even
	/// `Failed` for a payment that actually completed. Never gate a
	/// fund-releasing decision (revocation, refund, re-issuing sender vtxos) on
	/// this variant: use `HtlcSettler::is_settled` or the transaction's
	/// `ensure_not_settled`, as the `htlc_settlement` table is the single source
	/// of truth for settlement.
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
pub struct LightningPaymentAttempt {
	pub id: i64,
	pub lightning_node_id: LightningNodeId,
	pub payment_hash: PaymentHash,
	/// Invoice amount in msats: what the payee receives. Set at initiation
	/// from the invoice / requested payment amount, immutable after.
	pub amount_msat: u64,
	/// Total msats CLN put on the wire to fulfil the invoice
	/// (`amount_msat + LN routing fee`), from CLN's `amount_sent_msat`.
	/// `None` on intra-Ark self-payments (no CLN send) and while the attempt
	/// is still open. Does not include the Ark `user_fee`.
	pub final_amount_msat: Option<u64>,
	pub status: LightningPaymentStatus,
	/// The htlc subscription this attempt was initiated against, if any.
	///
	/// Set once, at initiation, when the payment is an intra-Ark
	/// self-payment. Never derive this from the current presence of a
	/// subscription with the same payment hash: a receive registered after
	/// the attempt was initiated must not retroactively turn it into a
	/// self-payment.
	pub lightning_htlc_subscription_id: Option<i64>,
	pub error: Option<String>,
	/// Chain-tip height at cosign time. `None` for pre-V57 rows and legacy
	/// protocol versions.
	pub block_height: Option<BlockHeight>,
	/// Fee quoted to the user at initiation (`base_fee + expiry_fee`).
	/// `None` for pre-V57 rows.
	pub user_fee: Option<Amount>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl LightningPaymentAttempt {
	/// Whether this attempt is an intra-Ark self-payment.
	pub fn is_self_payment(&self) -> bool {
		self.lightning_htlc_subscription_id.is_some()
	}

	/// Derive routing fee from CLN's `amount_sent_msat`; 0 when unset
	/// (intra-Ark self-pay or a Failed attempt CLN never accepted).
	pub fn routing_fee_sat_from(&self, final_amount_msat: Option<u64>) -> u64 {
		final_amount_msat
			.map(|sent| Amount::from_msat_ceil(
				sent.saturating_sub(self.amount_msat),
			).to_sat())
			.unwrap_or(0)
	}
}

impl TryFrom<Row> for LightningPaymentAttempt {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(LightningPaymentAttempt {
			id: row.get("id"),
			lightning_node_id: row.get("lightning_node_id"),
			payment_hash: PaymentHash::from_str(row.get::<_, &str>("payment_hash"))
				.context("error decoding payment hash from db")?,
			amount_msat: row.get::<_, i64>("amount_msat") as u64,
			final_amount_msat: row.get::<_, Option<i64>>("final_amount_msat").map(|i| i as u64),
			lightning_htlc_subscription_id: row.get("lightning_htlc_subscription_id"),
			status: row.get("status"),
			error: row.get("error"),
			block_height: row.get::<_, Option<i32>>("block_height").map(|i| i as BlockHeight),
			user_fee: row.get::<_, Option<i64>>("user_fee_sat")
				.map(|f| Amount::from_sat(u64::try_from(f).expect("negative user_fee_sat in db row"))),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
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
	pub lightning_node_id: LightningNodeId,
	pub payment_hash: PaymentHash,
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
			lightning_node_id: row.get("lightning_node_id"),
			payment_hash: PaymentHash::from_str(row.get::<_, &str>("payment_hash"))
				.context("error decoding payment hash from db")?,
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
