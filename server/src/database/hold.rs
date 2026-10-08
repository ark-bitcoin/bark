//! Storage for the hold invoices we serve through CLN's hold plugin.
//!
//! One row of `cln_hold` is one invoice. Several rows may share a payment hash,
//! so the `invoice` string is what tells our row and the plugin's own record
//! apart.
//!
//! This is the lightning side of an incoming payment, next to the htlc-recv
//! vtxos in `htlc_vtxo`. `lightning_htlc_subscription` keeps recording the
//! receive flow; a `cln_hold` row is written alongside the subscription it
//! belongs to.
//!
//! ## The plugin owns the status
//!
//! `status` mirrors the plugin's four states and the plugin is the authority on
//! which one an invoice is in. We only ever copy what it reports.
//!
//! The path through those states is one-way: `unpaid`, then `accepted`, then
//! `paid` or `cancelled`. The plugin never takes an accepted invoice back to
//! `unpaid`; when held HTLCs near their expiry it cancels the invoice instead.
//! The transitions are guarded so that exactly one writer records each of
//! them, whichever of the plugin and the server reports it first.
//!
//! ## The timestamps are notes, not state
//!
//! `accepted_at`, `paid_at` and `cancelled_at` record when a state was
//! reached.
//!
//! ## An accepted hold is HTLCs
//!
//! An accepted invoice is HTLCs the node is holding, and HTLCs have a sum and
//! a deadline. So an accepted row carries `accepted_amount_msat`, what those
//! HTLCs cover, and `lowest_incoming_htlc_expiry`, the blockheight we must have
//! acted by. Anyone deciding what to grant against a hold can read both
//! straight off the row.
//!
//! Times and heights are stored the way they are asked about, which means
//! absolutely. The one delta we keep says so in its name.

use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Local};
use postgres_types::{FromSql, ToSql};
use tokio_postgres::{GenericClient, Row};
use tokio_postgres::types::Type;

use ark::lightning::PaymentHash;
use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::database::ln::LightningNodeId;


/// All columns of the `cln_hold` table.
const HOLD_COLUMNS: &str = "
	id, lightning_node_id, invoice, payment_hash, requested_amount_msat,
	min_final_cltv_delta, expires_at, status, accepted_amount_msat,
	lowest_incoming_htlc_expiry, paid_amount_msat,
	created_at, accepted_at, paid_at, cancelled_at, updated_at
";

/// The states a hold invoice passes through, as the plugin reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToSql, FromSql)]
#[postgres(name = "cln_hold_status")]
pub enum ClnHoldStatus {
	/// The invoice exists but the node holds no matching HTLCs.
	#[postgres(name = "unpaid")]
	Unpaid,
	/// The node is holding incoming HTLCs for this payment hash.
	#[postgres(name = "accepted")]
	Accepted,
	/// We fulfilled the held HTLCs by revealing the preimage.
	#[postgres(name = "paid")]
	Paid,
	/// We don't serve this invoice anymore.
	#[postgres(name = "cancelled")]
	Cancelled,
}

impl ClnHoldStatus {
	/// Whether the invoice can still change state.
	///
	/// `unpaid` and `accepted` can still be paid or cancelled.
	pub fn is_final(&self) -> bool {
		match self {
			ClnHoldStatus::Unpaid => false,
			ClnHoldStatus::Accepted => false,
			ClnHoldStatus::Paid => true,
			ClnHoldStatus::Cancelled => true,
		}
	}
}

impl std::fmt::Display for ClnHoldStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ClnHoldStatus::Unpaid => f.write_str("unpaid"),
			ClnHoldStatus::Accepted => f.write_str("accepted"),
			ClnHoldStatus::Paid => f.write_str("paid"),
			ClnHoldStatus::Cancelled => f.write_str("cancelled"),
		}
	}
}

/// A row of the `cln_hold` table.
#[derive(Debug, Clone)]
pub struct ClnHoldRecord {
	pub id: i64,
	pub lightning_node_id: LightningNodeId,

	pub invoice: String,
	pub payment_hash: PaymentHash,
	pub requested_amount_msat: u64,
	/// The CLTV delta, in blocks, the payer must leave on the last hop.
	pub min_final_cltv_delta: BlockDelta,
	pub expires_at: DateTime<Local>,

	pub status: ClnHoldStatus,
	/// The sum of the HTLCs the node held when it accepted the invoice.
	///
	/// Set on acceptance and left as it was once the invoice is paid or
	/// cancelled.
	pub accepted_amount_msat: Option<u64>,
	/// The blockheight we must have acted by, once the node holds HTLCs.
	///
	/// The lowest expiry of the HTLCs held, because that is the first deadline
	/// to arrive. Set along with
	/// [`accepted_amount_msat`](Self::accepted_amount_msat).
	pub lowest_incoming_htlc_expiry: Option<BlockHeight>,
	/// What the payer actually sent. Can exceed the requested amount.
	///
	/// The held sum when we saw the invoice accepted, otherwise the invoice
	/// amount.
	pub paid_amount_msat: Option<u64>,

	pub created_at: DateTime<Local>,
	pub accepted_at: Option<DateTime<Local>>,
	pub paid_at: Option<DateTime<Local>>,
	pub cancelled_at: Option<DateTime<Local>>,
	pub updated_at: DateTime<Local>,
}

impl TryFrom<Row> for ClnHoldRecord {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ClnHoldRecord {
			id: row.get("id"),
			lightning_node_id: row.get("lightning_node_id"),
			invoice: row.get("invoice"),
			payment_hash: PaymentHash::from_str(row.get::<_, &str>("payment_hash"))
				.context("error decoding payment hash from db")?,
			requested_amount_msat: u64::try_from(row.get::<_, i64>("requested_amount_msat"))
				.context("negative requested_amount_msat in db")?,
			min_final_cltv_delta: BlockDelta::try_from(row.get::<_, i32>("min_final_cltv_delta"))
				.context("error decoding min_final_cltv_delta from db")?,
			expires_at: row.get("expires_at"),
			status: row.get("status"),
			accepted_amount_msat: row.get::<_, Option<i64>>("accepted_amount_msat")
				.map(u64::try_from)
				.transpose()
				.context("negative accepted_amount_msat in db")?,
			lowest_incoming_htlc_expiry: row.get::<_, Option<i32>>("lowest_incoming_htlc_expiry")
				.map(BlockHeight::try_from)
				.transpose()
				.context("negative lowest_incoming_htlc_expiry in db")?,
			paid_amount_msat: row.get::<_, Option<i64>>("paid_amount_msat")
				.map(u64::try_from)
				.transpose()
				.context("negative paid_amount_msat in db")?,
			created_at: row.get("created_at"),
			accepted_at: row.get("accepted_at"),
			paid_at: row.get("paid_at"),
			cancelled_at: row.get("cancelled_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

/// The immutable data of a hold invoice we just created with the plugin.
#[derive(Debug, Clone)]
pub struct NewClnHold {
	pub lightning_node_id: LightningNodeId,
	pub invoice: String,
	pub payment_hash: PaymentHash,
	pub requested_amount_msat: u64,
	pub min_final_cltv_delta: BlockDelta,
	pub expires_at: DateTime<Local>,
}

/// Store a hold invoice. It starts out unpaid, like the plugin's own record.
pub async fn create_hold<T: GenericClient>(
	client: &T,
	new: &NewClnHold,
) -> anyhow::Result<ClnHoldRecord> {
	let stmt = client.prepare_typed(&format!("
		INSERT INTO cln_hold (
			lightning_node_id, invoice, payment_hash, requested_amount_msat,
			min_final_cltv_delta, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING {HOLD_COLUMNS}
	"), &[
		Type::INT8, Type::TEXT, Type::TEXT, Type::INT8, Type::INT4, Type::TIMESTAMPTZ,
	]).await?;

	let requested_amount_msat = i64::try_from(new.requested_amount_msat)
		.context("requested_amount_msat is too large to store")?;
	let min_final_cltv_delta = i32::try_from(new.min_final_cltv_delta.to_u32())
		.context("min_final_cltv_delta is too large to store")?;

	let row = client.query_one(&stmt, &[
		&new.lightning_node_id,
		&new.invoice,
		&new.payment_hash.to_string(),
		&requested_amount_msat,
		&min_final_cltv_delta,
		&new.expires_at,
	]).await.context("failed to create hold invoice")?;

	ClnHoldRecord::try_from(row)
}

/// Record that the node holds HTLCs for this invoice: what they cover, and by
/// when we must act.
///
/// Returns `None` when the invoice was not unpaid, so the caller learns whether
/// this call is the one that made the transition.
pub async fn mark_hold_accepted<T: GenericClient>(
	client: &T,
	id: i64,
	accepted_amount_msat: u64,
	lowest_incoming_htlc_expiry: BlockHeight,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		UPDATE cln_hold
		SET status = 'accepted', accepted_amount_msat = $2,
			lowest_incoming_htlc_expiry = $3,
			accepted_at = COALESCE(accepted_at, NOW()), updated_at = NOW()
		WHERE id = $1 AND status = 'unpaid'
		RETURNING {HOLD_COLUMNS}
	"), &[Type::INT8, Type::INT8, Type::INT4]).await?;

	let accepted_amount_msat = i64::try_from(accepted_amount_msat)
		.context("accepted_amount_msat is too large to store")?;
	let lowest_incoming_htlc_expiry = i32::try_from(lowest_incoming_htlc_expiry)
		.context("lowest_incoming_htlc_expiry is too large to store")?;

	let row = client.query_opt(&stmt, &[
		&id, &accepted_amount_msat, &lowest_incoming_htlc_expiry,
	]).await.context("failed to mark hold invoice accepted")?;

	row.map(ClnHoldRecord::try_from).transpose()
}

/// Record that we revealed the preimage and took the money.
///
/// Returns `None` when the invoice had already reached a terminal state, so of
/// the writers that race to settle it exactly one gets the row.
///
/// The paid amount is the held sum, which is what the payer actually sent.
/// `invoice_amount_msat` stands in for it when we never saw the invoice
/// accepted.
///
/// Leaves the held sum and the HTLC deadline as they were: they record what
/// we were racing.
pub async fn mark_hold_settled<T: GenericClient>(
	client: &T,
	id: i64,
	invoice_amount_msat: u64,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		UPDATE cln_hold
		SET status = 'paid', paid_amount_msat = COALESCE(accepted_amount_msat, $2),
			paid_at = COALESCE(paid_at, NOW()), updated_at = NOW()
		WHERE id = $1 AND status IN ('unpaid', 'accepted')
		RETURNING {HOLD_COLUMNS}
	"), &[Type::INT8, Type::INT8]).await?;

	let invoice_amount_msat = i64::try_from(invoice_amount_msat)
		.context("invoice_amount_msat is too large to store")?;

	let row = client.query_opt(&stmt, &[&id, &invoice_amount_msat]).await
		.context("failed to mark hold invoice settled")?;

	row.map(ClnHoldRecord::try_from).transpose()
}

/// Record that we stopped serving this invoice.
///
/// Returns `None` when the invoice had already reached a terminal state, so of
/// the writers that race to cancel it exactly one gets the row.
///
/// Leaves the held sum and the HTLC deadline as they were: they record what
/// we were racing.
pub async fn mark_hold_cancelled<T: GenericClient>(
	client: &T,
	id: i64,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		UPDATE cln_hold
		SET status = 'cancelled', cancelled_at = COALESCE(cancelled_at, NOW()),
			updated_at = NOW()
		WHERE id = $1 AND status IN ('unpaid', 'accepted')
		RETURNING {HOLD_COLUMNS}
	"), &[Type::INT8]).await?;

	let row = client.query_opt(&stmt, &[&id]).await
		.context("failed to mark hold invoice cancelled")?;

	row.map(ClnHoldRecord::try_from).transpose()
}

/// A state the plugin reported for an invoice, to be copied onto its row.
#[derive(Debug, Clone, Copy)]
pub enum HoldTransition {
	/// The node holds HTLCs that sum to this and run out at this height.
	Accepted {
		amount_msat: u64,
		lowest_incoming_htlc_expiry: BlockHeight,
	},
	/// We revealed the preimage and took the held HTLCs.
	Settled {
		/// What the invoice asked for, in case we never saw what was held.
		invoice_amount_msat: u64,
	},
	/// We stopped serving the invoice.
	Cancelled,
}

/// Copy a plugin state onto the open invoice of this payment hash on this node.
///
/// The hold process and the node manager learn about an invoice by node and
/// payment hash, not by row id, so this finds the row for them. Returns `None`
/// when there is no open invoice to move: the subscription predates `cln_hold`
/// and has not been backfilled, or the invoice already ended. Both are for the
/// caller to log, not to fail on; the plugin remains the authority.
pub async fn transition_open_hold<T: GenericClient>(
	client: &T,
	node_id: LightningNodeId,
	payment_hash: PaymentHash,
	transition: HoldTransition,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let Some(hold) = get_open_hold_by_payment_hash(client, node_id, payment_hash).await? else {
		return Ok(None);
	};

	match transition {
		HoldTransition::Accepted { amount_msat, lowest_incoming_htlc_expiry } => {
			mark_hold_accepted(client, hold.id, amount_msat, lowest_incoming_htlc_expiry).await
		},
		HoldTransition::Settled { invoice_amount_msat } => {
			mark_hold_settled(client, hold.id, invoice_amount_msat).await
		},
		HoldTransition::Cancelled => mark_hold_cancelled(client, hold.id).await,
	}
}

/// Every invoice on this node that can still change state, oldest first.
pub async fn get_open_holds<T: GenericClient>(
	client: &T,
	node_id: LightningNodeId,
) -> anyhow::Result<Vec<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {HOLD_COLUMNS}
		FROM cln_hold
		WHERE lightning_node_id = $1 AND status IN ('unpaid', 'accepted')
		ORDER BY id
	"), &[Type::INT8]).await?;

	let rows = client.query(&stmt, &[&node_id]).await
		.context("failed to list open hold invoices")?;

	rows.into_iter().map(ClnHoldRecord::try_from).collect()
}

/// The invoice on this node and payment hash that can still change state.
///
/// A payment hash is served by at most one invoice at a time: the subscription
/// it belongs to is unique per hash, and a new invoice is only issued once the
/// old one has ended. Returns the newest if that ever does not hold.
pub async fn get_open_hold_by_payment_hash<T: GenericClient>(
	client: &T,
	node_id: LightningNodeId,
	payment_hash: PaymentHash,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {HOLD_COLUMNS}
		FROM cln_hold
		WHERE lightning_node_id = $1 AND payment_hash = $2
			AND status IN ('unpaid', 'accepted')
		ORDER BY id DESC
		LIMIT 1
	"), &[Type::INT8, Type::TEXT]).await?;

	let row = client.query_opt(&stmt, &[&node_id, &payment_hash.to_string()]).await
		.context("failed to get open hold invoice by payment hash")?;

	row.map(ClnHoldRecord::try_from).transpose()
}

pub async fn get_hold_by_id<T: GenericClient>(
	client: &T,
	id: i64,
) -> anyhow::Result<Option<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {HOLD_COLUMNS}
		FROM cln_hold
		WHERE id = $1
	"), &[Type::INT8]).await?;

	let row = client.query_opt(&stmt, &[&id]).await.context("failed to get hold invoice")?;

	row.map(ClnHoldRecord::try_from).transpose()
}

/// Every invoice on this payment hash, oldest first.
///
/// A payment hash can carry more than one invoice over its life, so this
/// returns them all.
pub async fn get_holds_by_payment_hash<T: GenericClient>(
	client: &T,
	payment_hash: PaymentHash,
) -> anyhow::Result<Vec<ClnHoldRecord>> {
	let stmt = client.prepare_typed(&format!("
		SELECT {HOLD_COLUMNS}
		FROM cln_hold
		WHERE payment_hash = $1
		ORDER BY id
	"), &[Type::TEXT]).await?;

	let rows = client.query(&stmt, &[&payment_hash.to_string()]).await
		.context("failed to list hold invoices by payment hash")?;

	rows.into_iter().map(ClnHoldRecord::try_from).collect()
}
