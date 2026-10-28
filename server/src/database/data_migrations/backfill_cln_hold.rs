use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Local};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use tokio_postgres::types::Type;

use bitcoin_ext::BlockDelta;

use crate::database::Db;

/// Backfill the cln_hold table from the existing lightning_htlc_subscription
/// rows.
///
/// V76 could not port these rows itself: the invoice expiry and the final
/// CLTV delta live inside the bolt11 string, which SQL cannot decode. This
/// decodes them and writes one cln_hold row per subscription that has none
/// yet, so it can run again after a partial run.
///
/// The subscription status maps onto the plugin's: created is unpaid,
/// accepted and htlcs-ready are accepted, settled is paid and canceled is
/// cancelled. An intra-Ark payment is the exception: accepting it canceled
/// the hold invoice on the node, so its row is cancelled whatever the
/// subscription went on to do. The attempt linked to the subscription (V55)
/// is what tells an intra-Ark payment apart.
///
/// The held sum of an accepted invoice was never recorded. The plugin only
/// accepts HTLCs that cover the invoice, so the requested amount is the
/// lower bound we know, and that is what is written.
pub async fn run(db: &Db) -> anyhow::Result<u64> {
	let reader = db.get_conn().await.context("reader connection")?;
	let writer = db.get_conn().await.context("writer connection")?;

	let select = reader.prepare(
		"SELECT lhs.id, lhs.lightning_node_id, lhs.payment_hash, lhs.invoice, \
			lhs.status::text AS status, lhs.final_amount_msat, \
			lhs.lowest_incoming_htlc_expiry, lhs.accepted_at, \
			lhs.created_at, lhs.updated_at, \
			EXISTS ( \
				SELECT 1 FROM lightning_payment_attempt lpa \
				WHERE lpa.lightning_htlc_subscription_id = lhs.id \
					AND lpa.status <> 'failed' \
			) AS intra_ark \
		 FROM lightning_htlc_subscription lhs \
		 WHERE NOT EXISTS ( \
			SELECT 1 FROM cln_hold h \
			WHERE h.lightning_node_id = lhs.lightning_node_id \
				AND h.payment_hash = lhs.payment_hash \
		 ) \
		 ORDER BY lhs.id",
	).await.context("preparing select")?;

	let insert = writer.prepare_typed(
		"INSERT INTO cln_hold ( \
			lightning_node_id, invoice, payment_hash, requested_amount_msat, \
			min_final_cltv_delta, expires_at, status, accepted_amount_msat, \
			lowest_incoming_htlc_expiry, paid_amount_msat, \
			created_at, accepted_at, paid_at, cancelled_at, updated_at \
		 ) VALUES ( \
			$1, $2, $3, $4, $5, $6, $7::cln_hold_status, $8, $9, $10, \
			$11, $12, $13, $14, $15 \
		 )",
		&[
			Type::INT8, Type::TEXT, Type::TEXT, Type::INT8,
			Type::INT4, Type::TIMESTAMPTZ, Type::TEXT, Type::INT8,
			Type::INT4, Type::INT8,
			Type::TIMESTAMPTZ, Type::TIMESTAMPTZ, Type::TIMESTAMPTZ, Type::TIMESTAMPTZ,
			Type::TIMESTAMPTZ,
		],
	).await.context("preparing insert")?;

	let rows = reader.query_raw(&select, &[] as &[&str; 0]).await
		.context("selecting htlc subscriptions")?;
	tokio::pin! { rows };

	let mut inserted: u64 = 0;
	let mut skipped: u64 = 0;

	while let Some(row) = rows.next().await {
		let row = row.context("reading htlc subscription row")?;
		let id: i64 = row.get("id");
		let node_id: i64 = row.get("lightning_node_id");
		let payment_hash: &str = row.get("payment_hash");
		let invoice_str: &str = row.get("invoice");
		let status: &str = row.get("status");
		let final_amount_msat: Option<i64> = row.get("final_amount_msat");
		let lowest_incoming_htlc_expiry: Option<i64> = row.get("lowest_incoming_htlc_expiry");
		let accepted_at: Option<DateTime<Local>> = row.get("accepted_at");
		let created_at: DateTime<Local> = row.get("created_at");
		let updated_at: DateTime<Local> = row.get("updated_at");
		let intra_ark: bool = row.get("intra_ark");

		let invoice = Bolt11Invoice::from_str(invoice_str)
			.with_context(|| format!("failed to parse invoice of subscription id={}", id))?;

		let requested_amount_msat = match final_amount_msat.or_else(|| {
			invoice.amount_milli_satoshis().and_then(|a| i64::try_from(a).ok())
		}) {
			Some(amount) => amount,
			None => {
				eprintln!("backfill_cln_hold: subscription id={} has no amount, skipping", id);
				skipped += 1;
				continue;
			},
		};

		let min_final_cltv_delta = BlockDelta::try_from(invoice.min_final_cltv_expiry_delta())
			.with_context(|| format!(
				"min_final_cltv_expiry_delta out of range for subscription id={}", id,
			))?;
		let min_final_cltv_delta = i32::try_from(min_final_cltv_delta.to_u32())
			.with_context(|| format!(
				"min_final_cltv_delta out of range for subscription id={}", id,
			))?;

		let expires_at = invoice.expires_at()
			.and_then(|d| i64::try_from(d.as_secs()).ok())
			.and_then(|secs| DateTime::from_timestamp(secs, 0))
			.map(|dt| dt.with_timezone(&Local))
			.with_context(|| format!("invoice of subscription id={} has no expiry", id))?;

		// The plugin's view of the invoice. An intra-Ark payment canceled the
		// hold invoice when the receive was accepted.
		let hold_status = match status {
			"created" => "unpaid",
			"accepted" | "htlcs-ready" if intra_ark => "cancelled",
			"settled" if intra_ark => "cancelled",
			"accepted" | "htlcs-ready" => "accepted",
			"settled" => "paid",
			"canceled" => "cancelled",
			other => anyhow::bail!("subscription id={} has unexpected status {}", id, other),
		};

		let lowest_incoming_htlc_expiry = lowest_incoming_htlc_expiry
			.map(i32::try_from)
			.transpose()
			.with_context(|| format!(
				"lowest_incoming_htlc_expiry out of range for subscription id={}", id,
			))?;
		let (accepted_amount_msat, lowest_incoming_htlc_expiry) = if hold_status == "accepted" {
			// An accepted hold is HTLCs: the row must carry their sum and
			// deadline. A subscription accepted without a deadline is not one
			// we can describe.
			let Some(expiry) = lowest_incoming_htlc_expiry else {
				eprintln!("backfill_cln_hold: subscription id={} is {} without a lowest \
					incoming htlc expiry, skipping", id, status,
				);
				skipped += 1;
				continue;
			};
			(Some(requested_amount_msat), Some(expiry))
		} else {
			(None, lowest_incoming_htlc_expiry)
		};
		let paid_amount_msat = (hold_status == "paid").then_some(requested_amount_msat);

		let paid_at = (hold_status == "paid").then_some(updated_at);
		let cancelled_at = match hold_status {
			// The intra-Ark cancel happened when the receive was accepted.
			"cancelled" if intra_ark => accepted_at.or(Some(updated_at)),
			"cancelled" => Some(updated_at),
			_ => None,
		};

		inserted += writer.execute(&insert, &[
			&node_id, &invoice_str, &payment_hash, &requested_amount_msat,
			&min_final_cltv_delta, &expires_at, &hold_status, &accepted_amount_msat,
			&lowest_incoming_htlc_expiry, &paid_amount_msat,
			&created_at, &accepted_at, &paid_at, &cancelled_at, &updated_at,
		]).await.with_context(|| format!("failed to insert cln_hold for subscription id={}", id))?;
	}

	eprintln!("backfill_cln_hold: inserted {} rows, skipped {}", inserted, skipped);
	Ok(inserted)
}
