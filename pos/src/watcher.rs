//! Watches the payment rails of recent sales and moves sales to their next
//! state.
//!
//! A sale is paid by the first rail that delivers its full amount. The
//! watcher keeps checking the other rails until they expire, so a second
//! payment is recorded as excess instead of being missed.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{Address, Amount};
use tokio_postgres::GenericClient;

use crate::App;
use crate::database::{Rail, SaleState, WatchedPayment};
use crate::rails::forward::ForwardStatus;


/// How long a Lightning or Ark payment is watched after its sale expires.
/// A payment made just before expiry can take a little while to deliver.
const DELIVERY_GRACE_SECS: f64 = 600.0;

/// On-chain addresses are checked every this many ticks.
const ONCHAIN_EVERY_TICKS: u64 = 5;

/// What a check found for one payment rail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
	/// Delivered to the owner. For on-chain, confirmed.
	pub received: Amount,
	/// Seen but not delivered. Only on-chain reports this.
	pub pending: Amount,
	/// Whether the rail is done: delivered, or certain never to pay.
	pub settled: bool,
	pub vtxo_ids: Option<Vec<String>>,
	pub txids: Option<Vec<String>>,
}

pub async fn run(app: Arc<App>) {
	let mut tick = 0u64;
	loop {
		if let Err(e) = run_once(&app, tick % ONCHAIN_EVERY_TICKS == 0).await {
			tracing::warn!("watcher pass failed: {:#}", e);
		}
		tick = tick.wrapping_add(1);
		tokio::time::sleep(app.cfg.sales.poll_interval()).await;
	}
}

/// One pass over all watched payments, then expiry.
pub async fn run_once(app: &App, check_onchain: bool) -> anyhow::Result<()> {
	let payments = watched_payments(app).await?;
	let mut changed = false;
	for p in payments {
		if p.rail == Rail::Onchain && !check_onchain {
			continue;
		}
		let obs = match observe(app, &p).await {
			Ok(Some(obs)) => obs,
			Ok(None) => continue,
			Err(e) => {
				tracing::warn!("check of sale {} ({}) failed: {:#}", p.sale_public_id, p.rail.as_str(), e);
				continue;
			},
		};
		changed |= record(app, &p, &obs).await?;
	}
	changed |= expire(app).await?;
	if changed {
		app.notify_sale_change();
	}
	Ok(())
}

async fn watched_payments(app: &App) -> anyhow::Result<Vec<WatchedPayment>> {
	let conn = app.db.conn().await?;
	let rows = conn.query("
		SELECT p.id AS payment_id, s.id AS sale_id, s.public_id, s.state, s.amount_sat,
			s.expires_at, p.rail, p.payment_hash, p.onchain_address, p.received_sat,
			p.pending_sat, p.settled_at, st.claim_pubkey, st.mailbox_id
		FROM sale_payment p
		JOIN sale s ON s.id = p.sale_id
		JOIN store st ON st.id = s.store_id
		WHERE p.settled_at IS NULL AND s.state <> 'canceled' AND (
			(p.rail <> 'onchain' AND s.expires_at > NOW() - make_interval(secs => $1))
			OR (p.rail = 'onchain' AND s.created_at > NOW() - make_interval(secs => $2))
		)
		ORDER BY p.id
	", &[&DELIVERY_GRACE_SECS, &(app.cfg.sales.onchain_watch_secs as f64)]).await?;
	Ok(rows.iter().map(WatchedPayment::from_row).collect())
}

/// Checks one rail. `None` means nothing new.
async fn observe(app: &App, p: &WatchedPayment) -> anyhow::Result<Option<Observation>> {
	match p.rail {
		Rail::Lightning => {
			let hash = p.payment_hash.as_deref().context("Lightning payment without hash")?;
			Ok(match app.forwarder.status(hash).await? {
				ForwardStatus::Pending => None,
				ForwardStatus::Delivered(amount) => Some(Observation {
					received: amount, pending: Amount::ZERO, settled: true,
					vtxo_ids: None, txids: None,
				}),
				// Canceled or expired unpaid: stop checking it.
				ForwardStatus::Gone => Some(Observation {
					received: Amount::ZERO, pending: Amount::ZERO, settled: true,
					vtxo_ids: None, txids: None,
				}),
			})
		},
		Rail::Ark => {
			let hash = p.payment_hash.as_deref().context("Ark payment without hash")?;
			let min = Amount::from_sat(p.sale_amount_sat as u64);
			let receipt = app.ark.receipt(hash, &p.claim_pubkey, &p.mailbox_id, min).await?;
			Ok(receipt.map(|r| Observation {
				received: r.amount, pending: Amount::ZERO, settled: true,
				vtxo_ids: Some(r.vtxo_ids), txids: None,
			}))
		},
		Rail::Onchain => {
			let address = p.onchain_address.as_deref().context("on-chain payment without address")?;
			let address = Address::from_str(address)?.require_network(app.cfg.network)?;
			let funds = app.chain.funds(&address).await?;
			let obs = Observation {
				received: funds.confirmed,
				pending: funds.pending,
				// An address stays watched for late or extra payments until
				// its watch window ends.
				settled: false,
				vtxo_ids: None,
				txids: Some(funds.txids),
			};
			let unchanged = obs.received.to_sat() as i64 == p.received_sat
				&& obs.pending.to_sat() as i64 == p.pending_sat;
			Ok(if unchanged { None } else { Some(obs) })
		},
	}
}

/// The state a sale moves to after an observation, if it changes.
pub fn next_state(
	state: SaleState,
	amount_sat: i64,
	rail: Rail,
	obs: &Observation,
	expired: bool,
) -> Option<SaleState> {
	if !state.is_live() {
		return None;
	}
	let received = obs.received.to_sat() as i64;
	let pending = obs.pending.to_sat() as i64;
	let delivered = match rail {
		Rail::Onchain => received >= amount_sat,
		Rail::Lightning | Rail::Ark => obs.settled && received >= amount_sat,
	};
	if delivered {
		return Some(SaleState::Paid);
	}
	if rail == Rail::Onchain {
		if received + pending >= amount_sat {
			if state == SaleState::Open {
				return Some(SaleState::InProgress);
			}
		} else if state == SaleState::InProgress {
			// The mempool payment went away.
			return Some(if expired { SaleState::Expired } else { SaleState::Open });
		}
	}
	None
}

/// Stores an observation and moves the sale on. Returns whether a sale
/// changed state.
async fn record(app: &App, p: &WatchedPayment, obs: &Observation) -> anyhow::Result<bool> {
	let mut conn = app.db.conn().await?;
	let tx = conn.transaction().await?;

	// Lock the sale, so two payments cannot both mark it paid.
	let row = tx.query_one(
		"SELECT state, amount_sat, expires_at < NOW() AS expired FROM sale WHERE id = $1 FOR UPDATE",
		&[&p.sale_id],
	).await?;
	let state: SaleState = row.get("state");
	let amount_sat: i64 = row.get("amount_sat");
	let expired: bool = row.get("expired");

	tx.execute("
		UPDATE sale_payment SET received_sat = $2, pending_sat = $3,
			settled_at = CASE WHEN $4 THEN NOW() END,
			vtxo_ids = coalesce($5, vtxo_ids), txids = coalesce($6, txids)
		WHERE id = $1
	", &[
		&p.payment_id, &(obs.received.to_sat() as i64), &(obs.pending.to_sat() as i64),
		&obs.settled, &obs.vtxo_ids, &obs.txids,
	]).await?;
	tx.execute("
		UPDATE sale SET received_sat = (
			SELECT coalesce(sum(received_sat), 0) FROM sale_payment WHERE sale_id = $1
		), updated_at = NOW() WHERE id = $1
	", &[&p.sale_id]).await?;

	let next = next_state(state, amount_sat, p.rail, obs, expired);
	if let Some(next) = next {
		let paid = next == SaleState::Paid;
		tx.execute("
			UPDATE sale SET state = $2,
				paid_rail = CASE WHEN $3 THEN $4 ELSE paid_rail END,
				paid_at = CASE WHEN $3 THEN NOW() ELSE paid_at END
			WHERE id = $1
		", &[&p.sale_id, &next, &paid, &p.rail]).await?;
	}
	tx.commit().await?;

	if next == Some(SaleState::Paid) {
		tracing::info!("sale {} paid by {}", p.sale_public_id, p.rail.as_str());
		if p.rail != Rail::Lightning {
			cancel_forward_invoice(app, p.sale_id).await;
		}
	}
	Ok(next.is_some())
}

/// Cancels the forwarding invoice of a sale paid by another rail, so a
/// second payment is less likely. It is best effort: a payment already in
/// flight still completes and counts as excess.
pub async fn cancel_forward_invoice(app: &App, sale_id: i64) {
	let hash = match lightning_hash(app, sale_id).await {
		Ok(Some(h)) => h,
		Ok(None) => return,
		Err(e) => {
			tracing::warn!("failed to load the invoice of sale {}: {:#}", sale_id, e);
			return;
		},
	};
	if let Err(e) = app.forwarder.cancel(&hash).await {
		tracing::info!("forwarding invoice {} stays open: {:#}", hash, e);
	}
}

async fn lightning_hash(app: &App, sale_id: i64) -> anyhow::Result<Option<String>> {
	let conn = app.db.conn().await?;
	let row = conn.query_opt(
		"SELECT payment_hash FROM sale_payment WHERE sale_id = $1 AND rail = 'lightning' AND settled_at IS NULL",
		&[&sale_id],
	).await?;
	Ok(row.and_then(|r| r.get("payment_hash")))
}

/// Expires open sales past their expiry. An `in-progress` sale stays open
/// for its mempool payment.
async fn expire(app: &App) -> anyhow::Result<bool> {
	let conn = app.db.conn().await?;
	let n = expire_sales(&*conn).await?;
	Ok(n > 0)
}

pub async fn expire_sales(conn: &impl GenericClient) -> anyhow::Result<u64> {
	Ok(conn.execute("
		UPDATE sale SET state = 'expired', updated_at = NOW()
		WHERE state = 'open' AND expires_at < NOW()
	", &[]).await?)
}

#[cfg(test)]
mod test {
	use super::*;

	fn obs(received: u64, pending: u64, settled: bool) -> Observation {
		Observation {
			received: Amount::from_sat(received),
			pending: Amount::from_sat(pending),
			settled,
			vtxo_ids: None,
			txids: None,
		}
	}

	#[test]
	fn state_transitions() {
		use SaleState::*;
		// Lightning and Ark pay on delivery of the full amount.
		assert_eq!(next_state(Open, 1000, Rail::Lightning, &obs(1000, 0, true), false), Some(Paid));
		assert_eq!(next_state(Open, 1000, Rail::Ark, &obs(1200, 0, true), false), Some(Paid));
		assert_eq!(next_state(Open, 1000, Rail::Lightning, &obs(0, 0, true), false), None);
		// A rail that delivers after expiry still pays an expired sale? No:
		// an expired sale is final and the payment counts as excess.
		assert_eq!(next_state(Expired, 1000, Rail::Ark, &obs(1000, 0, true), true), None);
		assert_eq!(next_state(Paid, 1000, Rail::Ark, &obs(1000, 0, true), false), None);

		// On-chain: mempool, then 1 confirmation.
		assert_eq!(next_state(Open, 1000, Rail::Onchain, &obs(0, 1000, false), false), Some(InProgress));
		assert_eq!(next_state(InProgress, 1000, Rail::Onchain, &obs(0, 1000, false), true), None);
		assert_eq!(next_state(InProgress, 1000, Rail::Onchain, &obs(1000, 0, false), true), Some(Paid));
		// Underpaid on-chain stays open.
		assert_eq!(next_state(Open, 1000, Rail::Onchain, &obs(0, 500, false), false), None);
		// The mempool payment disappears.
		assert_eq!(next_state(InProgress, 1000, Rail::Onchain, &obs(0, 0, false), false), Some(Open));
		assert_eq!(next_state(InProgress, 1000, Rail::Onchain, &obs(0, 0, false), true), Some(Expired));
	}
}
