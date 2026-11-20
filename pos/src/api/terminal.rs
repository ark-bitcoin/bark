//! Terminal endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::App;
use crate::api::{StoreView, Terminal};
use crate::database::{STORE_COLUMNS, SaleState, Store};
use crate::error::{ApiError, ApiResult, bad_request, conflict, not_found};
use crate::money::Decimal;
use crate::sales::{self, SaleAmount, SaleView};
use crate::{token, watcher};


/// The longest a long-poll waits.
const LONG_POLL: Duration = Duration::from_secs(25);

#[derive(Deserialize)]
pub struct PairRequest {
	code: String,
	device_name: String,
}

#[derive(Serialize)]
pub struct PairResponse {
	token: String,
	store: StoreView,
}

pub async fn pair(
	State(app): State<Arc<App>>,
	Json(req): Json<PairRequest>,
) -> ApiResult<Json<PairResponse>> {
	let name = req.device_name.trim();
	if name.is_empty() || name.chars().count() > 64 {
		return Err(bad_request("the device name must be 1 to 64 characters"));
	}

	let mut conn = app.db.conn().await?;
	let tx = conn.transaction().await?;
	// Locking the invite row makes a code work exactly once.
	let row = tx.query_opt(&format!("
		SELECT i.id AS invite_id, {} FROM invite i JOIN store s ON s.id = i.store_id
		WHERE i.code_hash = $1 AND i.redeemed_at IS NULL AND i.expires_at > NOW()
		FOR UPDATE OF i
	", STORE_COLUMNS), &[&token::hash(req.code.trim())]).await?
		.ok_or_else(|| not_found("the pairing code is unknown, used or expired"))?;
	let invite_id: i64 = row.get("invite_id");
	let store = Store::from_row(&row);

	let device_token = token::new_token();
	let device_id: i64 = tx.query_one(
		"INSERT INTO device (store_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id",
		&[&store.id, &name, &token::hash(&device_token)],
	).await?.get("id");
	tx.execute(
		"UPDATE invite SET redeemed_at = NOW(), device_id = $2 WHERE id = $1",
		&[&invite_id, &device_id],
	).await?;
	tx.commit().await?;

	Ok(Json(PairResponse { token: device_token, store: StoreView::new(&app, &store) }))
}

pub async fn terminal(State(app): State<Arc<App>>, t: Terminal) -> Json<Value> {
	Json(json!({ "store": StoreView::new(&app, &t.store), "device_name": t.device.name }))
}

pub async fn rate(State(app): State<Arc<App>>, t: Terminal) -> ApiResult<Json<Value>> {
	let quote = app.price.quote(&t.store.currency).await.map_err(ApiError::Upstream)?;
	Ok(Json(json!({
		"currency": quote.currency,
		"btc_price": quote.btc_price.to_string(),
		"fetched_at": quote.fetched_at,
	})))
}

#[derive(Deserialize)]
pub struct CreateSale {
	fiat_amount: Option<String>,
	amount_sat: Option<u64>,
	memo: Option<String>,
}

pub async fn create_sale(
	State(app): State<Arc<App>>,
	t: Terminal,
	Json(req): Json<CreateSale>,
) -> ApiResult<Json<SaleView>> {
	let amount = match (req.fiat_amount, req.amount_sat) {
		(Some(fiat), None) => SaleAmount::Fiat(fiat.parse::<Decimal>()
			.map_err(|e| bad_request(e.to_string()))?),
		(None, Some(sat)) => SaleAmount::Sat(bitcoin::Amount::from_sat(sat)),
		_ => return Err(bad_request("give exactly one of fiat_amount and amount_sat")),
	};
	let sale = sales::create_sale(&app, &t.store, Some(t.device.id), amount, req.memo, false).await?;
	Ok(Json(sale.into()))
}

#[derive(Deserialize)]
pub struct WaitQuery {
	wait: Option<String>,
}

pub async fn get_sale(
	State(app): State<Arc<App>>,
	t: Terminal,
	Path(id): Path<String>,
	Query(q): Query<WaitQuery>,
) -> ApiResult<Json<SaleView>> {
	let wait = q.wait.map(|w| w.parse::<SaleState>().map_err(|e| bad_request(e.to_string())))
		.transpose()?;
	let deadline = tokio::time::Instant::now() + LONG_POLL;
	loop {
		// Subscribe before reading, so a change between the read and the
		// wait is not missed.
		let mut changes = app.sale_changes.subscribe();
		let sale = {
			let conn = app.db.conn().await?;
			sales::get_sale(&*conn, t.store.id, &id).await?
		};
		let done = match wait {
			Some(state) => sale.state != state,
			None => true,
		};
		let now = tokio::time::Instant::now();
		if done || now >= deadline {
			return Ok(Json(sale.into()));
		}
		let _ = tokio::time::timeout(deadline - now, changes.changed()).await;
	}
}

pub async fn cancel_sale(
	State(app): State<Arc<App>>,
	t: Terminal,
	Path(id): Path<String>,
) -> ApiResult<Json<SaleView>> {
	let sale = {
		let conn = app.db.conn().await?;
		let n = conn.execute("
			UPDATE sale SET state = 'canceled', updated_at = NOW()
			WHERE store_id = $1 AND public_id = $2 AND state = 'open'
		", &[&t.store.id, &id]).await?;
		let sale = sales::get_sale(&*conn, t.store.id, &id).await?;
		if n == 0 {
			return Err(conflict(format!("the sale is {}", sale.state)));
		}
		sale
	};
	watcher::cancel_forward_invoice(&app, sale.id).await;
	app.notify_sale_change();
	Ok(Json(sale.into()))
}

#[derive(Deserialize)]
pub struct ListQuery {
	pub before: Option<String>,
	pub limit: Option<i64>,
}

pub async fn list_sales(
	State(app): State<Arc<App>>,
	t: Terminal,
	Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
	list(&app, &t.store, q).await
}

pub async fn list(app: &App, store: &Store, q: ListQuery) -> ApiResult<Json<Value>> {
	let conn = app.db.conn().await?;
	let sales = sales::list_sales(&*conn, store.id, q.before.as_deref(), q.limit.unwrap_or(50)).await?;
	let sales = sales.into_iter().map(SaleView::from).collect::<Vec<_>>();
	Ok(Json(json!({ "sales": sales })))
}

#[derive(Deserialize)]
pub struct CsvQuery {
	pub from: Option<String>,
	pub to: Option<String>,
}

pub async fn sales_csv(
	State(app): State<Arc<App>>,
	t: Terminal,
	Query(q): Query<CsvQuery>,
) -> ApiResult<Response> {
	csv(&app, &t.store, q).await
}

pub async fn csv(app: &App, store: &Store, q: CsvQuery) -> ApiResult<Response> {
	let from = q.from.as_deref().map(|d| parse_date(d, false)).transpose()?;
	let to = q.to.as_deref().map(|d| parse_date(d, true)).transpose()?;
	let conn = app.db.conn().await?;
	let body = sales::sales_csv(&*conn, store.id, from, to).await?;
	Ok((
		[
			(header::CONTENT_TYPE, "text/csv; charset=utf-8"),
			(header::CONTENT_DISPOSITION, "attachment; filename=\"sales.csv\""),
		],
		body,
	).into_response())
}

/// An RFC 3339 time, or a date in UTC. A date as the end of a range
/// includes that whole day.
fn parse_date(s: &str, end: bool) -> ApiResult<DateTime<Utc>> {
	if let Ok(t) = DateTime::parse_from_rfc3339(s) {
		return Ok(t.with_timezone(&Utc));
	}
	let day = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
		.ok_or_else(|| bad_request(format!("not a date: {}", s)))?;
	let day = if end { day.succ_opt().ok_or_else(|| bad_request("date out of range"))? } else { day };
	Ok(day.and_hms_opt(0, 0, 0).expect("midnight exists").and_utc())
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn date_ranges() {
		assert_eq!(parse_date("2026-11-20", false).unwrap().to_rfc3339(), "2026-11-20T00:00:00+00:00");
		assert_eq!(parse_date("2026-11-20", true).unwrap().to_rfc3339(), "2026-11-21T00:00:00+00:00");
		assert_eq!(parse_date("2026-11-20T10:00:00Z", true).unwrap().to_rfc3339(), "2026-11-20T10:00:00+00:00");
		assert!(parse_date("20/11/2026", false).is_err());
	}
}
