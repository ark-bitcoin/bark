//! Lightning address (LUD-06 and LUD-16).
//!
//! The Ark server cannot put a description hash in an invoice, so the
//! invoice carries the metadata's text description, not its hash. Wallets
//! that enforce the LUD-06 hash check refuse these invoices.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use bitcoin::Amount;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::App;
use crate::api::public_host;
use crate::database::{STORE_COLUMNS, Store};
use crate::error::{ApiResult, bad_request, not_found};
use crate::sales::{self, SaleAmount};


const MIN_SENDABLE_MSAT: u64 = 1_000;

async fn store_by_name(app: &App, name: &str) -> ApiResult<Store> {
	let conn = app.db.conn().await?;
	let row = conn.query_opt(
		&format!("SELECT {} FROM store s WHERE s.lightning_address_name = $1", STORE_COLUMNS),
		&[&name],
	).await?.ok_or_else(|| not_found("no such Lightning address"))?;
	Ok(Store::from_row(&row))
}

fn metadata(app: &App, store: &Store, name: &str) -> String {
	json!([
		["text/plain", format!("Payment to {}", store.name)],
		["text/identifier", format!("{}@{}", name, public_host(app))],
	]).to_string()
}

pub async fn pay_request(
	State(app): State<Arc<App>>,
	Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
	let store = store_by_name(&app, &name).await?;
	Ok(Json(json!({
		"tag": "payRequest",
		"callback": format!("{}/api/v1/lnurlp/{}/callback",
			app.cfg.http.public_url.trim_end_matches('/'), name),
		"minSendable": MIN_SENDABLE_MSAT,
		"maxSendable": app.cfg.sales.lnurl_max_sat * 1000,
		"metadata": metadata(&app, &store, &name),
	})))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
	amount: u64,
}

pub async fn callback(
	State(app): State<Arc<App>>,
	Path(name): Path<String>,
	Query(q): Query<CallbackQuery>,
) -> ApiResult<Json<Value>> {
	let store = store_by_name(&app, &name).await?;
	if q.amount < MIN_SENDABLE_MSAT || q.amount > app.cfg.sales.lnurl_max_sat * 1000 {
		return Err(bad_request("the amount is out of range"));
	}
	if q.amount % 1000 != 0 {
		return Err(bad_request("the amount must be whole sats"));
	}
	let sale = sales::create_sale(
		&app, &store, None, SaleAmount::Sat(Amount::from_sat(q.amount / 1000)), None, true,
	).await?;
	let pr = sale.lightning_invoice.ok_or_else(|| anyhow::anyhow!("sale has no invoice"))?;
	Ok(Json(json!({ "pr": pr, "routes": [] })))
}
