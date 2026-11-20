//! The posd HTTP API. The contract is in `pos/docs/api.md`.

mod lnurl;
mod owner;
mod terminal;
mod web;

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::routing::{delete, get, post};

use crate::App;
use crate::database::{Device, STORE_COLUMNS, Store};
use crate::error::ApiError;
use crate::token;


pub fn router(app: Arc<App>) -> Router {
	let api = Router::new()
		.route("/pair", post(terminal::pair))
		.route("/terminal", get(terminal::terminal))
		.route("/rate", get(terminal::rate))
		.route("/sales", post(terminal::create_sale).get(terminal::list_sales))
		.route("/sales.csv", get(terminal::sales_csv))
		.route("/sales/{id}", get(terminal::get_sale))
		.route("/sales/{id}/cancel", post(terminal::cancel_sale))
		.route("/stores", post(owner::register))
		.route("/owner/challenge", post(owner::challenge))
		.route("/owner/login", post(owner::login))
		.route("/owner/store", get(owner::get_store).patch(owner::update_store))
		.route("/owner/invites", post(owner::create_invite))
		.route("/owner/devices", get(owner::list_devices))
		.route("/owner/devices/{id}", delete(owner::revoke_device))
		.route("/owner/sales", get(owner::list_sales))
		.route("/owner/sales.csv", get(owner::sales_csv))
		.route("/lnurlp/{name}/callback", get(lnurl::callback))
		.fallback(|| async { ApiError::NotFound("no such endpoint".into()) });

	Router::new()
		.nest("/api/v1", api)
		.route("/.well-known/lnurlp/{name}", get(lnurl::pay_request))
		.route("/pair/{code}/manifest.webmanifest", get(web::pair_manifest))
		.route("/pair/{code}", get(web::index))
		.fallback(web::asset)
		.with_state(app)
}

fn bearer(parts: &Parts) -> Result<&str, ApiError> {
	parts.headers.get(AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.and_then(|v| v.strip_prefix("Bearer "))
		.map(str::trim)
		.filter(|t| !t.is_empty())
		.ok_or(ApiError::Unauthorized)
}

/// A paired terminal, from its bearer token.
pub struct Terminal {
	pub device: Device,
	pub store: Store,
}

impl FromRequestParts<Arc<App>> for Terminal {
	type Rejection = ApiError;

	async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
		let hash = token::hash(bearer(parts)?);
		let conn = app.db.conn().await?;
		let row = conn.query_opt(&format!("
			SELECT {}, d.id AS device_id, d.store_id AS device_store_id, d.name AS device_name,
				d.created_at AS device_created_at, d.revoked_at AS device_revoked_at
			FROM device d JOIN store s ON s.id = d.store_id
			WHERE d.token_hash = $1 AND d.revoked_at IS NULL
		", STORE_COLUMNS), &[&hash]).await?.ok_or(ApiError::Unauthorized)?;
		Ok(Terminal {
			device: Device {
				id: row.get("device_id"),
				store_id: row.get("device_store_id"),
				name: row.get("device_name"),
				created_at: row.get("device_created_at"),
				revoked_at: row.get("device_revoked_at"),
			},
			store: Store::from_row(&row),
		})
	}
}

/// The owner of a store, from an owner session token.
pub struct Owner {
	pub store: Store,
}

impl FromRequestParts<Arc<App>> for Owner {
	type Rejection = ApiError;

	async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Self::Rejection> {
		let hash = token::hash(bearer(parts)?);
		let conn = app.db.conn().await?;
		let row = conn.query_opt(&format!("
			SELECT {} FROM owner_session o JOIN store s ON s.id = o.store_id
			WHERE o.token_hash = $1 AND o.expires_at > NOW()
		", STORE_COLUMNS), &[&hash]).await?.ok_or(ApiError::Unauthorized)?;
		Ok(Owner { store: Store::from_row(&row) })
	}
}

/// How a store looks to the API.
#[derive(Debug, serde::Serialize)]
pub struct StoreView {
	pub name: String,
	pub currency: String,
	pub onchain_min_sat: i64,
	pub lightning_address: Option<String>,
}

impl StoreView {
	pub fn new(app: &App, store: &Store) -> StoreView {
		StoreView {
			name: store.name.clone(),
			currency: store.currency.clone(),
			onchain_min_sat: store.onchain_min_sat,
			lightning_address: store.lightning_address_name.as_ref()
				.map(|n| format!("{}@{}", n, public_host(app))),
		}
	}
}

/// The host of the public URL, for the Lightning address.
pub fn public_host(app: &App) -> String {
	url::Url::parse(&app.cfg.http.public_url).ok()
		.and_then(|u| u.host_str().map(|h| match u.port() {
			Some(p) => format!("{}:{}", h, p),
			None => h.to_string(),
		}))
		.unwrap_or_default()
}
