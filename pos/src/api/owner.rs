//! Owner endpoints: registration, login and store management.
//!
//! The owner is the Ark address that registered the store. It proves
//! control by signing with that address's key.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use bitcoin::secp256k1::schnorr;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::App;
use crate::api::terminal::{CsvQuery, ListQuery, csv, list};
use crate::api::{Owner, StoreView};
use crate::database::{Device, STORE_COLUMNS, Store};
use crate::error::{ApiResult, bad_request, conflict, not_found};
use crate::money::currency_decimals;
use crate::rails::onchain::StoreDescriptor;
use crate::registration::Registration;
use crate::token;


/// How far a registration timestamp may be from the server clock.
const REGISTRATION_CLOCK_SKEW_SECS: i64 = 600;
const CHALLENGE_LIFETIME_MINS: i64 = 5;
const SESSION_LIFETIME_HOURS: i64 = 24;
const INVITE_LIFETIME_HOURS: i64 = 24;

fn parse_signature(hex: &str) -> ApiResult<schnorr::Signature> {
	schnorr::Signature::from_str(hex).map_err(|_| bad_request("the signature is not valid hex"))
}

#[derive(Deserialize)]
pub struct RegisterRequest {
	registration: Registration,
	signature: String,
}

pub async fn register(
	State(app): State<Arc<App>>,
	Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<Value>> {
	let reg = req.registration;
	let signature = parse_signature(&req.signature)?;
	let info = app.ark.ark_info().await;
	let (ark_address, mailbox_id) = reg.verify(&signature, info.server_pubkey)
		.map_err(|e| bad_request(e.to_string()))?;

	let skew = (Utc::now().timestamp() - reg.timestamp as i64).abs();
	if skew > REGISTRATION_CLOCK_SKEW_SECS {
		return Err(bad_request("the registration timestamp is too far from the current time"));
	}
	let name = reg.name.trim();
	if name.is_empty() || name.chars().count() > 64 {
		return Err(bad_request("the store name must be 1 to 64 characters"));
	}
	if currency_decimals(&reg.currency).is_none() {
		return Err(bad_request(format!("unsupported currency: {}", reg.currency)));
	}
	StoreDescriptor::parse(&reg.onchain_descriptor).map_err(|e| bad_request(format!("{:#}", e)))?;

	let claim_pubkey = ark_address.policy().user_pubkey();
	let conn = app.db.conn().await?;
	let row = conn.query_opt(&format!("
		INSERT INTO store (name, ark_address, claim_pubkey, mailbox_id, onchain_descriptor,
			currency, onchain_min_sat, registration_signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (ark_address) DO NOTHING
		RETURNING {}
	", STORE_COLUMNS.replace("s.", "")), &[
		&name, &ark_address.to_string(), &claim_pubkey.to_string(),
		&mailbox_id.to_string(), &reg.onchain_descriptor, &reg.currency,
		&(app.cfg.sales.default_onchain_min_sat as i64), &signature.to_string(),
	]).await?;
	let store = row.map(|r| Store::from_row(&r))
		.ok_or_else(|| conflict("a store is already registered for this Ark address"))?;
	Ok(Json(json!({ "store": StoreView::new(&app, &store) })))
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
	ark_address: String,
}

pub async fn challenge(
	State(app): State<Arc<App>>,
	Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<Value>> {
	let expires_at = Utc::now() + Duration::minutes(CHALLENGE_LIFETIME_MINS);
	let challenge = format!(
		"scuttle-pos login v1\nark_address:{}\nnonce:{}\nexpires_at:{}",
		req.ark_address, token::random_hex(16), expires_at.timestamp(),
	);
	let conn = app.db.conn().await?;
	conn.execute(
		"INSERT INTO owner_challenge (ark_address, challenge, expires_at) VALUES ($1, $2, $3)",
		&[&req.ark_address, &challenge, &expires_at],
	).await?;
	Ok(Json(json!({ "challenge": challenge })))
}

#[derive(Deserialize)]
pub struct LoginRequest {
	ark_address: String,
	challenge: String,
	signature: String,
}

pub async fn login(
	State(app): State<Arc<App>>,
	Json(req): Json<LoginRequest>,
) -> ApiResult<Json<Value>> {
	let address = ark::Address::from_str(&req.ark_address)
		.map_err(|_| bad_request("not a valid Ark address"))?;
	let signature = parse_signature(&req.signature)?;
	if !ark::message::verify_for_address(&address, req.challenge.as_bytes(), &signature) {
		return Err(bad_request("the signature does not verify for this address"));
	}

	let mut conn = app.db.conn().await?;
	let tx = conn.transaction().await?;
	let used = tx.execute("
		UPDATE owner_challenge SET used_at = NOW()
		WHERE challenge = $1 AND ark_address = $2 AND used_at IS NULL AND expires_at > NOW()
	", &[&req.challenge, &req.ark_address]).await?;
	if used == 0 {
		return Err(bad_request("the challenge is unknown, used or expired"));
	}
	let store_id: i64 = tx.query_opt("SELECT id FROM store WHERE ark_address = $1", &[&req.ark_address])
		.await?.ok_or_else(|| not_found("no store is registered for this Ark address"))?
		.get("id");
	let session_token = token::new_token();
	let expires_at = Utc::now() + Duration::hours(SESSION_LIFETIME_HOURS);
	tx.execute(
		"INSERT INTO owner_session (store_id, token_hash, expires_at) VALUES ($1, $2, $3)",
		&[&store_id, &token::hash(&session_token), &expires_at],
	).await?;
	tx.commit().await?;
	Ok(Json(json!({ "token": session_token, "expires_at": expires_at })))
}

pub async fn get_store(State(app): State<Arc<App>>, owner: Owner) -> Json<StoreView> {
	Json(StoreView::new(&app, &owner.store))
}

#[derive(Deserialize)]
pub struct UpdateStore {
	name: Option<String>,
	currency: Option<String>,
	onchain_min_sat: Option<u64>,
	/// An empty name removes the Lightning address.
	lightning_address_name: Option<String>,
}

/// A Lightning address name: lowercase letters, digits, `.`, `-` and `_`.
fn valid_lightning_name(name: &str) -> bool {
	!name.is_empty() && name.len() <= 64
		&& name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

pub async fn update_store(
	State(app): State<Arc<App>>,
	owner: Owner,
	Json(req): Json<UpdateStore>,
) -> ApiResult<Json<StoreView>> {
	if let Some(name) = &req.name {
		if name.trim().is_empty() || name.trim().chars().count() > 64 {
			return Err(bad_request("the store name must be 1 to 64 characters"));
		}
	}
	if let Some(c) = &req.currency {
		if currency_decimals(c).is_none() {
			return Err(bad_request(format!("unsupported currency: {}", c)));
		}
	}
	let ln_name = match req.lightning_address_name.as_deref() {
		None => None,
		Some("") => Some(None),
		Some(n) if valid_lightning_name(n) => Some(Some(n.to_string())),
		Some(_) => return Err(bad_request(
			"a Lightning address name has only lowercase letters, digits, '.', '-' and '_'",
		)),
	};

	let conn = app.db.conn().await?;
	let row = conn.query_one(&format!("
		UPDATE store s SET
			name = coalesce($2, name),
			currency = coalesce($3, currency),
			onchain_min_sat = coalesce($4, onchain_min_sat),
			lightning_address_name = CASE WHEN $5 THEN $6 ELSE lightning_address_name END,
			updated_at = NOW()
		WHERE id = $1
		RETURNING {}
	", STORE_COLUMNS), &[
		&owner.store.id, &req.name.map(|n| n.trim().to_string()), &req.currency,
		&req.onchain_min_sat.map(|v| v as i64), &ln_name.is_some(), &ln_name.flatten(),
	]).await.map_err(|e| {
		if e.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
			conflict("that Lightning address name is taken")
		} else {
			e.into()
		}
	})?;
	Ok(Json(StoreView::new(&app, &Store::from_row(&row))))
}

pub async fn create_invite(State(app): State<Arc<App>>, owner: Owner) -> ApiResult<Json<Value>> {
	let code = token::new_code();
	let expires_at = Utc::now() + Duration::hours(INVITE_LIFETIME_HOURS);
	let conn = app.db.conn().await?;
	conn.execute(
		"INSERT INTO invite (store_id, code_hash, expires_at) VALUES ($1, $2, $3)",
		&[&owner.store.id, &token::hash(&code), &expires_at],
	).await?;
	let url = format!("{}/pair/{}", app.cfg.http.public_url.trim_end_matches('/'), code);
	Ok(Json(json!({ "code": code, "url": url, "expires_at": expires_at })))
}

pub async fn list_devices(State(app): State<Arc<App>>, owner: Owner) -> ApiResult<Json<Value>> {
	let conn = app.db.conn().await?;
	let rows = conn.query("
		SELECT id, store_id, name, created_at, revoked_at FROM device
		WHERE store_id = $1 ORDER BY id
	", &[&owner.store.id]).await?;
	let devices = rows.iter().map(Device::from_row).map(|d| json!({
		"id": d.id, "name": d.name, "created_at": d.created_at, "revoked_at": d.revoked_at,
	})).collect::<Vec<_>>();
	Ok(Json(json!({ "devices": devices })))
}

pub async fn revoke_device(
	State(app): State<Arc<App>>,
	owner: Owner,
	Path(id): Path<i64>,
) -> ApiResult<impl IntoResponse> {
	let conn = app.db.conn().await?;
	let n = conn.execute("
		UPDATE device SET revoked_at = coalesce(revoked_at, NOW())
		WHERE id = $1 AND store_id = $2
	", &[&id, &owner.store.id]).await.context("revoke failed")?;
	if n == 0 {
		return Err(not_found("no such device"));
	}
	Ok(StatusCode::NO_CONTENT)
}

pub async fn list_sales(
	State(app): State<Arc<App>>,
	owner: Owner,
	Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
	list(&app, &owner.store, q).await
}

pub async fn sales_csv(
	State(app): State<Arc<App>>,
	owner: Owner,
	Query(q): Query<CsvQuery>,
) -> ApiResult<axum::response::Response> {
	csv(&app, &owner.store, q).await
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn lightning_names() {
		assert!(valid_lightning_name("cafe.uvita_1-2"));
		assert!(!valid_lightning_name("Cafe"));
		assert!(!valid_lightning_name(""));
		assert!(!valid_lightning_name("a b"));
		assert!(!valid_lightning_name("a@b"));
	}
}
