use std::str::FromStr;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bark::lightning_utils::{pay_invoice, pay_lnaddr, pay_offer};
use bitcoin::Amount;
use anyhow::Context;
use utoipa::OpenApi;

use ark::lightning::Offer;
use bark::lightning_invoice::Bolt11Invoice;
use bark::lnurllib::lightning_address::LightningAddress;

use crate::error::HandlerResult;
use crate::BarkWebState;

#[derive(OpenApi)]
#[openapi(
	paths(
		lightning_invoice,
		lightning_invoices,
		lightning_status,
		lightning_pay,
	),
	components(schemas(
		bark_json::web::LightningInvoiceRequest,
		bark_json::cli::InvoiceInfo,
		bark_json::web::LightningStatusRequest,
		bark_json::web::LightningStatusResponse,
		bark_json::cli::LightningReceiveInfo,
		bark_json::web::LightningPayRequest,
		bark_json::web::LightningPayResponse,
	)),
	tags((name = "lightning", description = "Lightning-related endpoints"))
)]
pub struct LightningApiDoc;

pub fn router() -> Router<BarkWebState> {
	Router::new()
		.route("/receive/invoice", post(lightning_invoice))
		.route("/receive/invoices", get(lightning_invoices))
		.route("/receive/status", get(lightning_status))
		.route("/pay", post(lightning_pay))
}

#[utoipa::path(
	post,
	path = "/receive/invoice",
	request_body = bark_json::web::LightningInvoiceRequest,
	responses(
		(status = 200, description = "Returns the created invoice", body = bark_json::cli::InvoiceInfo),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	tag = "lightning"
)]
#[debug_handler]
pub async fn lightning_invoice(
	State(state): State<BarkWebState>,
	Json(params): Json<bark_json::web::LightningInvoiceRequest>,
) -> HandlerResult<Json<bark_json::cli::InvoiceInfo>> {
	let wallet_lock = state.wallet.read().await;

	let amount = Amount::from_sat(params.amount_sat);
	let invoice = wallet_lock.bolt11_invoice(amount).await
		.context("Failed to create invoice")?;

	Ok(axum::Json(bark_json::cli::InvoiceInfo {
		invoice: invoice.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/receive/status",
	request_body = bark_json::web::LightningStatusRequest,
	responses(
		(status = 200, description = "Returns the lightning receive status", body = bark_json::web::LightningStatusResponse),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	tag = "lightning"
)]
#[debug_handler]
pub async fn lightning_status(
	State(state): State<BarkWebState>,
	Query(params): Query<bark_json::web::LightningStatusRequest>,
) -> HandlerResult<Json<bark_json::web::LightningStatusResponse>> {
	let wallet_lock = state.wallet.read().await;

	let payment_hash = match (params.filter, params.preimage) {
		(Some(filter), None) => {
			if let Ok(h) = ark::lightning::PaymentHash::from_str(&filter) {
				h
			} else if let Ok(i) = Bolt11Invoice::from_str(&filter) {
				i.into()
			} else {
				return Err(anyhow::anyhow!("filter is not valid payment hash nor invoice").into());
			}
		},
		(None, Some(p)) => {
			ark::lightning::PaymentHash::from_str(&p)
				.context("Invalid preimage")?
		},
		(None, None) => return Err(anyhow::anyhow!("need to provide a filter").into()),
		(Some(_), Some(_)) => return Err(anyhow::anyhow!("cannot provide both filter and preimage").into()),
	};

	if let Some(status) = wallet_lock.lightning_receive_status(payment_hash)
		.context("Failed to get lightning receive status")? {

		Ok(axum::Json(bark_json::web::LightningStatusResponse {
			payment_hash: status.payment_hash,
			payment_preimage: status.payment_preimage,
			invoice: status.invoice,
			preimage_revealed_at: status.preimage_revealed_at.map(|t| {
				chrono::DateTime::from_timestamp_secs(t as i64)
					.expect("timestamp is valid")
			}),
		}))
	} else {
		return Err(anyhow::anyhow!("No invoice found").into());
	}
}

#[utoipa::path(
	get,
	path = "/receive/invoices",
	responses(
		(status = 200, description = "Returns all lightning invoices", body = Vec<bark_json::cli::LightningReceiveInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "lightning"
)]
#[debug_handler]
pub async fn lightning_invoices(
	State(state): State<BarkWebState>,
) -> HandlerResult<Json<Vec<bark_json::cli::LightningReceiveInfo>>> {
	let wallet_lock = state.wallet.read().await;

	let mut receives = wallet_lock.pending_lightning_receives()
		.context("Failed to get lightning receives")?;
	// receives are ordered from newest to oldest, so we reverse them so last terminal item is newest
	receives.reverse();

	let receives = receives.into_iter()
		.map(bark_json::cli::LightningReceiveInfo::from).collect::<Vec<_>>();

	Ok(axum::Json(receives))
}

#[utoipa::path(
	post,
	path = "/pay",
	request_body = bark_json::web::LightningPayRequest,
	responses(
		(status = 200, description = "Returns payment result", body = bark_json::web::LightningPayResponse),
		(status = 400, description = "Bad request - invalid destination or amount"),
		(status = 500, description = "Internal server error")
	),
	tag = "lightning"
)]
#[debug_handler]
pub async fn lightning_pay(
	State(state): State<BarkWebState>,
	Json(params): Json<bark_json::web::LightningPayRequest>,
) -> HandlerResult<Json<bark_json::web::LightningPayResponse>> {
	let mut wallet_lock = state.wallet.write().await;

	let amount = params.amount_sat.map(|a| Amount::from_sat(a));
	let no_sync = true;

	let preimage = if let Ok(invoice) = Bolt11Invoice::from_str(&params.destination) {
		pay_invoice(invoice, amount, params.comment, no_sync, &mut *wallet_lock).await?
	} else if let Ok(offer) = Offer::from_str(&params.destination) {
		pay_offer(offer, amount, params.comment, no_sync, &mut *wallet_lock).await?
	} else if let Ok(lnaddr) = LightningAddress::from_str(&params.destination) {
		pay_lnaddr(lnaddr, amount, params.comment, no_sync, &mut *wallet_lock).await?
	} else {
		return Err(anyhow::anyhow!("argument is not a valid bolt11 invoice, bolt12 offer or lightning address").into());
	};

	Ok(axum::Json(bark_json::web::LightningPayResponse {
		message: "Payment sent successfully".to_string(),
		preimage: Some(preimage),
	}))
}
