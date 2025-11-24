use std::str::FromStr;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use anyhow::Context;
use utoipa::OpenApi;

use ark::lightning::Offer;
use bark::lightning::{pay_invoice, pay_lnaddr, pay_offer};
use bark::lightning_invoice::Bolt11Invoice;
use bark::lnurllib::lightning_address::LightningAddress;

use crate::error::HandlerResult;
use crate::RestServer;

#[derive(OpenApi)]
#[openapi(
	paths(
		generate_invoice,
		get_receive_status,
		list_receive_statuses,
		pay,
	),
	components(schemas(
		bark_json::web::LightningInvoiceRequest,
		bark_json::cli::InvoiceInfo,
		bark_json::cli::LightningReceiveInfo,
		bark_json::web::LightningPayRequest,
		bark_json::web::LightningPayResponse,
	)),
	tags((name = "lightning", description = "Lightning-related endpoints"))
)]
pub struct LightningApiDoc;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/receives/invoice", post(generate_invoice))
		.route("/receives/{identifier}", get(get_receive_status))
		.route("/receives", get(list_receive_statuses))
		.route("/pay", post(pay))
}

#[utoipa::path(
	post,
	path = "/receives/invoice",
	request_body = bark_json::web::LightningInvoiceRequest,
	responses(
		(status = 200, description = "Returns the created invoice", body = bark_json::cli::InvoiceInfo),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	description = "Generates a new lightning invoice with the given amount",
	tag = "lightning"
)]
#[debug_handler]
pub async fn generate_invoice(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::LightningInvoiceRequest>,
) -> HandlerResult<Json<bark_json::cli::InvoiceInfo>> {
	let amount = Amount::from_sat(body.amount_sat);
	let invoice = state.wallet.bolt11_invoice(amount).await
		.context("Failed to create invoice")?;

	Ok(axum::Json(bark_json::cli::InvoiceInfo {
		invoice: invoice.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/receives/{identifier}",
	params(
		("identifier" = String, Path, description = "Payment hash, invoice string or preimage to search for"),
	),
	responses(
		(status = 200, description = "Returns the lightning receive status", body = bark_json::cli::LightningReceiveInfo),
		(status = 500, description = "Internal server error")
	),
	description = "Returns the status of a lightning receive for the provided filter",
	tag = "lightning"
)]
#[debug_handler]
pub async fn get_receive_status(
	State(state): State<RestServer>,
	Path(identifier): Path<String>,
) -> HandlerResult<Json<bark_json::cli::LightningReceiveInfo>> {
	let payment_hash = if let Ok(h) = ark::lightning::PaymentHash::from_str(&identifier) {
		h
	} else if let Ok(i) = Bolt11Invoice::from_str(&identifier) {
		i.into()
	} else if let Ok(p) = ark::lightning::Preimage::from_str(&identifier) {
		p.into()
	} else {
		return Err(anyhow::anyhow!("filter is not valid payment hash nor invoice").into());
	};

	if let Some(status) = state.wallet.lightning_receive_status(payment_hash)
		.context("Failed to get lightning receive status")? {

		Ok(axum::Json(status.into()))
	} else {
		return Err(anyhow::anyhow!("No invoice found").into());
	}
}

#[utoipa::path(
	get,
	path = "/receives",
	responses(
		(status = 200, description = "Returns all receive statuses", body = Vec<bark_json::cli::LightningReceiveInfo>),
		(status = 500, description = "Internal server error")
	),
	description = "Returns all the current pending receive statuses",
	tag = "lightning"
)]
#[debug_handler]
pub async fn list_receive_statuses(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::cli::LightningReceiveInfo>>> {
	let mut receives = state.wallet.pending_lightning_receives()
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
	description = "Sends a payment to the given lightning destination",
	tag = "lightning"
)]
#[debug_handler]
pub async fn pay(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::LightningPayRequest>,
) -> HandlerResult<Json<bark_json::web::LightningPayResponse>> {
	let amount = body.amount_sat.map(|a| Amount::from_sat(a));
	let no_sync = true;

	let preimage = if let Ok(invoice) = Bolt11Invoice::from_str(&body.destination) {
		pay_invoice(invoice, amount, body.comment, no_sync, &state.wallet).await?
	} else if let Ok(offer) = Offer::from_str(&body.destination) {
		pay_offer(offer, amount, body.comment, no_sync, &state.wallet).await?
	} else if let Ok(lnaddr) = LightningAddress::from_str(&body.destination) {
		pay_lnaddr(lnaddr, amount, body.comment, no_sync, &state.wallet).await?
	} else {
		return Err(anyhow::anyhow!("argument is not a valid bolt11 invoice, bolt12 offer or lightning address").into());
	};

	Ok(axum::Json(bark_json::web::LightningPayResponse {
		message: "Payment sent successfully".to_string(),
		preimage: Some(preimage),
	}))
}
