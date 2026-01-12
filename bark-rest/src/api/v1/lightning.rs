use std::str::FromStr;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use anyhow::Context;
use utoipa::OpenApi;

use ark::lightning::Offer;
use bark::lightning_invoice::Bolt11Invoice;
use bark::lnurllib::lightning_address::LightningAddress;

use crate::error::{self, badarg, not_found, ContextExt, HandlerResult};
use crate::ServerState;

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

pub fn router() -> Router<ServerState> {
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
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Generates a new lightning invoice with the given amount",
	tag = "lightning"
)]
#[debug_handler]
pub async fn generate_invoice(
	State(state): State<ServerState>,
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
		(status = 400, description = "Bad request", body = error::BadRequestError),
		(status = 404, description = "Not found", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the status of a lightning receive for the provided filter",
	tag = "lightning"
)]
#[debug_handler]
pub async fn get_receive_status(
	State(state): State<ServerState>,
	Path(identifier): Path<String>,
) -> HandlerResult<Json<bark_json::cli::LightningReceiveInfo>> {
	let payment_hash = if let Ok(h) = ark::lightning::PaymentHash::from_str(&identifier) {
		h
	} else if let Ok(i) = Bolt11Invoice::from_str(&identifier) {
		i.into()
	} else if let Ok(p) = ark::lightning::Preimage::from_str(&identifier) {
		p.into()
	} else {
		badarg!("identifier is not a valid payment hash, invoice or preimage");
	};

	if let Some(status) = state.wallet.lightning_receive_status(payment_hash).await
		.context("Failed to get lightning receive status")?
	{
		Ok(axum::Json(status.into()))
	} else {
		not_found!([payment_hash], "No invoice found");
	}
}

#[utoipa::path(
	get,
	path = "/receives",
	responses(
		(status = 200, description = "Returns all receive statuses", body = Vec<bark_json::cli::LightningReceiveInfo>),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns all the current pending receive statuses",
	tag = "lightning"
)]
#[debug_handler]
pub async fn list_receive_statuses(
	State(state): State<ServerState>,
) -> HandlerResult<Json<Vec<bark_json::cli::LightningReceiveInfo>>> {
	let mut receives = state.wallet.pending_lightning_receives().await
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
		(status = 200, description = "Returns success message, optionally with \
			preimage if payment was immediately settled", body = bark_json::web::LightningPayResponse),
		(status = 400, description = "The provided destination is not a valid \
			bolt11 invoice, bolt12 offer or lightning address", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Sends a payment to the given lightning destination",
	tag = "lightning"
)]
#[debug_handler]
pub async fn pay(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::LightningPayRequest>,
) -> HandlerResult<Json<bark_json::web::LightningPayResponse>> {
	let amount = body.amount_sat.map(|a| Amount::from_sat(a));

	if let Ok(invoice) = Bolt11Invoice::from_str(&body.destination) {
		if body.comment.is_some() {
			badarg!("comment is not supported for BOLT-11 invoices");
		}
		state.wallet.pay_lightning_invoice(invoice, amount).await?
	} else if let Ok(offer) = Offer::from_str(&body.destination) {
		if body.comment.is_some() {
			badarg!("comment is not supported for BOLT-12 offers");
		}
		state.wallet.pay_lightning_offer(offer, amount).await?
	} else if let Ok(lnaddr) = LightningAddress::from_str(&body.destination) {
		let amount = amount.badarg("amount is required for Lightning addresses")?;
		state.wallet.pay_lightning_address(&lnaddr, amount, body.comment).await?
	} else {
		badarg!("argument is not a valid BOLT-11 invoice, BOLT-12 offer or Lightning address");
	};

	Ok(axum::Json(bark_json::web::LightningPayResponse {
		message: "Payment initiated successfully".to_string(),
	}))
}
