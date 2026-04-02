use std::str::FromStr;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use anyhow::Context;
use bitcoin::Amount;
use utoipa::OpenApi;

use crate::ServerState;
use crate::error::{self, HandlerResult, ContextExt};

#[derive(OpenApi)]
#[openapi(
	paths(
		onchain_fee_rates,
		board_fee,
		send_onchain_fee,
		offboard_all_fee,
		lightning_send_fee,
		lightning_receive_fee,
	),
	components(schemas(
		bark_json::web::FeeEstimateQuery,
		bark_json::web::SendOnchainFeeEstimateQuery,
		bark_json::web::OffboardAllFeeEstimateQuery,
		bark_json::web::FeeEstimateResponse,
		bark_json::web::OnchainFeeRatesResponse,
	)),
	tags((name = "fees", description = "Estimate fees for wallet operations before executing them."))
)]
pub struct FeesApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/onchain", get(onchain_fee_rates))
		.route("/board", get(board_fee))
		.route("/send-onchain", get(send_onchain_fee))
		.route("/offboard-all", get(offboard_all_fee))
		.route("/lightning/pay", get(lightning_send_fee))
		.route("/lightning/receive", get(lightning_receive_fee))
}

#[utoipa::path(
	get,
	path = "/onchain",
	summary = "Get on-chain fee rates",
	responses(
		(status = 200, description = "Returns current mempool fee rates", body = bark_json::web::OnchainFeeRatesResponse),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the current mempool fee rates from the chain source at three \
		confirmation targets: fast (~1 block), regular (~3 blocks), and slow (~6 blocks). \
		Rates are in sat/vB, rounded up.",
	tag = "fees"
)]
#[debug_handler]
pub async fn onchain_fee_rates(
	State(state): State<ServerState>,
) -> HandlerResult<Json<bark_json::web::OnchainFeeRatesResponse>> {
	let wallet = state.require_wallet()?;

	let rates = wallet.chain.fee_rates().await;

	Ok(axum::Json(bark_json::web::OnchainFeeRatesResponse {
		fast_sat_per_vb: rates.fast.to_sat_per_vb_ceil(),
		regular_sat_per_vb: rates.regular.to_sat_per_vb_ceil(),
		slow_sat_per_vb: rates.slow.to_sat_per_vb_ceil(),
	}))
}

#[utoipa::path(
	get,
	path = "/board",
	summary = "Estimate board fee",
	params(
		("amount_sat" = u64, Query, description = "The amount in satoshis to board"),
	),
	responses(
		(status = 200, description = "Returns the fee estimate", body = bark_json::web::FeeEstimateResponse),
		(status = 400, description = "Invalid amount", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Estimates the Ark protocol fee for boarding the specified amount of on-chain \
		bitcoin. The net amount is what the user receives as a VTXO. Does not include the \
		on-chain transaction fee for the board anchor transaction.",
	tag = "fees"
)]
#[debug_handler]
pub async fn board_fee(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::FeeEstimateQuery>,
) -> HandlerResult<Json<bark_json::web::FeeEstimateResponse>> {
	let wallet = state.require_wallet()?;

	let amount = Amount::from_sat(query.amount_sat);
	let estimate = wallet.estimate_board_offchain_fee(amount).await
		.context("Failed to estimate board fee")?;

	Ok(axum::Json(estimate.into()))
}

#[utoipa::path(
	get,
	path = "/send-onchain",
	summary = "Estimate send-onchain fee",
	params(
		("amount_sat" = u64, Query, description = "The amount in satoshis to send on-chain"),
		("address" = String, Query, description = "The destination Bitcoin address"),
	),
	responses(
		(status = 200, description = "Returns the fee estimate", body = bark_json::web::FeeEstimateResponse),
		(status = 400, description = "Invalid amount or address", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Estimates the total fee for sending bitcoin from the Ark wallet to an \
		on-chain address. The fee depends on the destination address type and current fee \
		rates. The gross amount is what the user pays (including VTXOs spent), and the net \
		amount is what the recipient receives on-chain.",
	tag = "fees"
)]
#[debug_handler]
pub async fn send_onchain_fee(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::SendOnchainFeeEstimateQuery>,
) -> HandlerResult<Json<bark_json::web::FeeEstimateResponse>> {
	let wallet = state.require_wallet()?;

	let network = wallet.network().await?;
	let address = bitcoin::Address::from_str(&query.address)
		.badarg("Invalid destination address")?
		.require_network(network)
		.badarg("Address is not valid for configured network")?;

	let amount = Amount::from_sat(query.amount_sat);
	let estimate = wallet.estimate_send_onchain(&address, amount).await
		.context("Failed to estimate send-onchain fee")?;

	Ok(axum::Json(estimate.into()))
}

#[utoipa::path(
	get,
	path = "/offboard-all",
	summary = "Estimate offboard-all fee",
	params(
		("address" = String, Query, description = "The destination Bitcoin address"),
	),
	responses(
		(status = 200, description = "Returns the fee estimate", body = bark_json::web::FeeEstimateResponse),
		(status = 400, description = "Invalid address", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Estimates the fee for offboarding the entire Ark balance to the given \
		on-chain address. The gross amount is the total spendable balance, and the net \
		amount is what the user receives on-chain after fees. The fee depends on the \
		destination address type, current fee rates, and VTXO expiry.",
	tag = "fees"
)]
#[debug_handler]
pub async fn offboard_all_fee(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::OffboardAllFeeEstimateQuery>,
) -> HandlerResult<Json<bark_json::web::FeeEstimateResponse>> {
	let wallet = state.require_wallet()?;

	let network = wallet.network().await?;
	let address = bitcoin::Address::from_str(&query.address)
		.badarg("Invalid destination address")?
		.require_network(network)
		.badarg("Address is not valid for configured network")?;

	let estimate = wallet.estimate_offboard_all(&address).await
		.context("Failed to estimate offboard-all fee")?;

	Ok(axum::Json(estimate.into()))
}

#[utoipa::path(
	get,
	path = "/lightning/pay",
	summary = "Estimate Lightning send fee",
	params(
		("amount_sat" = u64, Query, description = "The amount in satoshis to send over Lightning"),
	),
	responses(
		(status = 200, description = "Returns the fee estimate", body = bark_json::web::FeeEstimateResponse),
		(status = 400, description = "Invalid amount", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Estimates the fee for sending the specified amount over Lightning. The net \
		amount is what the recipient receives. The fee depends on the VTXOs selected and \
		their expiry. If the wallet has insufficient funds, returns a worst-case fee \
		estimate assuming the user acquires enough funds to cover the payment.",
	tag = "fees"
)]
#[debug_handler]
pub async fn lightning_send_fee(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::FeeEstimateQuery>,
) -> HandlerResult<Json<bark_json::web::FeeEstimateResponse>> {
	let wallet = state.require_wallet()?;

	let amount = Amount::from_sat(query.amount_sat);
	let estimate = wallet.estimate_lightning_send_fee(amount).await
		.context("Failed to estimate lightning send fee")?;

	Ok(axum::Json(estimate.into()))
}

#[utoipa::path(
	get,
	path = "/lightning/receive",
	summary = "Estimate Lightning receive fee",
	params(
		("amount_sat" = u64, Query, description = "The amount in satoshis to receive over Lightning"),
	),
	responses(
		(status = 200, description = "Returns the fee estimate", body = bark_json::web::FeeEstimateResponse),
		(status = 400, description = "Invalid amount", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Estimates the fee for receiving the specified amount over Lightning. The \
		gross amount is the Lightning payment amount, and the net amount is what the user \
		receives as a VTXO after the Ark server deducts its fee.",
	tag = "fees"
)]
#[debug_handler]
pub async fn lightning_receive_fee(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::FeeEstimateQuery>,
) -> HandlerResult<Json<bark_json::web::FeeEstimateResponse>> {
	let wallet = state.require_wallet()?;

	let amount = Amount::from_sat(query.amount_sat);
	let estimate = wallet.estimate_lightning_receive_fee(amount).await
		.context("Failed to estimate lightning receive fee")?;

	Ok(axum::Json(estimate.into()))
}
