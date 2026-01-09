use std::str::FromStr;

use anyhow::Context;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use tracing::info;
use utoipa::OpenApi;

use bark::onchain::ChainSync;

use crate::ServerState;
use crate::error::{self, HandlerResult, ContextExt};

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/balance", get(onchain_balance))
		.route("/addresses/next", post(onchain_address))
		.route("/send", post(onchain_send))
		.route("/send-many", post(onchain_send_many))
		.route("/drain", post(onchain_drain))
		.route("/utxos", get(onchain_utxos))
		.route("/transactions", get(onchain_transactions))
		.route("/sync", post(onchain_sync))
}

#[derive(OpenApi)]
#[openapi(
	paths(
		onchain_balance,
		onchain_address,
		onchain_send,
		onchain_send_many,
		onchain_drain,
		onchain_utxos,
		onchain_transactions,
		onchain_sync,
	),
	components(schemas(
		bark_json::cli::onchain::OnchainBalance,
		bark_json::cli::onchain::Address,
		bark_json::cli::onchain::Send,
		bark_json::web::OnchainSendRequest,
		bark_json::web::OnchainSendManyRequest,
		bark_json::web::OnchainDrainRequest,
		bark_json::primitives::UtxoInfo,
		bark_json::primitives::TransactionInfo,
	)),
	tags((name = "onchain", description = "Onchain wallet endpoints"))
)]
pub struct OnchainApiDoc;

#[utoipa::path(
	get,
	path = "/balance",
	responses(
		(status = 200, description = "Returns the onchain balance", body = bark_json::cli::onchain::OnchainBalance),
	),
	description = "Returns the current onchain wallet balance",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_balance(
	State(state): State<ServerState>,
) -> HandlerResult<Json<bark_json::cli::onchain::OnchainBalance>> {
	let onchain = state.require_onchain()?;

	let balance = onchain.read().await.balance();
	let onchain_balance = bark_json::cli::onchain::OnchainBalance {
		total: balance.total(),
		trusted_spendable: balance.trusted_spendable(),
		immature: balance.immature,
		trusted_pending: balance.trusted_pending,
		untrusted_pending: balance.untrusted_pending,
		confirmed: balance.confirmed,
	};

	Ok(axum::Json(onchain_balance))
}

#[utoipa::path(
	post,
	path = "/addresses/next",
	responses(
		(status = 200, description = "Returns the onchain address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Generates a new onchain address and stores its index in the onchain wallet database",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_address(
	State(state): State<ServerState>,
) -> HandlerResult<Json<bark_json::cli::onchain::Address>> {
	let onchain = state.require_onchain()?;

	let address = onchain.write().await.address().await
		.context("Wallet failed to generate address")?;

	Ok(axum::Json(bark_json::cli::onchain::Address {
		address: address.into_unchecked()
	}))
}

#[utoipa::path(
	post,
	path = "/send",
	request_body = bark_json::web::OnchainSendRequest,
	responses(
		(status = 200, description = "Returns the send result", body = bark_json::cli::onchain::Send),
		(status = 400, description = "The provided destination address is invalid", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Sends a payment to the given onchain address",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_send(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::OnchainSendRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let wallet = state.require_wallet()?;
	let onchain = state.require_onchain()?;

	let net = wallet.network().await?;
	let addr = bitcoin::Address::from_str	(&body.destination)
		.badarg("Invalid destination address")?
		.require_network(net)
		.badarg("Address is not valid for configured network")?;

	let fee_rate = wallet.chain.fee_rates().await.regular;
	let amount = Amount::from_sat(body.amount_sat);
	let txid = onchain.write().await.send(&wallet.chain, addr, amount, fee_rate).await
		.context("Failed to send onchain payment")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	post,
	path = "/send-many",
	request_body = bark_json::web::OnchainSendManyRequest,
	responses(
		(status = 200, description = "Returns the send result", body = bark_json::cli::onchain::Send),
		(status = 400, description = "One of the provided destinations is invalid", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Sends multiple payments to provided onchain addresses",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_send_many(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::OnchainSendManyRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let onchain = state.require_onchain()?;
	let wallet = state.require_wallet()?;

	let net = wallet.network().await?;
	let outputs = body.destinations
		.iter()
		.map(|dest| {
			let mut parts = dest.splitn(2, ':');
			let addr = {
				let s = parts.next()
					.badarg("invalid destination format, expected address:amount")?;
				bitcoin::Address::from_str(s)
					.badarg("invalid address")?
					.require_network(net)
					.badarg("address is not valid for configured network")?
			};
			let amount = {
				let s = parts.next()
					.badarg("invalid destination format, expected address:amount")?;
				Amount::from_str(s)
					.badarg("invalid amount")?
			};
			Ok((addr, amount))
		})
		.collect::<Result<Vec<_>, error::ErrorResponse>>()?;

	info!("Attempting to send the following:");
	for (address, amount) in &outputs {
		info!("{} to {}", amount, address);
	}

	let fee_rate = wallet.chain.fee_rates().await.regular;
	let txid = onchain.write().await.send_many(&wallet.chain, &outputs, fee_rate).await
		.context("Failed to send many onchain payments")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	post,
	path = "/drain",
	request_body = bark_json::web::OnchainDrainRequest,
	responses(
		(status = 200, description = "Returns the drain result", body = bark_json::cli::onchain::Send),
		(status = 400, description = "The provided destination address is invalid", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Sends all onchain wallet funds to the given address",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_drain(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::OnchainDrainRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let onchain = state.require_onchain()?;
	let wallet = state.require_wallet()?;

	let net = wallet.network().await?;
	let addr = bitcoin::Address::from_str(&body.destination)
		.badarg("Invalid destination address")?
		.require_network(net)
		.badarg("Address is not valid for configured network")?;

	let fee_rate = wallet.chain.fee_rates().await.regular;
	let txid = onchain.write().await.drain(&wallet.chain, addr, fee_rate).await
		.context("Failed to drain onchain wallet")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	get,
	path = "/utxos",
	responses(
		(status = 200, description = "Returns the onchain UTXOs", body = Vec<bark_json::primitives::UtxoInfo>),
	),
	description = "Returns all the onchain wallet UTXOs",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_utxos(
	State(state): State<ServerState>,
) -> HandlerResult<Json<Vec<bark_json::primitives::UtxoInfo>>> {
	let onchain = state.require_onchain()?;

	let utxos = onchain.read().await.utxos()
		.into_iter()
		.map(bark_json::primitives::UtxoInfo::from)
		.collect::<Vec<_>>();

	Ok(axum::Json(utxos))
}

#[utoipa::path(
	get,
	path = "/transactions",
	responses(
		(status = 200, description = "Returns the onchain transactions", body = Vec<bark_json::primitives::TransactionInfo>),
	),
	description = "Returns all the onchain wallet transactions",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_transactions(
	State(state): State<ServerState>,
) -> HandlerResult<Json<Vec<bark_json::primitives::TransactionInfo>>> {
	let onchain = state.require_onchain()?;

	let mut transactions = onchain.read().await.list_transactions();
	// transactions are ordered from newest to oldest, so we reverse them so last terminal item is newest
	transactions.reverse();

	let transactions = transactions.into_iter()
		.map(|tx| bark_json::primitives::TransactionInfo::from(tx))
		.collect::<Vec<_>>();

	Ok(axum::Json(transactions))
}

#[utoipa::path(
	post,
	path = "/sync",
	responses(
		(status = 200, description = "Synced onchain wallet"),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Syncs the onchain wallet",
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_sync(
	State(state): State<ServerState>,
) -> HandlerResult<()> {
	let onchain = state.require_onchain()?;
	let wallet = state.require_wallet()?;

	onchain.write().await.sync(&wallet.chain).await?;
	Ok(())
}
