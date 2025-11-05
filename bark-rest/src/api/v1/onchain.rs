use std::str::FromStr;

use anyhow::Context;
use axum::extract::State;
use axum::routing::{get, post, put};
use axum::{debug_handler, Json, Router};
use bark_json::hal::GetInfo;
use bitcoin::Amount;
use tracing::info;
use utoipa::OpenApi;

use crate::{error::HandlerResult, RestServer};

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/balance", get(onchain_balance))
		.route("/addresses/next", put(onchain_address))
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
		bark_json::cli::TransactionInfo,
		bark_json::cli::InputInfo,
		bark_json::cli::InputScriptInfo,
		bark_json::cli::OutputInfo,
		bark_json::cli::OutputScriptInfo,
	)),
	tags((name = "onchain", description = "Onchain wallet endpoints"))
)]
pub struct OnchainApiDoc;

#[utoipa::path(
	get,
	path = "/balance",
	responses(
		(status = 200, description = "Returns the onchain balance", body = bark_json::cli::onchain::OnchainBalance),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_balance(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::cli::onchain::OnchainBalance>> {
	let onchain_lock = state.onchain.read().await;

	let balance = onchain_lock.balance();
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
	put,
	path = "/addresses/next",
	responses(
		(status = 200, description = "Returns the onchain address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_address(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::cli::onchain::Address>> {
	let mut onchain_lock = state.onchain.write().await;

	let address = onchain_lock.address()
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
		(status = 400, description = "Bad request - invalid destination or amount"),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_send(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::OnchainSendRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let mut onchain_lock = state.onchain.write().await;

	let net = state.wallet.properties()?.network;
	let addr = bitcoin::Address::from_str	(&params.destination)
		.context("Invalid destination address")?
		.require_network(net)
		.context("Address is not valid for configured network")?;

	let fee_rate = state.wallet.chain.fee_rates().await.regular;
	let amount = Amount::from_sat(params.amount_sat);
	let txid = onchain_lock.send(&state.wallet.chain, addr, amount, fee_rate).await
		.context("Failed to send onchain payment")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	post,
	path = "/send-many",
	request_body = bark_json::web::OnchainSendManyRequest,
	responses(
		(status = 200, description = "Returns the send result", body = bark_json::cli::onchain::Send),
		(status = 400, description = "Bad request - invalid destinations"),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_send_many(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::OnchainSendManyRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let mut onchain_lock = state.onchain.write().await;

	let net = state.wallet.properties()?.network;
	let outputs = params.destinations
		.iter()
		.map(|dest| -> anyhow::Result<(bitcoin::Address, Amount)> {
			let mut parts = dest.splitn(2, ':');
			let addr = {
				let s = parts.next()
					.context("invalid destination format, expected address:amount")?;
				bitcoin::Address::from_str(s)?.require_network(net)
					.context("invalid address")?
			};
			let amount = {
				let s = parts.next()
					.context("invalid destination format, expected address:amount")?;
				Amount::from_str(s)
					.context("invalid amount")?
			};
			Ok((addr, amount))
		})
		.collect::<Result<Vec<_>, _>>()
		.context("Failed to parse destinations")?;

	info!("Attempting to send the following:");
	for (address, amount) in &outputs {
		info!("{} to {}", amount, address);
	}

	let fee_rate = state.wallet.chain.fee_rates().await.regular;
	let txid = onchain_lock.send_many(&state.wallet.chain, outputs, fee_rate).await
		.context("Failed to send many onchain payments")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	post,
	path = "/drain",
	request_body = bark_json::web::OnchainDrainRequest,
	responses(
		(status = 200, description = "Returns the drain result", body = bark_json::cli::onchain::Send),
		(status = 400, description = "Bad request - invalid destination"),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_drain(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::OnchainDrainRequest>,
) -> HandlerResult<Json<bark_json::cli::onchain::Send>> {
	let mut onchain_lock = state.onchain.write().await;

	let net = state.wallet.properties()?.network;
	let addr = bitcoin::Address::from_str(&params.destination)
		.context("Invalid destination address")?
		.require_network(net)
		.context("Address is not valid for configured network")?;

	let fee_rate = state.wallet.chain.fee_rates().await.regular;
	let txid = onchain_lock.drain(&state.wallet.chain, addr, fee_rate).await
		.context("Failed to drain onchain wallet")?;

	Ok(axum::Json(bark_json::cli::onchain::Send { txid }))
}

#[utoipa::path(
	get,
	path = "/utxos",
	responses(
		(status = 200, description = "Returns the onchain UTXOs", body = Vec<bark_json::primitives::UtxoInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_utxos(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::primitives::UtxoInfo>>> {
	let onchain_lock = state.onchain.read().await;

	let utxos = onchain_lock.utxos()
		.into_iter()
		.map(bark_json::primitives::UtxoInfo::from)
		.collect::<Vec<_>>();

	Ok(axum::Json(utxos))
}

#[utoipa::path(
	get,
	path = "/transactions",
	responses(
		(status = 200, description = "Returns the onchain transactions", body = Vec<bark_json::cli::TransactionInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_transactions(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::cli::TransactionInfo>>> {
	let onchain_lock = state.onchain.read().await;

	let network = state.wallet.properties()?.network;

	let mut transactions = onchain_lock.list_transactions();
	// transactions are ordered from newest to oldest, so we reverse them so last terminal item is newest
	transactions.reverse();

	let transactions = transactions.into_iter()
		.map(|tx| bark_json::cli::TransactionInfo::from(tx.get_info(network)))
		.collect::<Vec<_>>();

	Ok(axum::Json(transactions))
}

#[utoipa::path(
	put,
	path = "/sync",
	responses(
		(status = 200, description = "Synced onchain wallet"),
		(status = 500, description = "Internal server error")
	),
	tag = "onchain"
)]
#[debug_handler]
pub async fn onchain_sync(
	State(state): State<RestServer>,
) -> HandlerResult<()> {
	let mut onchain_lock = state.onchain.write().await;

	onchain_lock.sync(&state.wallet.chain).await?;

	Ok(())
}
