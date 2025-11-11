use std::str::FromStr;

use anyhow::Context;
use axum::extract::{Query, State};
use axum::routing::{get, post, put};
use axum::{Json, Router, debug_handler};

use bitcoin::Amount;
use tracing::info;
use utoipa::OpenApi;

use ark::lightning::{Bolt11Invoice, Offer};
use bark::lightning_utils::{pay_invoice, pay_lnaddr, pay_offer};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::vtxo::selection::VtxoFilter;

use crate::RestServer;
use crate::error::HandlerResult;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/connected", get(connected))
		.route("/ark-info", get(ark_info))
		.route("/addresses/next", put(address))
		.route("/addresses/peak", get(peak_address))
		.route("/balance", get(balance))
		.route("/vtxos", get(vtxos))
		.route("/movements", get(movements))
		.route("/send", post(send))
		.route("/refresh/vtxos", post(refresh_vtxos))
		.route("/refresh/all", post(refresh_all))
		.route("/refresh/counterparty", post(refresh_counterparty))
		.route("/offboard/vtxos", post(offboard_vtxos))
		.route("/offboard/all", post(offboard_all))
		.route("/send-onchain", post(send_onchain))
		.route("/rounds", get(pending_rounds))
		.route("/sync", post(sync))
}

#[derive(OpenApi)]
#[openapi(
	paths(
		connected,
		ark_info,
		address,
		peak_address,
		balance,
		vtxos,
		movements,
		send,
		refresh_vtxos,
		refresh_all,
		refresh_counterparty,
		offboard_vtxos,
		offboard_all,
		send_onchain,
		pending_rounds,
		sync,
	),
	components(schemas(
		bark_json::web::ConnectedResponse,
		bark_json::cli::ArkInfo,
		bark_json::web::ArkAddressResponse,
		bark_json::web::PeakAddressRequest,
		bark_json::web::VtxosQuery,
		bark_json::cli::Balance,
		bark_json::primitives::WalletVtxoInfo,
		bark_json::cli::Movement,
		bark_json::web::SendRequest,
		bark_json::web::SendResponse,
		bark_json::web::RefreshRequest,
		bark_json::web::OffboardVtxosRequest,
		bark_json::web::OffboardAllRequest,
		bark_json::web::PendingRoundInfo,
		bark_json::cli::RoundStatus,
	)),
	tags(
		(name = "wallet", description = "Wallet-related endpoints"),
	)
)]
pub struct WalletApiDoc;

#[utoipa::path(
	get,
	path = "/connected",
	responses(
		(status = 200, description = "Returns whether the wallet is connected to an Ark server", body = bark_json::web::ConnectedResponse),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn connected(State(state): State<RestServer>) -> HandlerResult<Json<bark_json::web::ConnectedResponse>> {
	Ok(axum::Json(bark_json::web::ConnectedResponse {
		connected: state.wallet.check_connection().await.is_ok(),
	}))
}

#[utoipa::path(
	get,
	path = "/ark-info",
	responses(
		(status = 200, description = "Returns the Ark info", body = bark_json::cli::ArkInfo),
		(status = 404, description = "No ark info found"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn ark_info(State(state): State<RestServer>) -> HandlerResult<Json<bark_json::cli::ArkInfo>> {
	let ark_info = state.wallet.ark_info()
		.ok_or_else(|| anyhow::anyhow!("No ark info found"))?;

	Ok(axum::Json(ark_info.into()))
}

#[utoipa::path(
	put,
	path = "/addresses/next",
	responses(
		(status = 200, description = "Returns the Ark address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn address(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::ArkAddressResponse>> {
	let ark_address = state.wallet.new_address()
		.context("Failed to generate new address")?;

	Ok(axum::Json(bark_json::web::ArkAddressResponse {
		address: ark_address.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/addresses/peak",
	params(
		("index" = u32, Query, description = "Index for the address.")
	),
	responses(
		(status = 200, description = "Returns the Ark address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn peak_address(
	State(state): State<RestServer>,
	Query(params): Query<bark_json::web::PeakAddressRequest>,
) -> HandlerResult<Json<bark_json::web::ArkAddressResponse>> {
	let ark_address = state.wallet.peak_address(params.index)
		.with_context(|| format!("Failed to get address at index {}", params.index))?;

	Ok(axum::Json(bark_json::web::ArkAddressResponse {
		address: ark_address.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/balance",
	responses(
		(status = 200, description = "Returns the wallet balance", body = bark_json::cli::Balance),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn balance(State(state): State<RestServer>) -> HandlerResult<Json<bark_json::cli::Balance>> {
	let balance = state.wallet.balance()
		.context("Failed to get wallet balance")?;

	Ok(axum::Json(balance.into()))
}

#[utoipa::path(
	get,
	path = "/vtxos",
	params(
		("all" = Option<bool>, Query, description = "Return all VTXOs regardless of their state. If not provided, returns only non-spent VTXOs.")
	),
	responses(
		(status = 200, description = "Returns the wallet VTXOs", body = Vec<bark_json::primitives::WalletVtxoInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn vtxos(
	State(state): State<RestServer>,
	Query(params): Query<bark_json::web::VtxosQuery>,
) -> HandlerResult<Json<Vec<bark_json::primitives::WalletVtxoInfo>>> {
	let wallet_vtxos = if params.all.unwrap_or(false) {
		state.wallet.all_vtxos().context("Failed to get all VTXOs")?
	} else {
		state.wallet.vtxos().context("Failed to get VTXOs")?
	};

	let vtxo_infos = wallet_vtxos
		.iter()
		.map(|vtxo| bark_json::primitives::WalletVtxoInfo {
			vtxo: vtxo.vtxo.clone().into(),
			state: vtxo.state.kind().as_str().to_string(),
		})
		.collect::<Vec<_>>();

	Ok(axum::Json(vtxo_infos))
}

#[utoipa::path(
	get,
	path = "/movements",
	responses(
		(status = 200, description = "Returns the wallet movements", body = Vec<bark_json::cli::Movement>),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn movements(State(state): State<RestServer>) -> HandlerResult<Json<Vec<bark_json::cli::Movement>>> {
	let movements = state.wallet.movements().context("Failed to get movements")?;

	let json_movements = movements
		.into_iter()
		.map(bark_json::cli::Movement::from)
		.collect::<Vec<_>>();

	Ok(axum::Json(json_movements))
}

#[utoipa::path(
	get,
	path = "/rounds",
	responses(
		(status = 200, description = "Returns the wallet pending rounds", body = Vec<bark_json::web::PendingRoundInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn pending_rounds(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::web::PendingRoundInfo>>> {
	let rounds = state.wallet
		.pending_round_states()
		.context("Failed to get pending rounds")?;

	let infos = rounds
		.into_iter()
		.map(bark_json::web::PendingRoundInfo::from)
		.collect();

	Ok(axum::Json(infos))
}

#[utoipa::path(
	post,
	path = "/send",
	request_body = bark_json::web::SendRequest,
	responses(
		(status = 200, description = "Payment sent successfully", body = bark_json::web::SendResponse),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn send(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::SendRequest>,
) -> HandlerResult<Json<bark_json::web::SendResponse>> {
	let amount = params.amount_sat.map(|a| Amount::from_sat(a));
	let no_sync = true;

	if let Ok(addr) = ark::Address::from_str(&params.destination) {
		let amount = amount.context("amount missing")?;

		info!("Sending arkoor payment of {} to address {}", amount, addr);
		state.wallet.send_arkoor_payment(&addr, amount).await?;
	} else if let Ok(inv) = Bolt11Invoice::from_str(&params.destination) {
		pay_invoice(inv, amount, params.comment, no_sync, &state.wallet).await?;
	} else if let Ok(offer) = Offer::from_str(&params.destination) {
		pay_offer(offer, amount, params.comment, no_sync, &state.wallet).await?;
	} else if let Ok(addr) = LightningAddress::from_str(&params.destination) {
		pay_lnaddr(addr, amount, params.comment, no_sync, &state.wallet).await?;
	} else if let Ok(addr) = bitcoin::Address::from_str(&params.destination) {
		let checked_addr = addr
			.require_network(state.wallet.properties()?.network)
			.context("bitcoin address is not valid for configured network")?;
		let amount = amount.context("amount missing")?;

		state.wallet
			.send_round_onchain_payment(checked_addr, amount)
			.await?;
	} else {
		return Err(anyhow::anyhow!(
			"Argument is not a valid destination. Supported are: \
			VTXO pubkeys, bolt11 invoices, bolt12 offers and lightning addresses",
		)
		.into());
	}

	Ok(axum::Json(bark_json::web::SendResponse {
		message: "Payment sent successfully".to_string(),
	}))
}

#[utoipa::path(
	post,
	path = "/refresh/vtxos",
	request_body = bark_json::web::RefreshRequest,
	responses(
		(status = 200, description = "Returns the refresh result", body = bark_json::web::PendingRoundInfo),
		(status = 400, description = "Bad request - exactly one parameter must be provided"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn refresh_vtxos(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::RefreshRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	if params.vtxos.is_empty() {
		return Err(anyhow::anyhow!("No VTXO IDs provided").into());
	}

	// Specific VTXO IDs
	let vtxos = params
		.vtxos
		.iter()
		.map(|s| {
			let id = ark::VtxoId::from_str(s)?;
			Ok(state.wallet.get_vtxo_by_id(id)?)
		})
		.collect::<anyhow::Result<Vec<_>>>()
		.context("Invalid vtxo_id")?;

	let vtxo_ids = vtxos.into_iter().map(|v| v.id()).collect::<Vec<_>>();

	let participation = state.wallet
		.build_refresh_participation(vtxo_ids)
		.context("Failed to build round participation")?;

	match participation {
		Some(participation) => {
			let round = state.wallet.join_next_round(participation)
				.context("Failed to store round participation")?;

			Ok(axum::Json(round.into()))
		}
		None => {
			return Err(anyhow::anyhow!("No VTXOs to refresh").into());
		}
	}
}

#[utoipa::path(
	post,
	path = "/refresh/all",
	request_body = bark_json::web::RefreshRequest,
	responses(
		(status = 200, description = "Returns the refresh result", body = bark_json::web::PendingRoundInfo),
		(status = 400, description = "Bad request - exactly one parameter must be provided"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn refresh_all(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let vtxos = state.wallet
		.spendable_vtxos()
		.context("Failed to get spendable VTXOs")?;

	let participation = state.wallet
		.build_refresh_participation(vtxos)
		.context("Failed to build round participation")?;

	match participation {
		Some(participation) => {
			let round = state.wallet.join_next_round(participation)
				.context("Failed to store round participation")?;

			Ok(axum::Json(round.into()))
		}
		None => {
			return Err(anyhow::anyhow!("No VTXOs to refresh").into());
		}
	}
}

#[utoipa::path(
	post,
	path = "/refresh/counterparty",
	request_body = bark_json::web::RefreshRequest,
	responses(
		(status = 200, description = "Returns the refresh result", body = bark_json::web::PendingRoundInfo),
		(status = 400, description = "Bad request - exactly one parameter must be provided"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn refresh_counterparty(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let filter = VtxoFilter::new(&state.wallet).counterparty();
	let vtxos = state.wallet
		.spendable_vtxos_with(&filter)
		.context("Failed to get VTXOs")?;

	let participation = state.wallet
		.build_refresh_participation(vtxos)
		.context("Failed to build round participation")?;

	match participation {
		Some(participation) => {
			let round = state.wallet.join_next_round(participation)
				.context("Failed to store round participation")?;

			Ok(axum::Json(round.into()))
		}
		None => {
			return Err(anyhow::anyhow!("No VTXOs to refresh").into());
		}
	}
}

#[utoipa::path(
	post,
	path = "/offboard/vtxos",
	request_body = bark_json::web::OffboardVtxosRequest,
	responses(
		(status = 200, description = "Returns the offboard result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn offboard_vtxos(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::OffboardVtxosRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let mut onchain_lock = state.onchain.write().await;

	if params.vtxos.is_empty() {
		return Err(anyhow::anyhow!("No VTXO IDs provided").into());
	}

	let address = if let Some(addr) = params.address {
		let network = state.wallet.properties()?.network;
		bitcoin::Address::from_str(&addr)
			.context("invalid destination address")?
			.require_network(network)
			.context("address is not valid for configured network")?
	} else {
		onchain_lock.address()?
	};

	let vtxo_ids = params
		.vtxos
		.into_iter()
		.map(|s| ark::VtxoId::from_str(&s).context("invalid vtxo_id"))
		.collect::<anyhow::Result<Vec<_>>>()?;

	let participation = state.wallet
		.build_offboard_participation(vtxo_ids, address.script_pubkey())
		.context("Failed to build round participation")?;

	let round = state.wallet.join_next_round(participation)
		.context("Failed to store round participation")?;

	Ok(axum::Json(round.into()))
}

#[utoipa::path(
	post,
	path = "/offboard/all",
	request_body = bark_json::web::OffboardAllRequest,
	responses(
		(status = 200, description = "Returns the offboard result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn offboard_all(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::OffboardAllRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let mut onchain_lock = state.onchain.write().await;

	let address = if let Some(addr) = params.address {
		let network = state.wallet.properties()?.network;
		bitcoin::Address::from_str(&addr)
			.context("invalid destination address")?
			.require_network(network)
			.context("address is not valid for configured network")?
	} else {
		onchain_lock.address()?
	};

	let input_vtxos = state.wallet.spendable_vtxos()?;

	let participation = state.wallet
		.build_offboard_participation(input_vtxos, address.script_pubkey())
		.context("Failed to build round participation")?;

	let round = state.wallet.join_next_round(participation)
		.context("Failed to store round participation")?;

	Ok(axum::Json(round.into()))
}

#[utoipa::path(
	post,
	path = "/send-onchain",
	request_body = bark_json::web::SendOnchainRequest,
	responses(
		(status = 200, description = "Returns the send onchain result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn send_onchain(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::SendOnchainRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let addr = bitcoin::Address::from_str(&params.destination)
		.context("invalid destination address")?
		.require_network(state.wallet.properties()?.network)
		.context("address is not valid for configured network")?;

	let amount = Amount::from_sat(params.amount_sat);

	let participation = state.wallet
		.build_round_onchain_payment_participation(addr, amount)
		.context("Failed to build round participation")?;

	let round = state.wallet.join_next_round(participation)
		.context("Failed to store round participation")?;

	Ok(axum::Json(round.into()))
}

#[utoipa::path(
	post,
	path = "/sync",
	responses(
		(status = 200, description = "Synced wallet"),
		(status = 500, description = "Internal server error")
	),
	tag = "wallet"
)]
#[debug_handler]
pub async fn sync(State(state): State<RestServer>) -> HandlerResult<()> {
	state.wallet.sync().await;

	Ok(())
}
