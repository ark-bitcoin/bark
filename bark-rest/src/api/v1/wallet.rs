use std::str::FromStr;

use anyhow::Context;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router, debug_handler};

use bitcoin::Amount;
use tracing::info;
use utoipa::OpenApi;

use ark::lightning::{Bolt11Invoice, Offer};
use bark::lnurllib::lightning_address::LightningAddress;
use bark::subsystem::RoundMovement;
use bark::vtxo::VtxoFilter;
use bark_json::web::PendingRoundInfo;

use crate::{RestServer, error};
use crate::error::{ContextExt, HandlerResult, badarg, not_found};

pub fn router() -> Router<RestServer> {
	#[allow(deprecated)]
	Router::new()
		.route("/connected", get(connected))
		.route("/ark-info", get(ark_info))
		.route("/addresses/next", post(address))
		.route("/addresses/index/{index}", get(peak_address))
		.route("/balance", get(balance))
		.route("/vtxos", get(vtxos))
		.route("/movements", get(movements))
		.route("/history", get(history))
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
		history,
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
		error::InternalServerError,
		error::NotFoundError,
		error::BadRequestError,
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
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns whether the wallet is currently connected to the Ark server",
	tag = "wallet"
)]
#[debug_handler]
pub async fn connected(State(state): State<RestServer>) -> HandlerResult<Json<bark_json::web::ConnectedResponse>> {
	Ok(axum::Json(bark_json::web::ConnectedResponse {
		connected: state.wallet.ark_info().await?.is_some(),
	}))
}

#[utoipa::path(
	get,
	path = "/ark-info",
	responses(
		(status = 200, description = "Returns the Ark info", body = bark_json::cli::ArkInfo),
		(status = 404, description = "Wallet not connected to an Ark server", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the current Ark infos",
	tag = "wallet"
)]
#[debug_handler]
pub async fn ark_info(State(state): State<RestServer>) -> HandlerResult<Json<bark_json::cli::ArkInfo>> {
	let ark_info = state.wallet.ark_info().await?;

	match ark_info {
		Some(ark_info) => Ok(axum::Json(ark_info.into())),
		None => not_found!(["ark server"], "Wallet not connected to an Ark server"),
	}
}

#[utoipa::path(
	post,
	path = "/addresses/next",
	responses(
		(status = 200, description = "Returns the Ark address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Generates a new Ark address and stores it in the wallet database",
	tag = "wallet"
)]
#[debug_handler]
pub async fn address(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::ArkAddressResponse>> {
	let ark_address = state.wallet.new_address().await
		.context("Failed to generate new address")?;

	Ok(axum::Json(bark_json::web::ArkAddressResponse {
		address: ark_address.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/addresses/index/{index}",
	params(
		("index" = u32, Path, description = "Index for the address.")
	),
	responses(
		(status = 200, description = "Returns the Ark address", body = bark_json::cli::onchain::Address),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the Ark address at the given index. The address must \
		have been already derived before using the /addresses/next endpoint.",
	tag = "wallet"
)]
#[debug_handler]
pub async fn peak_address(
	State(state): State<RestServer>,
	Path(index): Path<u32>,
) -> HandlerResult<Json<bark_json::web::ArkAddressResponse>> {
	let ark_address = state.wallet.peak_address(index).await
		.with_context(|| format!("Failed to get address at index {}", index))?;

	Ok(axum::Json(bark_json::web::ArkAddressResponse {
		address: ark_address.to_string(),
	}))
}

#[utoipa::path(
	get,
	path = "/balance",
	responses(
		(status = 200, description = "Returns the wallet balance", body = bark_json::cli::Balance),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the current wallet balance",
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
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns all the wallet VTXOs",
	tag = "wallet"
)]
#[debug_handler]
pub async fn vtxos(
	State(state): State<RestServer>,
	Query(query): Query<bark_json::web::VtxosQuery>,
) -> HandlerResult<Json<Vec<bark_json::primitives::WalletVtxoInfo>>> {
	let wallet_vtxos = if query.all.unwrap_or(false) {
		state.wallet.all_vtxos().context("Failed to get all VTXOs")?
	} else {
		state.wallet.vtxos().context("Failed to get VTXOs")?
	};

	let vtxo_infos = wallet_vtxos
		.iter()
		.map(|vtxo| bark_json::primitives::WalletVtxoInfo {
			vtxo: vtxo.vtxo.clone().into(),
			state: vtxo.state.clone().into(),
		})
		.collect::<Vec<_>>();

	Ok(axum::Json(vtxo_infos))
}


#[utoipa::path(
	get,
	path = "/movements",
	responses(
		(status = 200, description = "Returns the wallet movements", body = Vec<bark_json::cli::Movement>),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Deprecated: Use history instead",
	tag = "wallet",
)]
#[debug_handler]
#[deprecated(note = "Use `history` instead")]
pub async fn movements(State(state): State<RestServer>) -> HandlerResult<Json<Vec<bark_json::cli::Movement>>> {
	#[allow(deprecated)]
	let movements = state.wallet.movements().context("Failed to get movements")?;

	let json_movements = movements
		.into_iter()
		.map(|m| bark_json::cli::Movement::try_from(m)
			.context("Failed to convert movement to JSON")
		).collect::<Result<Vec<_>, _>>()?;

	Ok(axum::Json(json_movements))
}

#[utoipa::path(
	get,
	path = "/history",
	responses(
		(status = 200, description = "Returns the wallet history", body = Vec<bark_json::cli::Movement>),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns all the wallet history",
	tag = "wallet"
)]
#[debug_handler]
pub async fn history(State(state): State<RestServer>) -> HandlerResult<Json<Vec<bark_json::cli::Movement>>> {
	let movements = state.wallet.history().context("Failed to get movements")?;

	let json_movements = movements
		.into_iter()
		.map(|m| bark_json::cli::Movement::try_from(m)
			.context("Failed to convert movement to JSON")
		).collect::<Result<Vec<_>, _>>()?;

	Ok(axum::Json(json_movements))
}

#[utoipa::path(
	get,
	path = "/rounds",
	responses(
		(status = 200, description = "Returns the wallet pending rounds", body = Vec<bark_json::web::PendingRoundInfo>),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns all the wallet ongoing round participations",
	tag = "wallet"
)]
#[debug_handler]
pub async fn pending_rounds(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::web::PendingRoundInfo>>> {
	let rounds = state.wallet.pending_round_states()
		.context("Failed to get pending rounds")?;
	let mut infos = Vec::with_capacity(rounds.len());
	for mut round in rounds {
		let sync = round.state.sync(&state.wallet).await;
		infos.push(PendingRoundInfo::new(&round, sync));
	}
	Ok(axum::Json(infos))
}

#[utoipa::path(
	post,
	path = "/send",
	request_body = bark_json::web::SendRequest,
	responses(
		(status = 200, description = "Payment sent successfully", body = bark_json::web::SendResponse),
		(status = 400, description = "The provided destination is not a valid Ark address, \
			bolt11 invoice, bolt12 offer or lightning address", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Sends a payment to the given destination. The destination \
		can be an Ark address, a BOLT11-invoice, LNURL or a lightning address",
	tag = "wallet"
)]
#[debug_handler]
pub async fn send(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::SendRequest>,
) -> HandlerResult<Json<bark_json::web::SendResponse>> {
	let amount = body.amount_sat.map(|a| Amount::from_sat(a));

	if let Ok(addr) = ark::Address::from_str(&body.destination) {
		let amount = amount.context("amount missing")?;

		info!("Sending arkoor payment of {} to address {}", amount, addr);
		state.wallet.send_arkoor_payment(&addr, amount).await?;
	} else if let Ok(inv) = Bolt11Invoice::from_str(&body.destination) {
		if body.comment.is_some() {
			badarg!("comment is not supported for BOLT-11 invoices");
		}
		state.wallet.pay_lightning_invoice(inv, amount).await?;
	} else if let Ok(offer) = Offer::from_str(&body.destination) {
		if body.comment.is_some() {
			badarg!("comment is not supported for BOLT-12 offers");
		}
		state.wallet.pay_lightning_offer(offer, amount).await?;
	} else if let Ok(addr) = LightningAddress::from_str(&body.destination) {
		let amount = amount.badarg("amount is required for Lightning addresses")?;
		state.wallet.pay_lightning_address(&addr, amount, body.comment).await?;
	} else if let Ok(addr) = bitcoin::Address::from_str(&body.destination) {
		let _checked_addr = addr
			.require_network(state.wallet.properties()?.network)
			.context("bitcoin address is not valid for configured network")?;
		let _amount = amount.context("amount missing")?;

		return Err(anyhow!("offboards are temporarily disabled").into());
	} else {
		badarg!("Argument is not a valid destination. Supported are: \
			VTXO pubkeys, bolt11 invoices, bolt12 offers and lightning addresses");
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
		(status = 400, description = "No VTXO IDs provided, or one of the provided VTXO \
			IDs is invalid", body = error::BadRequestError),
		(status = 404, description = "One the VTXOs wasn't found", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a new round participation to refresh the given VTXOs",
	tag = "wallet"
)]
#[debug_handler]
pub async fn refresh_vtxos(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::RefreshRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	if body.vtxos.is_empty() {
		badarg!("No VTXO IDs provided");
	}

	let mut vtxo_ids = Vec::new();
	for s in body.vtxos {
		let id = ark::VtxoId::from_str(&s).badarg("Invalid VTXO id")?;
		state.wallet.get_vtxo_by_id(id).not_found([id], "VTXO not found")?;
		vtxo_ids.push(id);
	}

	let participation = state.wallet
		.build_refresh_participation(vtxo_ids)
		.context("Failed to build round participation")?;

	match participation {
		Some(participation) => {
			let mut round = state.wallet.join_next_round(participation, Some(RoundMovement::Refresh))
				.await
				.context("Failed to store round participation")?;

			let sync = round.state.sync(&state.wallet).await;
			Ok(axum::Json(PendingRoundInfo::new(&round, sync)))
		}
		None => {
			badarg!("No VTXOs to refresh");
		}
	}
}

#[utoipa::path(
	post,
	path = "/refresh/all",
	responses(
		(status = 200, description = "Returns the refresh result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a new round participation to refresh all VTXOs",
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
			let mut round = state.wallet.join_next_round(participation, Some(RoundMovement::Refresh))
				.await
				.context("Failed to store round participation")?;

			let sync = round.state.sync(&state.wallet).await;
			Ok(axum::Json(PendingRoundInfo::new(&round, sync)))
		}
		None => {
			badarg!("No VTXOs to refresh");
		}
	}
}

#[utoipa::path(
	post,
	path = "/refresh/counterparty",
	request_body = bark_json::web::RefreshRequest,
	responses(
		(status = 200, description = "Returns the refresh result", body = bark_json::web::PendingRoundInfo),
		(status = 404, description = "There is no VTXO to refresh", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a new round participation to refresh VTXOs marked with counterparty",
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
			let mut round = state.wallet.join_next_round(participation, Some(RoundMovement::Refresh))
				.await
				.context("Failed to store round participation")?;

			let sync = round.state.sync(&state.wallet).await;
			Ok(axum::Json(PendingRoundInfo::new(&round, sync)))
		}
		None => {
			not_found!(Vec::<String>::new(), "No VTXO to refresh");
		}
	}
}

#[utoipa::path(
	post,
	path = "/offboard/vtxos",
	request_body = bark_json::web::OffboardVtxosRequest,
	responses(
		(status = 200, description = "Returns the offboard result", body = bark_json::web::PendingRoundInfo),
		(status = 400, description = "No VTXO IDs provided, or one of the provided \
			VTXO IDs is invalid, or destination address is invalid", body = error::BadRequestError),
		(status = 404, description = "One the VTXOs wasn't found", body = error::NotFoundError),
		(status = 500, description = "Internal server error")
	),
	description = "Creates a new round participation to offboard the given VTXOs",
	tag = "wallet"
)]
#[debug_handler]
pub async fn offboard_vtxos(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::OffboardVtxosRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let mut onchain_lock = state.onchain.write().await;

	if body.vtxos.is_empty() {
		badarg!("No VTXO IDs provided");
	}

	let _address = if let Some(addr) = body.address {
		let network = state.wallet.properties()?.network;
		bitcoin::Address::from_str(&addr)
			.badarg("invalid destination address")?
			.require_network(network)
			.badarg("address is not valid for configured network")?
	} else {
		onchain_lock.address()?
	};

	let mut _vtxo_ids = Vec::new();
	for s in body.vtxos {
		let id = ark::VtxoId::from_str(&s).badarg("Invalid VTXO id")?;
		state.wallet.get_vtxo_by_id(id).not_found([id], "VTXO not found")?;
		_vtxo_ids.push(id);
	}

	Err(anyhow!("offboards are temporarily not supported").into())
}

#[utoipa::path(
	post,
	path = "/offboard/all",
	request_body = bark_json::web::OffboardAllRequest,
	responses(
		(status = 200, description = "Returns the offboard result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a new round participation to offboard all VTXOs",
	tag = "wallet"
)]
#[debug_handler]
pub async fn offboard_all(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::OffboardAllRequest>,
) -> HandlerResult<Json<bark_json::web::PendingRoundInfo>> {
	let mut onchain_lock = state.onchain.write().await;

	let _address = if let Some(addr) = body.address {
		let network = state.wallet.properties()?.network;
		bitcoin::Address::from_str(&addr)
			.badarg("invalid destination address")?
			.require_network(network)
			.badarg("address is not valid for configured network")?
	} else {
		onchain_lock.address()?
	};

	Err(anyhow!("offboards are temporarily not supported").into())
}

#[utoipa::path(
	post,
	path = "/send-onchain",
	request_body = bark_json::web::SendOnchainRequest,
	responses(
		(status = 200, description = "Returns the send onchain result", body = bark_json::web::PendingRoundInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a new round participation to send a payment onchain from ark round",
	tag = "wallet"
)]
#[debug_handler]
pub async fn send_onchain(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::SendOnchainRequest>,
) -> HandlerResult<Json<()>> {
	let _addr = bitcoin::Address::from_str(&body.destination)
		.badarg("invalid destination address")?
		.require_network(state.wallet.properties()?.network)
		.badarg("address is not valid for configured network")?;

	let _amount = Amount::from_sat(body.amount_sat);

	Err(anyhow!("onchain payments are temporarily not supported").into())
}

#[utoipa::path(
	post,
	path = "/sync",
	responses(
		(status = 200, description = "Wallet was successfully synced"),
	),
	description = "Syncs the wallet",
	tag = "wallet"
)]
#[debug_handler]
pub async fn sync(State(state): State<RestServer>) {
	state.wallet.sync().await;
}
