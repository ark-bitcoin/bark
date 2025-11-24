use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use anyhow::Context;
use bitcoin::FeeRate;
use tracing::info;
use utoipa::OpenApi;

use bark::vtxo::selection::{FilterVtxos, VtxoFilter};
use bitcoin_ext::FeeRateExt;

use crate::{error::HandlerResult, RestServer};

#[derive(OpenApi)]
#[openapi(
	paths(
		get_exit_status_by_vtxo_id,
		get_all_exit_status,
		exit_start_vtxos,
		exit_start_all,
		exit_progress,
		exit_claim_all,
		exit_claim_vtxos,
	),
	components(schemas(
		bark_json::web::ExitStatusRequest,
		bark_json::cli::ExitTransactionStatus,
		bark_json::web::ExitStartRequest,
		bark_json::web::ExitStartResponse,
		bark_json::web::ExitProgressRequest,
		bark_json::cli::ExitProgressResponse,
		bark_json::web::ExitClaimAllRequest,
		bark_json::web::ExitClaimVtxosRequest,
		bark_json::web::ExitClaimResponse,
	)),
	tags((name = "exits", description = "Exit-related endpoints"))
)]
pub struct ExitsApiDoc;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/status/{vtxo_id}", get(get_exit_status_by_vtxo_id))
		.route("/status", get(get_all_exit_status))
		.route("/start/vtxos", post(exit_start_vtxos))
		.route("/start/all", post(exit_start_all))
		.route("/progress", post(exit_progress))
		.route("/claim/all", post(exit_claim_all))
		.route("/claim/vtxos", post(exit_claim_vtxos))
}

#[utoipa::path(
	get,
	path = "/status/{vtxo_id}",
	params(
		("vtxo_id" = String, Path, description = "The VTXO to check the exit status of"),
		("history" = Option<bool>, Query, description = "Whether to include the detailed history of the exit process"),
		("transactions" = Option<bool>, Query, description = "Whether to include the exit transactions and their CPFP children")
	),
	responses(
		(status = 200, description = "Returns the exit status", body = bark_json::cli::ExitTransactionStatus),
		(status = 404, description = "VTXO not found"),
		(status = 500, description = "Internal server error")
	),
	description = "Returns the status of the exit for the given VTXO",
	tag = "exits"
)]
#[debug_handler]
pub async fn get_exit_status_by_vtxo_id(
	State(state): State<RestServer>,
	Path(vtxo): Path<String>,
	Query(query): Query<bark_json::web::ExitStatusRequest>,
) -> HandlerResult<Json<bark_json::cli::ExitTransactionStatus>> {
	let vtxo_id = ark::VtxoId::from_str(&vtxo)
		.context("Invalid VTXO ID")?;

	let status = state.wallet.exit.write().await.get_exit_status(
		vtxo_id,
		query.history.unwrap_or(false),
		query.transactions.unwrap_or(false)
	).await.context("Failed to get exit status")?;

	match status {
		None => Err(anyhow::anyhow!("VTXO not found: {}", vtxo_id).into()),
		Some(status) => Ok(axum::Json(status.into())),
	}
}

#[utoipa::path(
	get,
	path = "/status",
	params(
		("history" = Option<bool>, Query, description = "Whether to include the detailed history of the exit process"),
		("transactions" = Option<bool>, Query, description = "Whether to include the exit transactions and their CPFP children")
	),
	responses(
		(status = 200, description = "Returns all exit statuses", body = Vec<bark_json::cli::ExitTransactionStatus>),
		(status = 500, description = "Internal server error")
	),
	description = "Returns all the current in-progress, completed and failed exits",
	tag = "exits"
)]
#[debug_handler]
pub async fn get_all_exit_status(
	State(state): State<RestServer>,
	Query(query): Query<bark_json::web::ExitStatusRequest>,
) -> HandlerResult<Json<Vec<bark_json::cli::ExitTransactionStatus>>> {
	let exit = state.wallet.exit.write().await;
	let mut statuses = Vec::with_capacity(exit.get_exit_vtxos().len());

	for e in exit.get_exit_vtxos() {
		let status = exit.get_exit_status(
			e.id(),
			query.history.unwrap_or(false),
			query.transactions.unwrap_or(false)
		).await.context("Failed to get exit status")?.unwrap();

		statuses.push(bark_json::cli::ExitTransactionStatus::from(status));
	}

	Ok(axum::Json(statuses))
}

#[utoipa::path(
	post,
	path = "/start/vtxos",
	request_body = bark_json::web::ExitStartRequest,
	responses(
		(status = 200, description = "Exit started successfully", body = bark_json::web::ExitStartResponse),
		(status = 400, description = "Bad request - no VTXOs specified"),
		(status = 500, description = "Internal server error")
	),
	description = "Starts an exit for the given VTXOs",
	tag = "exits"
)]
#[debug_handler]
pub async fn exit_start_vtxos(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::ExitStartRequest>,
) -> HandlerResult<Json<bark_json::web::ExitStartResponse>> {
	let mut onchain_lock = state.onchain.write().await;

	if body.vtxos.is_empty() {
		return Err(anyhow::anyhow!("No VTXO IDs provided").into());
	}

	let vtxo_ids = body.vtxos
		.into_iter()
		.map(|s| ark::VtxoId::from_str(&s).context("Invalid VTXO ID"))
		.collect::<anyhow::Result<Vec<_>>>()?;

	let filter = VtxoFilter::new(&state.wallet).include_many(vtxo_ids);

	let spendable = state.wallet.spendable_vtxos_with(&filter)
		.context("Error parsing vtxos")?;
	let inround = {
		let mut vtxos = state.wallet.pending_round_input_vtxos()
			.context("Error parsing vtxos")?;
		filter.filter_vtxos(&mut vtxos)?;
		vtxos
	};

	let vtxos = spendable.into_iter().chain(inround)
		.map(|v| v.vtxo).collect::<Vec<_>>();

	state.wallet.exit.write().await.start_exit_for_vtxos(&vtxos, &mut *onchain_lock).await
		.context("Failed to start exit for VTXOs")?;

	Ok(axum::Json(bark_json::web::ExitStartResponse {
		message: "Exit started successfully".to_string(),
	}))
}

#[utoipa::path(
	post,
	path = "/start/all",
	responses(
		(status = 200, description = "Exit started successfully", body = bark_json::web::ExitStartResponse),
		(status = 400, description = "Bad request - no VTXOs specified"),
		(status = 500, description = "Internal server error")
	),
	description = "Starts an exit for all VTXOs",
	tag = "exits"
)]
#[debug_handler]
pub async fn exit_start_all(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::ExitStartResponse>> {
	let mut onchain_lock = state.onchain.write().await;

	state.wallet.exit.write().await.start_exit_for_entire_wallet(&mut *onchain_lock).await
		.context("Failed to start exit for entire wallet")?;

	Ok(axum::Json(bark_json::web::ExitStartResponse {
		message: "Exit started successfully".to_string(),
	}))
}


#[utoipa::path(
	post,
	path = "/progress",
	request_body = bark_json::web::ExitProgressRequest,
	responses(
		(status = 200, description = "Returns the exit progress", body = bark_json::cli::ExitProgressResponse),
		(status = 500, description = "Internal server error")
	),
	description = "Progresses the exit process of all current exits until it completes",
	tag = "exits"
)]
#[debug_handler]
pub async fn exit_progress(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::ExitProgressRequest>,
) -> HandlerResult<Json<bark_json::cli::ExitProgressResponse>> {
	let mut onchain_lock = state.onchain.write().await;

	let fee_rate = body.fee_rate.map(FeeRate::from_sat_per_kvb_ceil);

	let mut exit = state.wallet.exit.write().await;
	let result = exit.progress_exits(&mut *onchain_lock, fee_rate).await
		.context("error making progress on exit process")?;

	let done = !exit.has_pending_exits();
	let claimable_height = exit.all_claimable_at_height().await;
	let exits = result.unwrap_or_default();

	Ok(axum::Json(bark_json::cli::ExitProgressResponse {
		done,
		claimable_height,
		exits: exits.into_iter().map(|e| e.into()).collect::<Vec<_>>()
	}))
}

async fn inner_claim_vtxos(
	state: &RestServer,
	exit: &bark::exit::Exit,
	address: bitcoin::Address,
	vtxos: &[&bark::exit::ExitVtxo],
	fee_rate: Option<FeeRate>,
) -> HandlerResult<Json<bark_json::web::ExitClaimResponse>> {
	let address_spk = address.script_pubkey();
	let psbt = exit.drain_exits(vtxos, &state.wallet, address, fee_rate).await
		.context("Failed to drain exits")?;
	let tx = psbt.extract_tx()
		.context("Failed to extract transaction")?;
	state.wallet.chain.broadcast_tx(&tx).await
		.context("Failed to broadcast transaction")?;
	info!("Drain transaction broadcasted: {}", tx.compute_txid());

	let mut onchain_lock = state.onchain.write().await;

	// Commit the transaction to the wallet if the claim destination is ours
	if onchain_lock.is_mine(address_spk) {
		info!("Adding claim transaction to wallet: {}", tx.compute_txid());
		let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
			.context("Failed to get current timestamp")?.as_secs();
		onchain_lock.apply_unconfirmed_txs([(tx, timestamp)]);
	}

	Ok(axum::Json(bark_json::web::ExitClaimResponse {
		message: "Exit claimed successfully".to_string(),
	}))
}

#[utoipa::path(
	post,
	path = "/claim/all",
	request_body = bark_json::web::ExitClaimAllRequest,
	responses(
		(status = 200, description = "Exit claimed successfully", body = bark_json::web::ExitClaimResponse),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	description = "Claims all claimable exited VTXOs to the given destination address",
	tag = "exits"
)]
#[debug_handler]
pub async fn exit_claim_all(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::ExitClaimAllRequest>,
) -> HandlerResult<Json<bark_json::web::ExitClaimResponse>> {

	let network = state.wallet.properties()?.network;
	let address = bitcoin::Address::from_str(&body.destination)
		.context("Invalid destination address")?
		.require_network(network)
		.context("Address is not valid for configured network")?;

	let exit = state.wallet.exit.read().await;
	let vtxos = exit.list_claimable();

	let fee_rate = body.fee_rate.map(FeeRate::from_sat_per_kvb_ceil);

	inner_claim_vtxos(&state, &*exit, address, &vtxos, fee_rate).await
}

#[utoipa::path(
	post,
	path = "/claim/vtxos",
	request_body = bark_json::web::ExitClaimVtxosRequest,
	responses(
		(status = 200, description = "Exit claimed successfully", body = bark_json::web::ExitClaimResponse),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	description = "Claims the given exited VTXOs to the given destination address",
	tag = "exits"
)]
#[debug_handler]
pub async fn exit_claim_vtxos(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::ExitClaimVtxosRequest>,
) -> HandlerResult<Json<bark_json::web::ExitClaimResponse>> {
	let network = state.wallet.properties()?.network;
	let address = bitcoin::Address::from_str(&body.destination)
		.context("Invalid destination address")?
		.require_network(network)
		.context("Address is not valid for configured network")?;

	let exit = state.wallet.exit.read().await;
	let vtxos = {
		let mut vtxo_ids = body.vtxos.iter().map(|s| {
			ark::VtxoId::from_str(s).context("invalid vtxo id")
		}).collect::<anyhow::Result<std::collections::HashSet<_>>>()?;
		let vtxos = exit.list_claimable().into_iter()
			.filter(|v| vtxo_ids.remove(&v.id()))
			.collect::<Vec<_>>();
		for id in vtxo_ids {
			return Err(anyhow::anyhow!("Unspendable VTXO provided: {}", id).into());
		}
		vtxos
	};

	let fee_rate = body.fee_rate.map(FeeRate::from_sat_per_kvb_ceil);

	inner_claim_vtxos(&state, &*exit, address, &vtxos, fee_rate).await
}
