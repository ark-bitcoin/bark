use std::str::FromStr;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use anyhow::Context;
use tracing::info;
use utoipa::OpenApi;

use bark::vtxo_selection::FilterVtxos;
use bitcoin_ext::FeeRateExt;

use crate::{error::HandlerResult, BarkWebState};

#[derive(OpenApi)]
#[openapi(
	paths(
		exit_status,
		exit_list,
		exit_start_vtxos,
		exit_start_all,
		exit_progress,
		exit_claim,
	),
	components(schemas(
		bark_json::web::ExitStatusRequest,
		bark_json::cli::ExitTransactionStatus,
		bark_json::web::ExitListRequest,
		bark_json::web::ExitStartRequest,
		bark_json::web::ExitStartResponse,
		bark_json::web::ExitProgressRequest,
		bark_json::cli::ExitProgressResponse,
		bark_json::web::ExitClaimRequest,
		bark_json::web::ExitClaimResponse,
	)),
	tags((name = "exit", description = "Exit-related endpoints"))
)]
pub struct ExitApiDoc;

pub fn router() -> Router<BarkWebState> {
	Router::new()
		.route("/status", get(exit_status))
		.route("/list", get(exit_list))
		.route("/start/vtxos", post(exit_start_vtxos))
		.route("/start/all", post(exit_start_all))
		.route("/progress", post(exit_progress))
		.route("/claim", post(exit_claim))
}

#[utoipa::path(
	get,
	path = "/status",
	params(
		("vtxo" = String, Query, description = "The VTXO to check the exit status of"),
		("history" = Option<bool>, Query, description = "Whether to include the detailed history of the exit process"),
		("transactions" = Option<bool>, Query, description = "Whether to include the exit transactions and their CPFP children")
	),
	responses(
		(status = 200, description = "Returns the exit status", body = bark_json::cli::ExitTransactionStatus),
		(status = 404, description = "VTXO not found"),
		(status = 500, description = "Internal server error")
	),
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_status(
	State(state): State<BarkWebState>,
	Query(params): Query<bark_json::web::ExitStatusRequest>,
) -> HandlerResult<Json<bark_json::cli::ExitTransactionStatus>> {
	let mut wallet_lock = state.wallet.write().await;

	let vtxo_id = ark::VtxoId::from_str(&params.vtxo)
		.context("Invalid VTXO ID")?;

	let status = wallet_lock.exit.get_mut().get_exit_status(
		vtxo_id,
		params.history.unwrap_or(false),
		params.transactions.unwrap_or(false)
	).await.context("Failed to get exit status")?;

	match status {
		None => Err(anyhow::anyhow!("VTXO not found: {}", vtxo_id).into()),
		Some(status) => Ok(axum::Json(status.into())),
	}
}

#[utoipa::path(
	get,
	path = "/list",
	params(
		("history" = Option<bool>, Query, description = "Whether to include the detailed history of the exit process"),
		("transactions" = Option<bool>, Query, description = "Whether to include the exit transactions and their CPFP children")
	),
	responses(
		(status = 200, description = "Returns all exit statuses", body = Vec<bark_json::cli::ExitTransactionStatus>),
		(status = 500, description = "Internal server error")
	),
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_list(
	State(state): State<BarkWebState>,
	Query(params): Query<bark_json::web::ExitListRequest>,
) -> HandlerResult<Json<Vec<bark_json::cli::ExitTransactionStatus>>> {
	let mut wallet_lock = state.wallet.write().await;

	let exit = wallet_lock.exit.get_mut();
	let mut statuses = Vec::with_capacity(exit.get_exit_vtxos().len());

	for e in exit.get_exit_vtxos() {
		let status = exit.get_exit_status(
			e.id(),
			params.history.unwrap_or(false),
			params.transactions.unwrap_or(false)
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
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_start_vtxos(
	State(state): State<BarkWebState>,
	Json(params): Json<bark_json::web::ExitStartRequest>,
) -> HandlerResult<Json<bark_json::web::ExitStartResponse>> {
	let mut wallet_lock = state.wallet.write().await;
	let mut onchain_lock = state.onchain.write().await;

	if params.vtxos.is_empty() {
		return Err(anyhow::anyhow!("No VTXO IDs provided").into());
	}

	let vtxo_ids = params.vtxos
		.into_iter()
		.map(|s| ark::VtxoId::from_str(&s).context("Invalid VTXO ID"))
		.collect::<anyhow::Result<Vec<_>>>()?;

	let filter = bark::vtxo_selection::VtxoFilter::new(&wallet_lock).include_many(vtxo_ids);

	let spendable = wallet_lock.spendable_vtxos_with(&filter)
		.context("Error parsing vtxos")?;
	let inround = {
		let mut vtxos = wallet_lock.pending_round_input_vtxos()
			.context("Error parsing vtxos")?;
		filter.filter_vtxos(&mut vtxos)?;
		vtxos
	};

	let vtxos = spendable.into_iter().chain(inround)
		.map(|v| v.vtxo).collect::<Vec<_>>();

	wallet_lock.exit.get_mut().start_exit_for_vtxos(&vtxos, &mut *onchain_lock).await
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
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_start_all(
	State(state): State<BarkWebState>,
) -> HandlerResult<Json<bark_json::web::ExitStartResponse>> {
	let mut wallet_lock = state.wallet.write().await;
	let mut onchain_lock = state.onchain.write().await;

	wallet_lock.exit.get_mut().start_exit_for_entire_wallet(&mut *onchain_lock).await
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
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_progress(
	State(state): State<BarkWebState>,
	Json(params): Json<bark_json::web::ExitProgressRequest>,
) -> HandlerResult<Json<bark_json::cli::ExitProgressResponse>> {
	let mut wallet_lock = state.wallet.write().await;
	let mut onchain_lock = state.onchain.write().await;

	let fee_rate = params.fee_rate.map(|rate| bitcoin::FeeRate::from_sat_per_kvb_ceil(rate));

	let exit_status = if params.wait.unwrap_or(false) {
		loop {
			let exit_status = progress_exit_once(&mut wallet_lock, &mut onchain_lock, fee_rate).await?;
			if exit_status.done {
				break exit_status
			} else {
				info!("Sleeping for a minute, then will continue...");
				tokio::time::sleep(std::time::Duration::from_secs(60)).await;
			}
		}
	} else {
		progress_exit_once(&mut wallet_lock, &mut onchain_lock, fee_rate).await?
	};

	Ok(axum::Json(exit_status))
}

async fn progress_exit_once(
	wallet: &mut bark::Wallet,
	onchain: &mut bark::onchain::OnchainWallet,
	fee_rate: Option<bitcoin::FeeRate>,
) -> anyhow::Result<bark_json::cli::ExitProgressResponse> {
	let exit = wallet.exit.get_mut();
	let result = exit.progress_exits(onchain, fee_rate).await
		.context("error making progress on exit process")?;

	let done = !exit.has_pending_exits();
	let claimable_height = exit.all_claimable_at_height().await;
	let exits = result.unwrap_or_default();

	Ok(bark_json::cli::ExitProgressResponse {
		done,
		claimable_height,
		exits: exits.into_iter().map(|e| e.into()).collect::<Vec<_>>()
	})
}

#[utoipa::path(
	post,
	path = "/claim",
	request_body = bark_json::web::ExitClaimRequest,
	responses(
		(status = 200, description = "Exit claimed successfully", body = bark_json::web::ExitClaimResponse),
		(status = 400, description = "Bad request - invalid parameters"),
		(status = 500, description = "Internal server error")
	),
	tag = "exit"
)]
#[debug_handler]
pub async fn exit_claim(
	State(state): State<BarkWebState>,
	Json(params): Json<bark_json::web::ExitClaimRequest>,
) -> HandlerResult<Json<bark_json::web::ExitClaimResponse>> {
	let wallet_lock = state.wallet.write().await;
	let mut onchain_lock = state.onchain.write().await;

	let network = wallet_lock.properties()?.network;
	let address = bitcoin::Address::from_str(&params.destination)
		.context("Invalid destination address")?
		.require_network(network)
		.context("Address is not valid for configured network")?;

	let exit = wallet_lock.exit.read().await;
	let vtxos = match (params.vtxos, params.all.unwrap_or(false)) {
		(Some(vtxo_ids), false) => {
			let mut vtxo_ids = vtxo_ids.iter().map(|s| {
				ark::VtxoId::from_str(s).context("invalid vtxo id")
			}).collect::<anyhow::Result<std::collections::HashSet<_>>>()?;
			let vtxos = exit.list_claimable().into_iter()
				.filter(|v| vtxo_ids.remove(&v.id()))
				.collect::<Vec<_>>();
			for id in vtxo_ids {
				return Err(anyhow::anyhow!("Unspendable VTXO provided: {}", id).into());
			}
			vtxos
		},
		(None, true) => exit.list_claimable(),
		(None, false) => return Err(anyhow::anyhow!("Either vtxos or all must be specified").into()),
		(Some(_), true) => return Err(anyhow::anyhow!("Cannot specify both vtxos and all").into()),
	};

	let address_spk = address.script_pubkey();
	let psbt = exit.drain_exits(&vtxos, &wallet_lock, address, None).await
		.context("Failed to drain exits")?;
	let tx = psbt.extract_tx()
		.context("Failed to extract transaction")?;
	wallet_lock.chain.broadcast_tx(&tx).await
		.context("Failed to broadcast transaction")?;
	info!("Drain transaction broadcasted: {}", tx.compute_txid());

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
