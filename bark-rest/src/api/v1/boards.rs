use axum::extract::State;
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use utoipa::OpenApi;

use crate::error::{self, HandlerResult};
use crate::ServerState;

#[derive(OpenApi)]
#[openapi(
	paths(
		board_amount,
		board_all,
		get_pending_boards,
	),
	components(schemas(
		bark_json::web::BoardRequest,
		bark_json::cli::PendingBoardInfo,
	)),
	tags((name = "boards", description = "Move on-chain bitcoin onto the Ark protocol."))
)]
pub struct BoardsApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/board-amount", post(board_amount))
		.route("/board-all", post(board_all))
		.route("/", get(get_pending_boards))
}

#[utoipa::path(
	post,
	path = "/board-amount",
	summary = "Board a specific amount",
	request_body = bark_json::web::BoardRequest,
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::PendingBoardInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Moves the specified amount of bitcoin in the on-chain wallet onto the Ark \
		protocol. Creates and broadcasts a funding transaction, then returns the pending board \
		details. The resulting VTXO is not spendable off-chain until the funding transaction \
		reaches the number of on-chain confirmations required by the Ark server.",
	tag = "boards"
)]
#[debug_handler]
pub async fn board_amount(
	State(state): State<ServerState>,
	Json(body): Json<bark_json::web::BoardRequest>,
) -> HandlerResult<Json<bark_json::cli::PendingBoardInfo>> {
	let wallet = state.require_wallet()?;
	let onchain = state.require_onchain()?;

	let mut onchain_lock = onchain.write().await;
	let amount = Amount::from_sat(body.amount_sat);

	let board = wallet.board_amount(
		&mut *onchain_lock,
		amount,
	).await?;

	Ok(axum::Json(board.into()))
}

#[utoipa::path(
	post,
	path = "/board-all",
	summary = "Board all on-chain bitcoin",
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::PendingBoardInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Moves all bitcoin in the on-chain wallet onto the Ark protocol. Creates and \
		broadcasts a funding transaction that drains the on-chain balance into a single VTXO, \
		then returns the pending board details. The resulting VTXO is not spendable off-chain \
		until the funding transaction reaches the number of on-chain confirmations required by \
		the Ark server.",
	tag = "boards"
)]
#[debug_handler]
pub async fn board_all(
	State(state): State<ServerState>,
) -> HandlerResult<Json<bark_json::cli::PendingBoardInfo>> {
	let wallet = state.require_wallet()?;
	let onchain = state.require_onchain()?;

	let mut onchain_lock = onchain.write().await;

	let board = wallet.board_all(&mut *onchain_lock).await?;

	Ok(axum::Json(board.into()))
}

#[utoipa::path(
	get,
	path = "/",
	summary = "List pending boards",
	responses(
		(status = 200, description = "Returns all pending boards", body = Vec<bark_json::cli::PendingBoardInfo>),
		(status = 500, description = "Internal server error")
	),
	description = "Returns all boards whose funding transactions have not yet reached the \
		number of on-chain confirmations required by the Ark server.",
	tag = "boards"
)]
#[debug_handler]
pub async fn get_pending_boards(
	State(state): State<ServerState>,
) -> HandlerResult<Json<Vec<bark_json::cli::PendingBoardInfo>>> {
	let wallet = state.require_wallet()?;

	let boards = wallet.pending_boards().await?.into_iter()
		.map(bark_json::cli::PendingBoardInfo::from).collect();

	Ok(axum::Json(boards))
}
