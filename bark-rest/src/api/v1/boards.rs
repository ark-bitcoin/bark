use axum::extract::State;
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use utoipa::OpenApi;

use crate::error::{self, HandlerResult};
use crate::RestServer;

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
	tags((name = "boards", description = "Board-related endpoints"))
)]
pub struct BoardsApiDoc;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/board-amount", post(board_amount))
		.route("/board-all", post(board_all))
		.route("/", get(get_pending_boards))
}

#[utoipa::path(
	post,
	path = "/board-amount",
	request_body = bark_json::web::BoardRequest,
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::PendingBoardInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Board the given amount of onchain funds to the offchain wallet",
	tag = "boards"
)]
#[debug_handler]
pub async fn board_amount(
	State(state): State<RestServer>,
	Json(body): Json<bark_json::web::BoardRequest>,
) -> HandlerResult<Json<bark_json::cli::PendingBoardInfo>> {
	let mut onchain_lock = state.onchain.write().await;
	let amount = Amount::from_sat(body.amount_sat);

	let board = state.wallet.board_amount(
		&mut *onchain_lock,
		amount,
	).await?;

	Ok(axum::Json(board.into()))
}

#[utoipa::path(
	post,
	path = "/board-all",
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::PendingBoardInfo),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Board all the onchain funds to the offchain wallet",
	tag = "boards"
)]
#[debug_handler]
pub async fn board_all(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::cli::PendingBoardInfo>> {
	let mut onchain_lock = state.onchain.write().await;

	let board = state.wallet.board_all(&mut *onchain_lock).await?;

	Ok(axum::Json(board.into()))
}

#[utoipa::path(
	get,
	path = "/",
	responses(
		(status = 200, description = "Returns all pending boards", body = Vec<bark_json::cli::PendingBoardInfo>),
		(status = 500, description = "Internal server error")
	),
	tag = "boards"
)]
#[debug_handler]
pub async fn get_pending_boards(
	State(state): State<RestServer>,
) -> HandlerResult<Json<Vec<bark_json::cli::PendingBoardInfo>>> {
	let boards = state.wallet.pending_boards()?.into_iter()
		.map(bark_json::cli::PendingBoardInfo::from).collect();

	Ok(axum::Json(boards))
}

