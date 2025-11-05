use axum::extract::State;
use axum::routing::post;
use axum::{debug_handler, Json, Router};
use bitcoin::Amount;
use utoipa::OpenApi;

use crate::error::HandlerResult;
use crate::RestServer;

#[derive(OpenApi)]
#[openapi(
	paths(
		board,
		board_all,
	),
	components(schemas(
		bark_json::web::BoardRequest,
		bark_json::cli::Board,
	)),
	tags((name = "board", description = "Board-related endpoints"))
)]
pub struct BoardApiDoc;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/board", post(board))
		.route("/board/all", post(board_all))
}

#[utoipa::path(
	post,
	path = "/board",
	request_body = bark_json::web::BoardRequest,
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::Board),
		(status = 500, description = "Internal server error")
	),
	tag = "board"
)]
#[debug_handler]
pub async fn board(
	State(state): State<RestServer>,
	Json(params): Json<bark_json::web::BoardRequest>,
) -> HandlerResult<Json<bark_json::cli::Board>> {
	let mut onchain_lock = state.onchain.write().await;

	let board = state.wallet.board_amount(
		&mut *onchain_lock,
		Amount::from_sat(params.amount_sat),
	).await?;

	Ok(axum::Json(board.into()))
}

#[utoipa::path(
	post,
	path = "/board/all",
	responses(
		(status = 200, description = "Returns the board result", body = bark_json::cli::Board),
		(status = 500, description = "Internal server error")
	),
	tag = "board"
)]
#[debug_handler]
pub async fn board_all(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::cli::Board>> {
	let mut onchain_lock = state.onchain.write().await;

	let board = state.wallet.board_all(&mut *onchain_lock).await?;

	Ok(axum::Json(board.into()))
}

