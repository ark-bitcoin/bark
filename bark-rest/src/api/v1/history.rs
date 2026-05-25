use axum::extract::State;
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use anyhow::Context;
use utoipa::OpenApi;

use crate::error::{self, HandlerResult};
use crate::ServerState;

#[derive(OpenApi)]
#[openapi(
	paths(
		list,
	),
	components(schemas(
		bark_json::movements::Movement,
		error::InternalServerError,
		error::NotFoundError,
		error::BadRequestError,
	)),
	tags((name = "history", description = "Inspect wallet movement history."))
)]
pub struct HistoryApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/", get(list))
}

#[utoipa::path(
	get,
	path = "/",
	summary = "Get wallet history",
	responses(
		(status = 200, description = "Returns the wallet history", body = Vec<bark_json::movements::Movement>),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the full history of wallet movements ordered from newest to \
		oldest. A movement represents any wallet operation that affects VTXOs—an arkoor \
		send or receive, Lightning send or receive, board, offboard, or refresh. Each \
		entry records which VTXOs were consumed and produced, the effective balance \
		change (if any), fees paid, and the operation status.",
	tag = "history"
)]
#[debug_handler]
pub async fn list(
	State(state): State<ServerState>,
) -> HandlerResult<Json<Vec<bark_json::movements::Movement>>> {
	let wallet = state.require_wallet()?;
	let movements = wallet.history().await.context("Failed to get movements")?;

	let json_movements = movements
		.into_iter()
		.map(|m| bark_json::movements::Movement::try_from(m)
			.context("Failed to convert movement to JSON")
		).collect::<Result<Vec<_>, _>>()?;

	Ok(axum::Json(json_movements))
}
