use axum::extract::State;
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use utoipa::OpenApi;

use crate::error::{self, HandlerResult};
use crate::ServerState;

#[derive(OpenApi)]
#[openapi(
	paths(
		tip,
	),
	components(schemas(
		bark_json::web::TipResponse,
	)),
	tags((name = "bitcoin", description = "Query bitcoin network data."))
)]
pub struct BitcoinApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/tip", get(tip))
}

#[utoipa::path(
	get,
	path = "/tip",
	summary = "Get bitcoin tip height",
	responses(
		(status = 200, description = "Returns the current bitcoin tip height", body = bark_json::web::TipResponse),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Queries the wallet's chain source for the block height of the latest block on the best chain.",
	tag = "bitcoin"
)]
#[debug_handler]
pub async fn tip(
	State(state): State<ServerState>,
) -> HandlerResult<Json<bark_json::web::TipResponse>> {
	let wallet = state.require_wallet()?;

	let tip_height = wallet.chain.tip().await?;
	Ok(axum::Json(bark_json::web::TipResponse { tip_height }))
}
