use axum::extract::State;
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use utoipa::OpenApi;

use crate::error::HandlerResult;
use crate::RestServer;

#[derive(OpenApi)]
#[openapi(
	paths(
		tip,
	),
	components(schemas(
		bark_json::web::TipResponse,
	)),
	tags((name = "bitcoin", description = "Bitcoin network endpoints"))
)]
pub struct BitcoinApiDoc;

pub fn router() -> Router<RestServer> {
	Router::new()
		.route("/tip", get(tip))
}

#[utoipa::path(
	get,
	path = "/tip",
	responses(
		(status = 200, description = "Returns the current bitcoin tip height", body = bark_json::web::TipResponse),
		(status = 500, description = "Internal server error")
	),
	description = "Returns the current bitcoin tip height",
	tag = "bitcoin"
)]
#[debug_handler]
pub async fn tip(
	State(state): State<RestServer>,
) -> HandlerResult<Json<bark_json::web::TipResponse>> {
	let tip_height = state.wallet.chain.tip().await?;
	Ok(axum::Json(bark_json::web::TipResponse { tip_height }))
}


