use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{debug_handler, Json, Router};
use anyhow::Context;
use utoipa::OpenApi;

use bark::movement::{MovementId, PaymentMethod};

use crate::error::{self, badarg, ContextExt, HandlerResult};
use crate::ServerState;

#[derive(OpenApi)]
#[openapi(
	paths(
		list,
		update_metadata,
	),
	components(schemas(
		bark_json::movements::Movement,
		error::InternalServerError,
		error::NotFoundError,
		error::BadRequestError,
	)),
	tags((name = "history", description = "Inspect and annotate wallet movement history."))
)]
pub struct HistoryApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/", get(list))
		.route("/{id}/metadata", post(update_metadata))
}

#[utoipa::path(
	get,
	path = "",
	summary = "Get wallet history",
	params(
		("type" = Option<String>, Query, description = "Payment method type tag to \
			filter by, e.g. `ark`, `bitcoin`, `output-script`, `invoice`, `offer`, \
			`lightning-address`, `lnurl` or `custom`. Must be supplied together with \
			`value`."),
		("value" = Option<String>, Query, description = "Payment method value to filter \
			by, e.g. the destination address or invoice. Must be supplied together with \
			`type`."),
	),
	responses(
		(status = 200, description = "Returns the wallet history", body = Vec<bark_json::movements::Movement>),
		(status = 400, description = "Bad request", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Returns the history of wallet movements ordered from newest to \
		oldest. A movement represents any wallet operation that affects VTXOs—an arkoor \
		send or receive, Lightning send or receive, board, offboard, or refresh. Each \
		entry records which VTXOs were consumed and produced, the effective balance \
		change (if any), fees paid, and the operation status. Supplying the `type` and \
		`value` query parameters (together) restricts the result to movements involving \
		that single payment method, such as all payments sent to one address.",
	tag = "history"
)]
#[debug_handler]
pub async fn list(
	State(state): State<ServerState>,
	Query(query): Query<bark_json::web::HistoryQuery>,
) -> HandlerResult<Json<Vec<bark_json::movements::Movement>>> {
	let wallet = state.require_wallet()?;
	let movements = match (query.method_type, query.value) {
		(Some(method_type), Some(value)) => {
			let pm = PaymentMethod::from_type_value(&method_type, &value)
				.badarg("invalid payment method")?;
			wallet.history_by_payment_method(&pm).await
				.context("Failed to get movements")?
		},
		(None, None) => wallet.history().await.context("Failed to get movements")?,
		_ => badarg!("`type` and `value` must be supplied together"),
	};

	let json_movements = movements
		.into_iter()
		.map(|m| bark_json::movements::Movement::try_from(m)
			.context("Failed to convert movement to JSON")
		).collect::<Result<Vec<_>, _>>()?;

	Ok(axum::Json(json_movements))
}

#[utoipa::path(
	post,
	path = "/{id}/metadata",
	summary = "Patch movement metadata",
	params(
		("id" = u32, Path, description = "Movement identifier."),
	),
	request_body(
		content = serde_json::Value,
		content_type = "application/merge-patch+json",
		description = "RFC 7396 JSON Merge Patch. The body is applied directly to the \
			movement's metadata object: any field with value `null` is removed, every \
			other field is recursively merged.",
	),
	responses(
		(status = 200, description = "Metadata updated"),
		(status = 500, description = "Internal server error", body = error::InternalServerError),
	),
	description = "Applies an [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396) JSON Merge \
		Patch to a movement's metadata. Use this to annotate history entries after the fact \
		(e.g. refund notes, counterparty info). Keys set to `null` are removed; other values \
		are recursively merged.",
	tag = "history"
)]
#[debug_handler]
pub async fn update_metadata(
	State(state): State<ServerState>,
	Path(id): Path<u32>,
	Json(patch): Json<serde_json::Value>,
) -> HandlerResult<()> {
	let wallet = state.require_wallet()?;
	wallet.update_history_metadata(MovementId::new(id), &patch).await?;
	Ok(())
}
