use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{debug_handler, Json, Router};
use utoipa::OpenApi;

use bark_json::web::{
	NwcConnectionListResponse, NwcConnectionRequest, NwcConnectionResponse, NwcRelayRequest,
	NwcRelaysResponse,
};

use crate::error::{self, HandlerResult, badarg, not_found};
use crate::ServerState;


#[derive(OpenApi)]
#[openapi(
	paths(
		create_connection, list_connections, revoke_connection,
		list_relays, add_relay, remove_relay,
	),
	components(schemas(
		NwcConnectionRequest,
		NwcConnectionResponse,
		NwcConnectionListResponse,
		bark_json::web::NwcConnectionInfo,
		NwcRelayRequest,
		NwcRelaysResponse,
	)),
	tags((name = "nwc", description = "Manage Nostr Wallet Connect connections and the relays \
		they are served on. bark supports the NWC methods `get_info`, `get_balance`, \
		`make_invoice`, `lookup_invoice`, `pay_invoice` and `list_transactions`."))
)]
pub struct NwcApiDoc;

pub fn router() -> Router<Arc<ServerState>> {
	Router::new()
		.route("/connections", post(create_connection))
		.route("/connections", get(list_connections))
		.route("/connections/{client_pubkey}", delete(revoke_connection))
		.route("/relays", get(list_relays))
		.route("/relays", post(add_relay))
		.route("/relays/{relay}", delete(remove_relay))
}

#[utoipa::path(
	post,
	path = "/connections",
	summary = "Create a NWC connection",
	request_body = NwcConnectionRequest,
	responses(
		(status = 200, description = "Returns the connection URI", body = NwcConnectionResponse),
		(status = 400, description = "Every method is turned off, or no relays are configured", body = error::BadRequestError),
		(status = 404, description = "NWC is off on this daemon", body = error::NotFoundError),
		(status = 422, description = "`methods` names a method bark does not know"),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Creates a Nostr Wallet Connect connection and returns the \
		`nostr+walletconnect://` URI to hand to an app. The URI contains a secret \
		that is not stored and is returned only once; a lost URI has to be \
		revoked and recreated.\n\n\
		Every method bark supports is allowed unless it is set to `false` in \
		`methods`, so a connection created without `methods` may call all of \
		them, `pay_invoice` included.\n\n\
		The URI names the relays configured at creation, so at least one relay \
		has to be added first (see `POST /api/v1/nwc/relays`).\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn create_connection(
	State(state): State<Arc<ServerState>>,
	Json(req): Json<NwcConnectionRequest>,
) -> HandlerResult<Json<NwcConnectionResponse>> {
	let nwc = state.require_nwc()?;
	let methods = req.methods.clone().unwrap_or_default();
	if methods.allowed().is_empty() {
		badarg!("a connection with every method turned off cannot do anything");
	}
	Ok(Json(nwc.create(req).await?))
}

#[utoipa::path(
	get,
	path = "/connections",
	summary = "List NWC connections",
	responses(
		(status = 200, description = "Returns all connections", body = NwcConnectionListResponse),
		(status = 404, description = "NWC is off on this daemon", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Lists every Nostr Wallet Connect connection with its permitted \
		methods. Connection secrets are never returned.\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn list_connections(
	State(state): State<Arc<ServerState>>,
) -> HandlerResult<Json<NwcConnectionListResponse>> {
	let nwc = state.require_nwc()?;
	Ok(Json(nwc.list().await?))
}

#[utoipa::path(
	delete,
	path = "/connections/{client_pubkey}",
	summary = "Revoke a NWC connection",
	params(("client_pubkey" = String, Path, description = "The connection's client public key")),
	responses(
		(status = 200, description = "The connection was revoked"),
		(status = 404, description = "No such connection, or NWC is off on this daemon", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Revokes a Nostr Wallet Connect connection and stops serving it. \
		The app loses access immediately; requests it sends afterwards go \
		unanswered rather than being refused, because the service it was talking \
		to no longer exists.\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn revoke_connection(
	State(state): State<Arc<ServerState>>,
	Path(client_pubkey): Path<String>,
) -> HandlerResult<()> {
	let nwc = state.require_nwc()?;
	if !nwc.revoke(&client_pubkey).await? {
		not_found!([&client_pubkey], "no NWC connection with that public key");
	}
	Ok(())
}

#[utoipa::path(
	get,
	path = "/relays",
	summary = "List NWC relays",
	responses(
		(status = 200, description = "Returns the relays NWC is served on", body = NwcRelaysResponse),
		(status = 404, description = "NWC is off on this daemon", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Lists the nostr relays that Nostr Wallet Connect is served on.\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn list_relays(
	State(state): State<Arc<ServerState>>,
) -> HandlerResult<Json<NwcRelaysResponse>> {
	let nwc = state.require_nwc()?;
	Ok(Json(nwc.relays().await?))
}

#[utoipa::path(
	post,
	path = "/relays",
	summary = "Add a NWC relay",
	request_body = NwcRelayRequest,
	responses(
		(status = 200, description = "Returns the relays after the change", body = NwcRelaysResponse),
		(status = 400, description = "The relay is not a ws:// or wss:// url", body = error::BadRequestError),
		(status = 404, description = "NWC is off on this daemon", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Adds a nostr relay and restarts every connection's service on the \
		new set. The change is stored with the connections in nwc.json, so it \
		survives a restart. Adding a relay that is already configured changes \
		nothing.\n\n\
		Existing connection URIs keep the relays they were created with, so an \
		app only learns of the new relay from a new connection.\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn add_relay(
	State(state): State<Arc<ServerState>>,
	Json(req): Json<NwcRelayRequest>,
) -> HandlerResult<Json<NwcRelaysResponse>> {
	let nwc = state.require_nwc()?;
	Ok(Json(nwc.add_relay(req.relay).await?))
}

#[utoipa::path(
	delete,
	path = "/relays/{relay}",
	summary = "Remove a NWC relay",
	params(("relay" = String, Path, description = "The relay url, percent-encoded")),
	responses(
		(status = 200, description = "Returns the relays after the change", body = NwcRelaysResponse),
		(status = 404, description = "No such relay, or NWC is off on this daemon", body = error::NotFoundError),
		(status = 500, description = "Internal server error", body = error::InternalServerError)
	),
	description = "Removes a nostr relay and restarts every connection's service on the \
		remaining ones. The change is stored with the connections in \
		nwc.json, so it survives a restart.\n\n\
		An app only reaches the wallet through the relays in its connection URI, \
		so removing all of them cuts it off until it is given a new connection.\n\n\
		The NWC endpoints respond with 404 when barkd was built without NWC \
		support or has no wallet loaded.",
	tag = "nwc"
)]
#[debug_handler]
pub async fn remove_relay(
	State(state): State<Arc<ServerState>>,
	Path(relay): Path<String>,
) -> HandlerResult<Json<NwcRelaysResponse>> {
	let nwc = state.require_nwc()?;
	Ok(Json(nwc.remove_relay(relay).await?))
}
