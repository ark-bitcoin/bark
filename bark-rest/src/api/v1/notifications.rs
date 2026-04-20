use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, Request, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use chrono::{DateTime, Utc};
use bitcoin::hashes::hex::DisplayHex;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use bark_json::notifications::WalletNotification;
use bark::bip39::rand::{self, Rng};
use futures::{SinkExt, StreamExt};

use crate::{ServerState, error};
use crate::auth::authenticate_request;
use crate::error::{HandlerResult, unauthorized};

/// The expiration time for a websocket ticket in minutes
const WEBSOCKET_TICKET_EXPIRATION_MINUTES: u64 = 10;

/// The timeout for the long-poll `wait` endpoint, in seconds
#[cfg(not(test))]
const NOTIFICATION_WAIT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
#[cfg(test)]
const NOTIFICATION_WAIT_REQUEST_TIMEOUT_SECONDS: u64 = 5;

#[derive(OpenApi)]
#[openapi(
	paths(
		websocket_ticket,
		wait_notification,
	),
	components(schemas(
		HandshakeParams,
		bark_json::notifications::WalletNotification,
		bark_json::movements::Movement,
		WaitNotificationQuery,
		WaitNotificationResponse,
		error::InternalServerError,
		error::BadRequestError,
	)),
	components(schemas(
		bark_json::notifications::WalletNotification,
	)),
	tags((name = "notifications", description = "Receive real-time notifications from barkd."))
)]
pub struct NotificationsApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/ws/ticket", get(websocket_ticket))
		.route("/ws", get(websocket_handshake))
		.route("/wait", get(wait_notification))
}

#[utoipa::path(
	get,
	path = "/ws/ticket",
	summary = "Create a websocket ticket",
	description = "Creates a single-use ticket that authenticates a websocket connection \
		at `ws://<host>/api/v1/notifications/ws?ticket=<ticket>`. The ticket must be \
		used within 10 minutes of creation; the resulting websocket connection is \
		long-lived.",
	responses(
		(status = 200, description = "Returns the websocket ticket. Valid to open a websocket connection in the next 10 minutes.", body = String),
		(status = 401, description = "Unauthorized", body = String)
	),
	tag = "notifications"
)]
#[debug_handler]
pub async fn websocket_ticket(
	state: State<ServerState>,
	req: Request<Body>,
) -> HandlerResult<Json<String>> {
	authenticate_request(state.clone(), &req)?;

	let mut write_lock = state.0.websocket_tickets.write().await;

	let req_time = Utc::now();

	// Remove all expired tickets
	let expiration_bound = req_time - Duration::from_secs(WEBSOCKET_TICKET_EXPIRATION_MINUTES * 60);
	write_lock.retain(|_, expiration| {
		let keep = *expiration > expiration_bound;
		if !keep {
			log::debug!("Purging expired ticket: {}", expiration);
		}
		keep
	});

	let ticket = rand::thread_rng().r#gen::<[u8; 32]>().to_lower_hex_string();
	let _ = write_lock.insert(ticket.clone(), req_time);

	Ok(axum::Json(ticket))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HandshakeParams {
	/// The ticket to use to authenticate the websocket connection
	///
	/// The ticket must have been created within the last 10 minutes,
	/// but the created websocket connection is long lived
	ticket: String,
}

async fn websocket_handshake(
	ws: WebSocketUpgrade,
	State(state): State<ServerState>,
	Query(params): Query<HandshakeParams>,
) -> HandlerResult<Response<Body>> {
	if state.websocket_tickets.write().await.remove(&params.ticket).is_none() {
		unauthorized!("Invalid websocket ticket");
	}

	Ok(ws.on_upgrade(|socket| handle_socket(socket, state)))
}

/// Handle a websocket connection and forward notifications
async fn handle_socket(socket: WebSocket, state: ServerState) {
	let (mut sender, mut receiver) = socket.split();

	let wallet = match state.require_wallet() {
		Ok(w) => w,
		Err(e) => {
			error!("websocket handler: no wallet available: {:#}", e);
			return;
		}
	};

	// Create a new subscription to the notification channel
	let mut notification_rx = wallet.subscribe_notifications();

	// Spawn a task to forward notifications from the channel to the websocket
	let mut send_task = tokio::spawn(async move {
		loop {
			match notification_rx.next().await {
				Some(notification) => {
					let notification = WalletNotification::from(notification);
					let json = serde_json::to_string(&notification).unwrap();

					// Send the notification as a text message
					if sender.send(Message::Text(json.into())).await.is_err() {
						break;
					}
				}
				None => break,
			}
		}
	});

	// Handle incoming messages from the client (close connection on close message)
	// Pings are handled automatically by axum/tokio-tungstenite
	let mut recv_task = tokio::spawn(async move {
		while let Some(Ok(msg)) = receiver.next().await {
			if matches!(msg, Message::Close(_)) {
				break;
			}
		}
	});

	// Wait for either task to complete
	tokio::select! {
		_ = &mut send_task => {
			recv_task.abort();
		}
		_ = &mut recv_task => {
			send_task.abort();
		}
	}
}

/// Query parameters for the long-poll `wait` endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct WaitNotificationQuery {
	/// The timestamp to start waiting for notifications from. Defaults to now.
	pub since: Option<DateTime<Utc>>,
}

/// Response payload for the long-poll `wait` endpoint.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct WaitNotificationResponse {
	/// Notifications received during the long-poll window. Empty if the
	/// timeout elapsed without any notifications. Sorted by timestamp
	/// in ascending order.
	pub notifications: Vec<WalletNotification>,
	/// The timestamp of the last notification pushed to the client.
	pub last_pushed_at: Option<DateTime<Utc>>,
}

#[utoipa::path(
	get,
	path = "/wait",
	summary = "Long-poll for wallet notifications",
	params(
		("since" = Option<DateTime<Utc>>, Query,
			description = "The timestamp to start waiting for notifications from. \
				If not provided, returns all notifications in the buffer."),
	),
	responses(
		(status = 200, description = "Returns notifications received during the \
			long-poll window if any. Otherwise returns an empty array with \
			provided `since` argument as `last_pushed_at` field", body = WaitNotificationResponse),
		(status = 400, description = "Invalid query parameters", body = error::BadRequestError),
		(status = 500, description = "Internal server error", body = error::InternalServerError),
	),
	description = "Long-polls for wallet notifications. Returns all notifications \
		received since the given timestamp. If no timestamp is provided, returns all \
		notifications in the buffer. Returned notifications are sorted by timestamp \
		in ascending order.",
	tag = "notifications",
)]
#[debug_handler]
pub async fn wait_notification(
	state: State<ServerState>,
	Query(query): Query<WaitNotificationQuery>,
	req: Request<Body>,
) -> HandlerResult<Json<WaitNotificationResponse>> {
	authenticate_request(state.clone(), &req)?;

	let notif_mngr = state.require_notifications()?;

	tokio::select! {
		_ = tokio::time::sleep(Duration::from_secs(NOTIFICATION_WAIT_REQUEST_TIMEOUT_SECONDS)) => {
			return Ok(Json(WaitNotificationResponse {
				notifications: Vec::new(),
				last_pushed_at: query.since,
			}));
		}
		notif_handle = notif_mngr.wait_notifications(query.since) => {
			if let Some((last_pushed_at, notifications)) = notif_handle {
				let notifications = notifications
					.into_iter()
					.map(WalletNotification::from)
					.collect::<Vec<_>>();

				return Ok(Json(WaitNotificationResponse {
					notifications,
					last_pushed_at: Some(last_pushed_at),
				}));
			} else {
				return Err(anyhow!("Notification manager returned nothing. \
					Server might be shutting down.").into());
			}
		}
	}
}
