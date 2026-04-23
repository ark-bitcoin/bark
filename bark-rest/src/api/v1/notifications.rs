use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, Request, State, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use axum::{debug_handler, Json, Router};
use chrono::Utc;
use bitcoin::hashes::hex::DisplayHex;
use log::error;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use bark_json::notifications::WalletNotification;
use bark::bip39::rand::{self, Rng};
use futures::{SinkExt, StreamExt};

use crate::ServerState;
use crate::auth::authenticate_request;
use crate::error::{HandlerResult, unauthorized};

const WEBSOCKET_TICKET_EXPIRATION_MINUTES: u64 = 10;

#[derive(OpenApi)]
#[openapi(
	paths(
		websocket_ticket,
	),
	components(schemas(
		HandshakeParams,
	)),
	components(schemas(
		bark_json::notifications::WalletNotification,
	)),
	tags((name = "notifications", description = "Receive real-time notifications from barkd."))
)]
pub struct NotificationApiDoc;

pub fn router() -> Router<ServerState> {
	Router::new()
		.route("/ws/ticket", get(websocket_ticket))
		.route("/ws", get(websocket_handshake))
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

