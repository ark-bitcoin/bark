pub mod exits;
pub mod fees;
pub mod history;
pub mod lightning;
pub mod message;
pub mod notifications;
pub mod onchain;
pub mod boards;
pub mod wallet;
pub mod bitcoin;

use std::sync::Arc;

use axum::Router;

use crate::ServerState;
use crate::auth::authed_router;

pub fn router(state: &Arc<ServerState>) -> Router<Arc<ServerState>> {
	Router::new()
		.nest("/lightning", authed_router(state, lightning::router()))
		.nest("/onchain", authed_router(state, onchain::router()))
		.nest("/boards", authed_router(state, boards::router()))
		.nest("/exits", authed_router(state, exits::router()))
		.nest("/fees", authed_router(state, fees::router()))
		.nest("/history", authed_router(state, history::router()))
		.nest("/message", authed_router(state, message::router()))
		.nest("/wallet", authed_router(state, wallet::router()))
		.nest("/bitcoin", authed_router(state, bitcoin::router()))
		.nest("/notifications", notifications::router())
}
