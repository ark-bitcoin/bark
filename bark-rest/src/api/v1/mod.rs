pub mod exit;
pub mod lightning;
pub mod onchain;
pub mod board;
pub mod wallet;
pub mod bitcoin;

use axum::Router;

use crate::RestServer;

pub fn router() -> Router<RestServer> {
	Router::new()
		.nest("/lightning", lightning::router())
		.nest("/onchain", onchain::router())
		.nest("/board", board::router())
		.nest("/exit", exit::router())
		.nest("/wallet", wallet::router())
		.nest("/bitcoin", bitcoin::router())
}
