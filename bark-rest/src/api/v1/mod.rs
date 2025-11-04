pub mod exit;
pub mod lightning;
pub mod onchain;
pub mod board;
pub mod wallet;

use axum::Router;

use crate::BarkWebState;

pub fn router() -> Router<BarkWebState> {
	Router::new()
		.nest("/lightning", lightning::router())
		.nest("/onchain", onchain::router())
		.nest("/board", board::router())
		.nest("/exit", exit::router())
		.nest("/wallet", wallet::router())
}
