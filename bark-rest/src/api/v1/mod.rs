pub mod exit;
pub mod lightning;
pub mod board;

use axum::Router;

use crate::BarkWebState;

pub fn router() -> Router<BarkWebState> {
	Router::new()
		.nest("/lightning", lightning::router())
		.nest("/board", board::router())
		.nest("/exit", exit::router())
}
