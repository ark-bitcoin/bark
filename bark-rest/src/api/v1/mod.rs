pub mod exits;
pub mod lightning;
pub mod onchain;
pub mod boards;
pub mod wallet;
pub mod bitcoin;

use axum::Router;

use crate::ServerState;

pub fn router() -> Router<ServerState> {
	Router::new()
		.nest("/lightning", lightning::router())
		.nest("/onchain", onchain::router())
		.nest("/boards", boards::router())
		.nest("/exits", exits::router())
		.nest("/wallet", wallet::router())
		.nest("/bitcoin", bitcoin::router())
}
