use axum::Router;

use crate::{BarkWebState};

pub fn router() -> Router<BarkWebState> {
	Router::new()
}