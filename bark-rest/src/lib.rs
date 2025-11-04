pub mod api;
pub mod config;
pub mod error;

use std::sync::Arc;

use anyhow;
use bark::{onchain::OnchainWallet, Wallet};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::Config;

const CRATE_VERSION : &'static str = env!("CARGO_PKG_VERSION");

#[derive(OpenApi)]
#[openapi(
	nest(
		(path = "/api/v1/board", api = api::v1::board::BoardApiDoc),
		(path = "/api/v1/exit", api = api::v1::exit::ExitApiDoc),
		(path = "/api/v1/lightning", api = api::v1::lightning::LightningApiDoc),
		(path = "/api/v1/onchain", api = api::v1::onchain::OnchainApiDoc),
		(path = "/api/v1/wallet", api = api::v1::wallet::WalletApiDoc),
	),
	info(
		title = "Barkd API",
		version = CRATE_VERSION,
		description = "A simple REST API for Barkd"
	)
)]
pub struct ApiDoc;

#[derive(Clone)]
pub struct BarkWebState {
	wallet: Arc<RwLock<Wallet>>,
	onchain: Arc<RwLock<OnchainWallet>>,
}

impl BarkWebState {
	pub fn new(wallet: Arc<RwLock<Wallet>>, onchain: Arc<RwLock<OnchainWallet>>) -> Self {
		Self { wallet, onchain }
	}
}

pub async fn serve(cfg: &Config, state: BarkWebState) -> anyhow::Result<()> {
	let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
		.split_for_parts();

	// Build our application with routes
	let router = router
		.nest("/api/v1", api::v1::router())
		.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
		.layer(CorsLayer::permissive())
		.with_state(state)
		.fallback(error::not_found);

	// Run the server
	let socket_addr = cfg.socket_addr();
	tracing::info!("Server running on http://{}", socket_addr);

	let listener = tokio::net::TcpListener::bind(socket_addr).await.expect("Failed to bind to address");
	axum::serve(listener, router.into_make_service()).await.expect("Failed to serve");
	Ok(())
}