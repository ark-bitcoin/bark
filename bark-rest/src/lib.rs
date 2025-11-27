pub mod api;
pub mod config;
pub mod error;

pub use crate::config::Config;


use std::sync::Arc;

use anyhow;
use axum::routing::get;
use bark::daemon::CancellationToken;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use bark::Wallet;
use bark::onchain::OnchainWallet;



const CRATE_VERSION : &'static str = env!("CARGO_PKG_VERSION");

#[derive(OpenApi)]
#[openapi(
	paths(
		ping,
	),
	nest(
		(path = "/api/v1/boards", api = api::v1::boards::BoardsApiDoc),
		(path = "/api/v1/exits", api = api::v1::exits::ExitsApiDoc),
		(path = "/api/v1/lightning", api = api::v1::lightning::LightningApiDoc),
		(path = "/api/v1/onchain", api = api::v1::onchain::OnchainApiDoc),
		(path = "/api/v1/wallet", api = api::v1::wallet::WalletApiDoc),
		(path = "/api/v1/bitcoin", api = api::v1::bitcoin::BitcoinApiDoc),
	),
	info(
		title = "Barkd API",
		version = CRATE_VERSION,
		description = "A simple REST API for Barkd"
	)
)]
pub struct ApiDoc;

/// A server that serves a REST API for the bark [Wallet]
#[derive(Clone)]
pub struct RestServer {
	shutdown: CancellationToken,

	config: Config,
	wallet: Arc<Wallet>,
	onchain: Arc<RwLock<OnchainWallet>>,
}

async fn shutdown_signal(shutdown: CancellationToken) {
	shutdown.cancelled().await;
}

impl RestServer {
	/// Create a new [RestServer] for the given bark [Wallet] and [OnchainWallet]
	pub fn new(
		shutdown: CancellationToken,

		config: Config,
		wallet: Arc<Wallet>,
		onchain: Arc<RwLock<OnchainWallet>>,
	) -> Self {
		Self { shutdown, config, wallet, onchain }
	}

	/// Serve the REST server
	///
	/// This function blocks while the API is being served.
	pub async fn serve(self: RestServer) -> anyhow::Result<()> {
		let shutdown = self.shutdown.clone();

		let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
			.split_for_parts();

		let socket_addr = self.config.socket_addr();

		// Build our application with routes
		let router = router
			.route("/ping", get(ping))
			.nest("/api/v1", api::v1::router())
			.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
			.layer(CorsLayer::permissive())
			.with_state(self)
			.fallback(error::route_not_found);

		// Run the server
		log::info!("Server running on http://{}", socket_addr);

		let listener = tokio::net::TcpListener::bind(socket_addr).await.expect("Failed to bind to address");
		axum::serve(listener, router.into_make_service()).with_graceful_shutdown(shutdown_signal(shutdown)).await?;
		log::info!("Server stopped running");

		Ok(())
	}
}

#[utoipa::path(
	get,
	path = "/ping",
	responses(
		(status = 200, description = "Returns pong")
	)
)]
pub async fn ping() -> &'static str { "pong" }