
#[macro_use]
extern crate anyhow;

pub(crate) mod api;
pub mod config;
pub mod error;

pub use crate::config::Config;


use std::sync::Arc;

use anyhow::Context;
use axum::routing::get;
use log::{error, info};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
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

async fn shutdown_signal(shutdown: CancellationToken) {
	shutdown.cancelled().await;
}

/// A server that serves a REST API for the bark [Wallet]
pub struct RestServer {
	shutdown: CancellationToken,
	jh: JoinHandle<()>,
}

#[derive(Clone)]
pub(crate) struct ServerState {
	wallet: Arc<Wallet>,
	onchain: Arc<RwLock<OnchainWallet>>,
}

impl RestServer {
	/// Create a new [RestServer] for the given bark [Wallet] and [OnchainWallet]
	pub async fn start(
		config: &Config,
		wallet: Arc<Wallet>,
		onchain: Arc<RwLock<OnchainWallet>>,
	) -> anyhow::Result<Self> {
		let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
			.split_for_parts();

		let socket_addr = config.socket_addr();

		let state = ServerState { wallet, onchain };

		// Build our application with routes
		let router = router
			.route("/ping", get(ping))
			.nest("/api/v1", api::v1::router())
			.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
			.layer(CorsLayer::permissive())
			.with_state(state)
			.fallback(error::route_not_found);

		// Run the server
		log::info!("Server starting on http://{}", socket_addr);

		let listener = tokio::net::TcpListener::bind(socket_addr).await
			.context("Failed to bind to address")?;

		let shutdown = CancellationToken::new();

		let shutdown2 = shutdown.clone();
		let jh = tokio::spawn(async move {
			if let Err(e) = axum::serve(listener, router.into_make_service())
				.with_graceful_shutdown(shutdown_signal(shutdown2)).await
			{
				error!("Error running server: {:#}", e);
			} else {
				info!("Server stopped running");
			}
		});

		Ok(RestServer { shutdown, jh })
	}

	/// Stop the REST server
	pub fn stop(&self) {
		self.shutdown.cancel();
	}

	/// Stop the REST server and wait for it to shut down
	pub async fn stop_wait(self) -> anyhow::Result<()> {
		self.stop();
		self.jh.await?;
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
