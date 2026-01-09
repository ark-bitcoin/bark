
#[macro_use]
extern crate anyhow;

pub(crate) mod api;
pub mod config;
pub mod error;

pub use crate::config::Config;


use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use axum::routing::get;
use bark_json::web::CreateWalletRequest;
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

type BoxFuture<T> =
	Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub type OnWalletCreate = dyn Fn(CreateWalletRequest)
	-> BoxFuture<anyhow::Result<ServerWallet>> + Send + Sync;

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

/// A simple wrapper around a [Wallet] and an [OnchainWallet] hold by
/// the [RestServer]
pub struct ServerWallet {
	pub wallet: Arc<Wallet>,
	pub onchain: Arc<RwLock<OnchainWallet>>,
}

impl ServerWallet {
	pub fn new(wallet: Arc<Wallet>, onchain: Arc<RwLock<OnchainWallet>>) -> Self {
		Self { wallet, onchain }
	}
}

#[derive(Clone)]
pub(crate) struct ServerState {
	wallet: Arc<parking_lot::RwLock<Option<ServerWallet>>>,
	on_wallet_create: Option<Arc<OnWalletCreate>>,
}

impl ServerState {
	pub fn require_wallet(&self) -> anyhow::Result<Arc<Wallet>> {
		let wallet = self.wallet.read().as_ref()
			.ok_or_else(|| anyhow!("No wallet set"))?.wallet.clone();
		Ok(wallet)
	}

	pub fn require_onchain(&self) -> anyhow::Result<Arc<RwLock<OnchainWallet>>> {
		let onchain = self.wallet.read().as_ref()
			.ok_or_else(|| anyhow!("No onchain set"))?.onchain.clone();
		Ok(onchain)
	}
}

impl RestServer {
	/// Start a new [RestServer] with the given config and an optional [ServerWallet]
	///
	/// If no wallet is provided, the server will reject any action
	pub async fn start(
		config: &Config,
		wallet: Option<ServerWallet>,
		on_wallet_create: Option<Arc<OnWalletCreate>>,
	) -> anyhow::Result<Self> {
		let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
			.split_for_parts();

		let socket_addr = config.socket_addr();

		let wallet = Arc::new(parking_lot::RwLock::new(wallet));
		let state = ServerState { wallet, on_wallet_create };

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
