
#[macro_use]
extern crate anyhow;

pub mod api;
pub mod auth;
pub mod config;
pub mod error;
pub use axum::http;

use crate::auth::AuthToken;
pub use crate::config::Config;


use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use axum::routing::get;
use bark_json::web::CreateWalletRequest;
use log::{error, warn, info};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use axum::http::{header, Method, HeaderValue};
use tower_http::cors::CorsLayer;
use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use bark::Wallet;
use bark::onchain::OnchainWallet;

type BoxFuture<T> =
	Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub type OnWalletCreate = dyn Fn(CreateWalletRequest)
	-> BoxFuture<anyhow::Result<ServerWallet>> + Send + Sync;

pub type OnWalletDelete = dyn Fn()
	-> BoxFuture<anyhow::Result<()>> + Send + Sync;

const CRATE_VERSION : &'static str = env!("CARGO_PKG_VERSION");

// NB please keep below 1000 chars for crates.io publish
const API_DESCRIPTION: &str = "\
A simple REST API for barkd, a wallet daemon for integrating bitcoin payments into your app over HTTP. Supports self-custodial Lightning, Ark, and on-chain out of the box.

barkd is a long-running daemon best suited for always-on or high-connectivity environments like nodes, servers, desktops, and point-of-sale terminals.

All endpoints return JSON. Amounts are denominated in satoshis.";

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
		title = "barkd REST API",
		version = CRATE_VERSION,
		description = API_DESCRIPTION,
	),
	security(
		("bearer" = []),
	),
	modifiers(&BearerSecurity),
)]
pub struct ApiDoc;

struct BearerSecurity;

impl Modify for BearerSecurity {
	fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
		let components = openapi.components.get_or_insert_with(Default::default);
		components.add_security_scheme(
			"bearer",
			SecurityScheme::Http(
				HttpBuilder::new()
					.scheme(HttpAuthScheme::Bearer)
					.bearer_format("AuthToken")
					.description(Some("Base64url-encoded auth token"))
					.build(),
			),
		);
	}
}

fn cors_layer(config: &Config) -> CorsLayer {
	if config.allowed_origins.is_empty() {
		return CorsLayer::new(); // deny all cross-origin
	}

	// Origins are validated at config construction time.
	let origins: Vec<HeaderValue> = config.allowed_origins.iter()
		.map(|o| o.parse().expect("pre-validated"))
		.collect();

	CorsLayer::new()
		.allow_origin(origins)
		.allow_methods([Method::GET, Method::POST, Method::DELETE])
		.allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}

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
pub struct ServerState {
	wallet: Arc<parking_lot::RwLock<Option<ServerWallet>>>,
	on_wallet_create: Option<Arc<OnWalletCreate>>,
	auth_token: Option<AuthToken>,
	on_wallet_delete: Option<Arc<OnWalletDelete>>,
}

impl ServerState {
	pub fn new(
		wallet: Option<ServerWallet>,
		auth_token: Option<AuthToken>,
		on_wallet_create: Option<Arc<OnWalletCreate>>,
		on_wallet_delete: Option<Arc<OnWalletDelete>>,
	) -> Self {
		ServerState {
			wallet: Arc::new(parking_lot::RwLock::new(wallet)),
			on_wallet_create,
			auth_token,
			on_wallet_delete,
		}
	}

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

	pub fn auth_token(&self) -> Option<&AuthToken> {
		self.auth_token.as_ref()
	}
}

impl RestServer {
	/// Start a new [RestServer] with the given config and an optional [ServerWallet]
	///
	/// If no wallet is provided, the server will reject any action.
	/// If `auth_secrets` is non-empty, token-based authentication is
	/// enforced on all `/api/v1` routes.
	pub async fn start(
		config: &Config,
		auth_token: Option<AuthToken>,
		wallet: Option<ServerWallet>,
		on_wallet_create: Option<Arc<OnWalletCreate>>,
		on_wallet_delete: Option<Arc<OnWalletDelete>>,
	) -> anyhow::Result<Self> {
		let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
			.split_for_parts();

		let socket_addr = config.socket_addr();

		if auth_token.is_none() {
			warn!("No auth token configured — all authentication is disabled");
		}

		let state = ServerState::new(wallet, auth_token, on_wallet_create, on_wallet_delete);

		// /ping stays outside the auth layer.
		let authed_api = api::v1::router()
			.route_layer(axum::middleware::from_fn_with_state(state.clone(), auth::guard_auth));

		let router = router
			.route("/ping", get(ping))
			.nest("/api/v1", authed_api)
			.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
			.layer(cors_layer(config))
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
	summary = "Ping",
	security(()),
	responses(
		(status = 200, description = "Returns pong")
	)
)]
pub async fn ping() -> &'static str { "pong" }
