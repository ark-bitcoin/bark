
#[macro_use]
extern crate anyhow;

pub mod api;
pub mod auth;
pub mod config;
pub mod error;

use crate::auth::AuthToken;
pub use crate::config::Config;
pub use axum::http;
use chrono::{DateTime, Utc};


use std::collections::{HashMap};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use axum::routing::get;
use log::{error, warn, info};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use axum::http::{header, Method, HeaderValue};
use tower_http::cors::CorsLayer;
use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa_axum::router::OpenApiRouter;

use bark::Wallet;
use bark::onchain::OnchainWalletTrait;
use bark_json::web::CreateWalletRequest;

type BoxFuture<T> =
	Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub type OnWalletCreate = dyn Fn(CreateWalletRequest)
	-> BoxFuture<anyhow::Result<Wallet>> + Send + Sync;

pub type OnWalletDelete = dyn Fn()
	-> BoxFuture<anyhow::Result<()>> + Send + Sync;

/// A hook that returns the wallet's BIP-39 mnemonic phrase.
pub type OnGetMnemonic = dyn Fn()
	-> BoxFuture<anyhow::Result<String>> + Send + Sync;

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
		(path = "/api/v1/fees", api = api::v1::fees::FeesApiDoc),
		(path = "/api/v1/history", api = api::v1::history::HistoryApiDoc),
		(path = "/api/v1/lightning", api = api::v1::lightning::LightningApiDoc),
		(path = "/api/v1/onchain", api = api::v1::onchain::OnchainApiDoc),
		(path = "/api/v1/wallet", api = api::v1::wallet::WalletApiDoc),
		(path = "/api/v1/bitcoin", api = api::v1::bitcoin::BitcoinApiDoc),
		(path = "/api/v1/notifications", api = api::v1::notifications::NotificationApiDoc),
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

/// Shared state held by the REST server.
///
/// Construct via [`ServerState::builder`].
#[derive(Clone)]
pub struct ServerState {
	wallet: Arc<parking_lot::RwLock<Option<Wallet>>>,
	auth_token: Option<AuthToken>,

	/// A hook to be called when a wallet is created, returning a
	/// [Wallet] to be added to the server state
	on_wallet_create: Option<Arc<OnWalletCreate>>,
	/// A hook to be called when a wallet is deleted,
	///in addition to removing the wallet from the server state
	on_wallet_delete: Option<Arc<OnWalletDelete>>,
	/// A hook to be called to retrieve the wallet's mnemonic phrase.
	/// When `None`, the mnemonic endpoint responds with 404.
	on_get_mnemonic: Option<Arc<OnGetMnemonic>>,

	/// A map of websocket tickets to their expiration time
	///
	/// Note: this map is only stored in memory and not persisted
	/// to the database, any server restart will clear the map.
	websocket_tickets: Arc<tokio::sync::RwLock<HashMap<String, DateTime<Utc>>>>,
}

/// Builder for [`ServerState`].
///
/// ```ignore
/// let state = ServerState::builder()
///     .wallet(server_wallet)
///     .auth_token(token)
///     .on_wallet_create(create_hook)
///     .build();
/// ```
pub struct ServerStateBuilder {
	wallet: Option<Wallet>,
	auth_token: Option<AuthToken>,
	on_wallet_create: Option<Arc<OnWalletCreate>>,
	on_wallet_delete: Option<Arc<OnWalletDelete>>,
	on_get_mnemonic: Option<Arc<OnGetMnemonic>>,
}

impl ServerStateBuilder {
	pub fn new() -> Self {
		Self {
			wallet: None,
			auth_token: None,
			on_wallet_create: None,
			on_wallet_delete: None,
			on_get_mnemonic: None,
		}
	}

	pub fn wallet(mut self, wallet: impl Into<Option<Wallet>>) -> Self {
		self.wallet = wallet.into();
		self
	}

	pub fn auth_token(mut self, token: impl Into<Option<AuthToken>>) -> Self {
		self.auth_token = token.into();
		self
	}

	pub fn on_wallet_create(mut self, hook: impl Into<Option<Arc<OnWalletCreate>>>) -> Self {
		self.on_wallet_create = hook.into();
		self
	}

	pub fn on_wallet_delete(mut self, hook: impl Into<Option<Arc<OnWalletDelete>>>) -> Self {
		self.on_wallet_delete = hook.into();
		self
	}

	pub fn on_get_mnemonic(mut self, hook: impl Into<Option<Arc<OnGetMnemonic>>>) -> Self {
		self.on_get_mnemonic = hook.into();
		self
	}

	pub fn build(self) -> ServerState {
		ServerState {
			wallet: Arc::new(parking_lot::RwLock::new(self.wallet)),
			auth_token: self.auth_token,
			on_wallet_create: self.on_wallet_create,
			on_wallet_delete: self.on_wallet_delete,
			on_get_mnemonic: self.on_get_mnemonic,
			websocket_tickets: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
		}
	}
}

impl Default for ServerStateBuilder {
	fn default() -> Self {
		Self::new()
	}
}

impl ServerState {
	pub fn builder() -> ServerStateBuilder {
		ServerStateBuilder::new()
	}

	pub fn require_wallet(&self) -> anyhow::Result<Wallet> {
		self.wallet.read().clone().context("No wallet set")
	}

	pub fn require_onchain(&self) -> anyhow::Result<Arc<tokio::sync::RwLock<dyn OnchainWalletTrait>>> {
		self.wallet.read().as_ref().context("No wallet set")?
			.onchain().context("No onchain wallet configured")
	}

	pub fn auth_token(&self) -> Option<&AuthToken> {
		self.auth_token.as_ref()
	}
}

impl RestServer {
	/// Start a new [RestServer] with the given config and [ServerState].
	///
	/// Build the state via [`ServerState::builder`].
	pub async fn start(config: &Config, state: ServerState) -> anyhow::Result<Self> {
		let (router, _api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
			.split_for_parts();

		let socket_addr = config.socket_addr();

		if state.auth_token().is_none() {
			warn!("No auth token configured — all authentication is disabled");
		}

		let router = router
			.route("/ping", get(ping))
			.nest("/api/v1", api::v1::router(&state));
		#[cfg(feature = "swagger-ui")]
		let router = router
			.merge(utoipa_swagger_ui::SwaggerUi::new("/swagger-ui")
				.url("/api-docs/openapi.json", _api.clone()),
			);
		let router = router
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
	extensions(
		("x-hidden" = json!(true))
	),
	responses(
		(status = 200, description = "Returns pong")
	)
)]
pub async fn ping() -> &'static str { "pong" }
