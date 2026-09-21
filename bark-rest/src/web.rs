use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rust_embed::RustEmbed;
use serde::Serialize;

use bark::Wallet;
use bark::chain::ChainSourceSpec;
use bitcoin_ext::rpc::Auth;

use crate::ServerState;
use crate::auth::authed_router;

/// The bark-web distribution staged by build.rs from the directory the
/// BARK_WEB_DIST env var pointed at during the build. Empty when the var
/// was unset, in which case no web UI is served.
#[derive(RustEmbed)]
#[folder = "$OUT_DIR/bark-web-dist/"]
struct WebAssets;

const LOG_DOWNLOAD_NAME: &str = "barkd-debug.log";

#[derive(Clone)]
pub struct WebConfig {
	pub ark_server: String,
	pub chain_source: String,
	pub network: String,
	pub wallet_data_path: String,
	pub datadir: PathBuf,
}

#[derive(Serialize)]
struct WebRuntimeConfig {
	#[serde(rename = "arkServer")]
	ark_server: String,
	/// Either a plain esplora URL string or a bitcoind object, matching
	/// the shapes the UI accepts for its chain source.
	#[serde(rename = "chainSource")]
	chain_source: serde_json::Value,
	network: String,
	#[serde(rename = "walletDataPath")]
	wallet_data_path: String,
}

/// Returns the router back plus a boolean indicating whether the web-ui
/// could be attached.
pub(crate) fn attach_web_routes(
	router: axum::Router<Arc<ServerState>>,
	state: &Arc<ServerState>,
) -> (axum::Router<Arc<ServerState>>, bool) {
	if WebAssets::get("index.html").is_none() {
		log::info!("No bark-web distribution was embedded in this build, not serving a web UI");
		return (router.fallback(crate::error::route_not_found), false);
	}

	if state.web.is_none() {
		log::info!("Web UI disabled, not serving it");
		return (router.fallback(crate::error::route_not_found), false);
	}

	let authed = authed_router(
		state,
		axum::Router::new()
			.route("/api/config", get(config_handler))
			.route("/api/logs", get(logs_handler)),

	);

	let ret = router
		.merge(authed)
		.nest("/api/barkd/api/v1", crate::api::v1::router(state))
		.nest("/barkd-ws/api/v1", crate::api::v1::router(state))
		.fallback(spa_fallback);
	(ret, true)
}

async fn config_handler(State(state): State<Arc<ServerState>>) -> Response {
	let Some(web) = state.web.as_ref() else {
		return (StatusCode::NOT_FOUND, "web ui not configured").into_response();
	};

	// A loaded wallet is the source of truth for the UI; the configured
	// values only seed the create flow while no wallet exists yet.
	if let Ok(wallet) = state.require_wallet() {
		return wallet_config_response(&wallet, web).await;
	}

	Json(WebRuntimeConfig {
		ark_server: web.ark_server.clone(),
		chain_source: serde_json::Value::String(web.chain_source.clone()),
		network: web.network.clone(),
		wallet_data_path: web.wallet_data_path.clone(),
	})
	.into_response()
}

/// The web UI config derived from the loaded wallet.
async fn wallet_config_response(wallet: &Wallet, web: &WebConfig) -> Response {
	let config = wallet.config();

	// The persisted wallet properties store the bitcoin network, which
	// can't distinguish mutinynet from regular signet.
	let network = match wallet.properties().await {
		Ok(props) => match props.network {
			bitcoin::Network::Bitcoin => "mainnet".to_owned(),
			bitcoin::Network::Signet => "signet".to_owned(),
			bitcoin::Network::Regtest => "regtest".to_owned(),
			other => other.to_string(),
		},
		Err(_) => web.network.clone(),
	};

	let chain_source = match config.chain_source() {
		Ok(ChainSourceSpec::Esplora { url }) => serde_json::Value::String(url),
		Ok(ChainSourceSpec::Bitcoind { url, auth: Auth::CookieFile(cookie), .. }) => {
			serde_json::json!({
				"bitcoind": {
					"bitcoind": url,
					"bitcoindAuth": { "cookie": { "cookie": cookie.display().to_string() } },
				},
			})
		},
		// The UI can't represent user/pass bitcoind auth (and shouldn't
		// be handed the password), so fall back to the configured value.
		Ok(ChainSourceSpec::Bitcoind { .. }) | Err(_) => {
			serde_json::Value::String(web.chain_source.clone())
		},
	};

	Json(WebRuntimeConfig {
		ark_server: config.server_address.clone(),
		chain_source,
		network,
		wallet_data_path: web.wallet_data_path.clone(),
	})
	.into_response()
}

async fn logs_handler(State(state): State<Arc<ServerState>>) -> Response {
	let Some(web) = state.web.as_ref() else {
		return (StatusCode::NOT_FOUND, "web ui not configured").into_response();
	};

	let path = web.datadir.join("debug.log");
	match tokio::fs::File::open(&path).await {
		Ok(file) => {
			let stream = tokio_util::io::ReaderStream::new(file);
			(
				[
					(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
					(
						header::CONTENT_DISPOSITION,
						format!("attachment; filename=\"{}\"", LOG_DOWNLOAD_NAME),
					),
				],
				axum::body::Body::from_stream(stream),
			)
				.into_response()
		},
		Err(_) => (StatusCode::NOT_FOUND, "log_unavailable").into_response(),
	}
}

async fn spa_fallback(uri: Uri) -> Response {
	let path = uri.path().trim_start_matches('/');

	if path.starts_with("api/") || path == "ping" {
		return (StatusCode::NOT_FOUND, "not found").into_response();
	}

	serve_asset(path)
}

fn serve_asset(path: &str) -> Response {
	let path = if path.is_empty() { "index.html" } else { path };

	let (path, file) = match WebAssets::get(path) {
		Some(file) => (path, file),
		// Hashed build outputs never fall back to the entry point.
		None if path.starts_with("assets/") => {
			return (StatusCode::NOT_FOUND, "not found").into_response();
		},
		// Any other unknown path is a client-side route: serve the SPA
		// entry point and let its router handle it.
		None => match WebAssets::get("index.html") {
			Some(file) => ("index.html", file),
			None => {
				return (StatusCode::INTERNAL_SERVER_ERROR, "web UI not correctly embedded").into_response();
			},
		},
	};

	let cache = if path.starts_with("assets/") {
		"public, max-age=31536000, immutable"
	} else {
		"no-cache"
	};
	(
		[
			(header::CONTENT_TYPE, file.metadata.mimetype().to_string()),
			(header::CACHE_CONTROL, cache.to_string()),
		],
		file.data.into_owned(),
	)
		.into_response()
}
