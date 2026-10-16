use std::sync::Arc;

use axum::Json;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use utoipa::openapi::OpenApi;

use crate::ServerState;

const INDEX_HTML: &str = include_str!("../swagger-ui/index.html");
const BUNDLE_JS: &str = include_str!("../swagger-ui/swagger-ui-bundle.js");
const CSS: &str = include_str!("../swagger-ui/swagger-ui.css");
const FAVICON_32: &[u8] = include_bytes!("../swagger-ui/favicon-32x32.png");
const FAVICON_16: &[u8] = include_bytes!("../swagger-ui/favicon-16x16.png");

pub(crate) fn router(api: OpenApi) -> axum::Router<Arc<ServerState>> {
	let api = Arc::new(api);
	axum::Router::new()
		.route("/swagger-ui", get(index))
		.route("/swagger-ui/", get(index))
		.route("/swagger-ui/swagger-ui-bundle.js", get(bundle_js))
		.route("/swagger-ui/swagger-ui.css", get(css))
		.route("/swagger-ui/favicon-32x32.png", get(favicon_32))
		.route("/swagger-ui/favicon-16x16.png", get(favicon_16))
		.route("/api-docs/openapi.json", get(move || async move { Json(api.as_ref().clone()) }))
}

async fn index() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML)
}

async fn bundle_js() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], BUNDLE_JS)
}

async fn css() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}

async fn favicon_32() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "image/png")], FAVICON_32)
}

async fn favicon_16() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "image/png")], FAVICON_16)
}
