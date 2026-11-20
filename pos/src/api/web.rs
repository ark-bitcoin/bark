//! Serves the terminal PWA, embedded at build time (see `build.rs`).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use serde_json::json;

use crate::App;


#[derive(RustEmbed)]
#[folder = "$OUT_DIR/web-dist/"]
struct WebDist;

/// `GET /pair/<code>`: the PWA, which reads the code from the path.
pub async fn index() -> Response {
	serve_index()
}

fn serve_index() -> Response {
	match WebDist::get("index.html") {
		Some(file) => (
			[(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
			file.data,
		).into_response(),
		None => (StatusCode::NOT_FOUND, "posd was built without the terminal").into_response(),
	}
}

/// The manifest of an install from a pairing link. Its `start_url` carries
/// the code, so the installed app opens with it: on iOS the installed app
/// does not share storage with the browser that opened the link.
pub async fn pair_manifest(State(app): State<Arc<App>>, Path(code): Path<String>) -> Response {
	if !code.bytes().all(|b| b.is_ascii_hexdigit()) || code.len() > 64 {
		return StatusCode::NOT_FOUND.into_response();
	}
	let _ = app;
	let manifest = json!({
		"name": "Scuttle POS",
		"short_name": "POS",
		"start_url": format!("/pair/{}", code),
		"scope": "/",
		"display": "standalone",
		"background_color": "#ffffff",
		"theme_color": "#ffffff",
		"icons": [
			{ "src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png" },
			{ "src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png" },
		],
	});
	(
		[(header::CONTENT_TYPE, "application/manifest+json"), (header::CACHE_CONTROL, "no-cache")],
		manifest.to_string(),
	).into_response()
}

/// Static assets. Unknown paths outside the API fall back to the PWA, so
/// its client-side routes work on reload.
pub async fn asset(uri: Uri) -> Response {
	let path = uri.path().trim_start_matches('/');
	if path.starts_with("api/") || path.starts_with(".well-known/") {
		return StatusCode::NOT_FOUND.into_response();
	}
	if path.is_empty() {
		return serve_index();
	}
	match WebDist::get(path) {
		Some(file) => {
			// Vite hashes the names of bundled assets, so they never change.
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
				file.data,
			).into_response()
		},
		None if path.starts_with("assets/") || path.contains('.') => StatusCode::NOT_FOUND.into_response(),
		None => serve_index(),
	}
}
