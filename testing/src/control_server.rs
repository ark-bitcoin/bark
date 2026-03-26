
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use bitcoin::Amount;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{Captaind, TestContext};

#[derive(Clone)]
struct AppState {
	ctx: Arc<TestContext>,
	srv: Arc<Captaind>,
	/// The real electrs URL (not the proxy URL returned by [super::esplora_url]).
	upstream_esplora: Arc<str>,
}

pub struct ControlServer {
	state: AppState,
	port: u16,
}

impl ControlServer {
	pub fn new(ctx: Arc<TestContext>, srv: Arc<Captaind>) -> Self {
		let upstream_esplora = ctx.electrs.as_ref()
			.expect("wasm tests require esplora; set CHAIN_SOURCE=esplora")
			.rest_url()
			.replace("0.0.0.0", "127.0.0.1")
			.into();
		let port = portpicker::pick_unused_port()
			.expect("no free TCP port for control server");
		Self { state: AppState { ctx, srv, upstream_esplora }, port }
	}

	pub fn url(&self) -> String {
		format!("http://127.0.0.1:{}", self.port)
	}

	pub fn spawn(self) -> tokio::task::JoinHandle<()> {
		tokio::spawn(self.run())
	}

	async fn run(self) {
		let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port)).await
			.expect("failed to bind control server");
		println!("Control server listening on 127.0.0.1:{}", self.port);

		let app = Router::new()
			.route("/generate_blocks", get(generate_blocks))
			.route("/fund_address", get(fund_address))
			.route("/trigger_round", get(trigger_round))
			.route("/get_new_address", get(get_new_address))
			.route("/esplora/{*rest}", any(esplora))
			.with_state(self.state)
			.layer(SetResponseHeaderLayer::overriding(
				header::CACHE_CONTROL,
				HeaderValue::from_static("no-store"),
			))
			.layer(
				CorsLayer::new()
					.allow_origin(Any)
					.allow_methods(Any)
					.allow_headers(Any),
			);

		axum::serve(listener, app).await.expect("control server failed");
	}
}

/// Renders any propagated error as 400 Bad Request.
struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
	fn from(e: E) -> Self { Self(e.into()) }
}

impl IntoResponse for AppError {
	fn into_response(self) -> Response {
		(StatusCode::BAD_REQUEST, self.0.to_string()).into_response()
	}
}

#[derive(Deserialize)]
struct GenerateBlocksQuery {
	#[serde(default = "one")]
	n: u32,
}

fn one() -> u32 { 1 }

async fn generate_blocks(
	State(state): State<AppState>,
	Query(q): Query<GenerateBlocksQuery>,
) -> Result<String, AppError> {
	Ok(state.ctx.generate_blocks(q.n).await.to_string())
}

#[derive(Deserialize)]
struct FundAddressQuery {
	address: String,
	sats: u64,
}

async fn fund_address(
	State(state): State<AppState>,
	Query(q): Query<FundAddressQuery>,
) -> Result<String, AppError> {
	let txid = state.ctx.bitcoind().fund_addr(&q.address, Amount::from_sat(q.sats)).await;
	state.ctx.bitcoind().generate(1).await;
	state.ctx.await_block_count_sync().await;
	Ok(txid.to_string())
}

async fn esplora(
	State(state): State<AppState>,
	Path(rest): Path<String>,
	RawQuery(query): RawQuery,
	method: Method,
	body: Bytes,
) -> Response {
	let target = match query.as_deref() {
		Some(q) if !q.is_empty() => format!("{}/{}?{}", state.upstream_esplora, rest, q),
		_ => format!("{}/{}", state.upstream_esplora, rest),
	};
	let body_str = std::str::from_utf8(&body).unwrap_or("");
	match esplora_proxy(&target, method.as_str(), body_str).await {
		Ok((ct, body)) => match HeaderValue::from_str(&ct) {
			Ok(ct) => ([(header::CONTENT_TYPE, ct)], body).into_response(),
			Err(_) => body.into_response(),
		},
		Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
	}
}

async fn trigger_round(State(state): State<AppState>) -> &'static str {
	state.srv.trigger_round().await;
	"ok"
}

async fn get_new_address(State(state): State<AppState>) -> String {
	state.ctx.bitcoind().get_new_address().to_string()
}

/// Forward an HTTP request to a local esplora URL.
/// Returns (content_type, raw body bytes). Uses bytes instead of
/// String because some esplora endpoints (e.g. /tx/<txid>/raw)
/// return binary data.
async fn esplora_proxy(url: &str, method: &str, body: &str) -> anyhow::Result<(String, Vec<u8>)> {
	let rest = url.strip_prefix("http://").unwrap_or(url);
	let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
	let path = format!("/{}", path);

	let mut tcp = TcpStream::connect(authority).await?;
	let req = format!(
		"{method} {path} HTTP/1.0\r\nHost: {authority}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len(),
	);
	tcp.write_all(req.as_bytes()).await?;

	let mut resp = Vec::new();
	tcp.read_to_end(&mut resp).await?;

	let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
	let hdrs = String::from_utf8_lossy(&resp[..split]);
	let body = resp[split + 4..].to_vec();

	let ct = hdrs.lines()
		.find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
		.and_then(|l| l.split_once(':'))
		.map(|(_, v)| v.trim().to_string())
		.unwrap_or_else(|| "application/octet-stream".into());

	Ok((ct, body))
}