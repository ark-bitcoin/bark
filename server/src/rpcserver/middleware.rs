use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::HeaderMap;
use http_body::Body as HttpBody;
use opentelemetry::KeyValue;
use parking_lot::RwLock;
use server_rpc::client::{ACCESS_TOKEN_HEADER, USER_AGENT_HEADER};
use server_rpc::lookup_grpc_method;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};
use tracing::{debug, error, info_span, trace, Instrument};
use crate::telemetry::{self};
use super::MAX_PROTOCOL_VERSION;

const RPC_SYSTEM_HTTP: &str = "http";
const RPC_SYSTEM_GRPC: &str = "grpc";

/// Hard cap on distinct `client` label values admitted per process lifetime.
/// Once full, unknown names roll up into the `other` bucket. With pre-seeded
/// known clients ([SEEN_CLIENTS]) the effective dynamic budget is slightly
/// smaller than this number.
const MAX_CLIENT_BUCKETS: usize = 1024;
/// Max length of an accepted client name. Longer names are rejected.
const MAX_CLIENT_NAME_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct RpcMethodDetails {
	system: &'static str,
	service: &'static str,
	method: &'static str,
	client: &'static str,
}

impl RpcMethodDetails {
	pub fn format_path(&self) -> String {
		format!("{}://{}/{}", self.system, self.service, self.method)
	}
}

/// Process-wide set of admitted `client` label values. Pre-seeded with the
/// canonical client names we ship (pure-Rust `bark` plus the per-binding flavors
/// from `bark-ffi-bindings`) so their slots are always available even if an
/// attacker races to fill the dynamic budget on startup. Members are `'static`
/// because we leak admitted names ([bucket_client] uses `Box::leak`); the set
/// is bounded by [MAX_CLIENT_BUCKETS] so the total leak is at most ~1KB per
/// process.
static SEEN_CLIENTS: LazyLock<RwLock<HashSet<&'static str>>> = LazyLock::new(|| {
	let mut s = HashSet::new();
	s.insert("bark");
	s.insert("bark-kotlin");
	s.insert("bark-swift");
	s.insert("bark-dart");
	s.insert("bark-react-native");
	s.insert("bark-wasm");
	s.insert("bark-go");
	RwLock::new(s)
});

/// Parse a strict `<name>/<version>` user-agent value, borrowing the name slice.
///
/// Called on every request, so this is allocation-free. The schema is rigid:
/// exactly one `/`, a non-empty name on the left, a non-empty version on the
/// right. The name must be lowercase ASCII alphanumeric with optional `-`/`_`
/// and no longer than [MAX_CLIENT_NAME_LEN]. We don't lowercase ourselves
/// (that would allocate); uppercase names are rejected so misbehaving clients
/// get a clear signal rather than silently bucketing as something else.
fn parse_client_name(raw: &str) -> Option<&str> {
	let (name, version) = raw.split_once('/')?;
	if name.is_empty() || version.is_empty() || name.len() > MAX_CLIENT_NAME_LEN {
		return None;
	}
	if !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')) {
		return None;
	}
	Some(name)
}

/// Bucket a raw `x-user-agent` value into a stable `client` telemetry label.
///
/// - `None` (header absent) -> `Ok("unknown")`.
/// - Header present but malformed -> `Err(())`; the caller should reject the RPC.
/// - Otherwise, the parsed name is admitted to [SEEN_CLIENTS] up to
///   [MAX_CLIENT_BUCKETS], returning the interned `&'static str`. Past the
///   cap further unique names collapse into `other`, bounding label cardinality.
pub fn bucket_client(raw: Option<&str>) -> Result<&'static str, ()> {
	let Some(raw) = raw else { return Ok("unknown") };
	let name = parse_client_name(raw).ok_or(())?;

	// Fast path: already admitted.
	if let Some(&interned) = SEEN_CLIENTS.read().get(name) {
		return Ok(interned);
	}

	// Slow path: admit if we still have budget.
	let mut seen = SEEN_CLIENTS.write();
	// Re-check under the write lock in case another thread admitted concurrently.
	if let Some(&interned) = seen.get(name) {
		return Ok(interned);
	}
	if seen.len() >= MAX_CLIENT_BUCKETS {
		return Ok("other");
	}
	let interned: &'static str = Box::leak(Box::<str>::from(name));
	seen.insert(interned);
	// Fire exactly once, on the insert that brings us up to the cap. After
	// this point any further unique client names bucket as "other". Emitted
	// at error level so the team is paged: hitting the cap means either the
	// budget needs raising or something fishy is going on, both of which
	// warrant prompt attention.
	if seen.len() == MAX_CLIENT_BUCKETS {
		let mut admitted: Vec<&'static str> = seen.iter().copied().collect();
		admitted.sort_unstable();
		error!(
			"rpc.client bucket budget exhausted ({}/{} admitted: {:?}); \
			 further unique client names will be reported as 'other'",
			seen.len(), MAX_CLIENT_BUCKETS, admitted,
		);
	}
	Ok(interned)
}

#[derive(Clone)]
pub struct RemoteAddrLayer;

impl<S> Layer<S> for RemoteAddrLayer {
	type Service = RemoteAddrService<S>;

	fn layer(&self, inner: S) -> Self::Service {
		RemoteAddrService { inner }
	}
}

#[derive(Clone)]
pub struct RemoteAddrService<S> {
	inner: S,
}

impl<S, ReqBody> Service<hyper::Request<ReqBody>> for RemoteAddrService<S>
where
	S: Service<hyper::Request<ReqBody>>,
	S::Future: Send + 'static,
	ReqBody: http_body::Body + Send + 'static,
	<ReqBody as http_body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = S::Future;

	fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, mut req: hyper::Request<ReqBody>) -> Self::Future {
		if let Some(ff) = req
			.headers()
			.get("x-forwarded-for")
			.and_then(|v| v.to_str().ok())
			.and_then(|s| s.split(',').next())
			.and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
		{
			req.extensions_mut().insert(std::net::SocketAddr::new(ff, 0));
		} else if let Some(remote) = req
			.extensions()
			.get::<TcpConnectInfo>()
			.and_then(|info| info.remote_addr())
		{
			// 2. Fallback: the TCP peer (nginx or direct client)
			req.extensions_mut().insert(remote);
		}

		self.inner.call(req)
	}
}

fn report_grpc_status(
	headers: &HeaderMap,
	rpc_method_details: &RpcMethodDetails,
	duration: Duration,
) {
	let code = headers
		.get("grpc-status")
		.and_then(|v| v.to_str().ok())
		.and_then(|s| s.parse::<i32>().ok());

	match code {
		Some(0) => {
			trace!(
				"Completed gRPC call: {} in {:?}, status: OK",
				rpc_method_details.format_path(),
				duration,
			);
		}
		Some(code) => {
			telemetry::add_grpc_error(&[
				KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
				KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
				KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
				KeyValue::new(telemetry::RPC_CLIENT, rpc_method_details.client),
				KeyValue::new(telemetry::ATTRIBUTE_ERROR, tonic::Code::from_i32(code).to_string()),
			]);

			let grpc_message = headers
				.get("grpc-message")
				.and_then(|v| v.to_str().ok())
				.unwrap_or("unknown error");

			debug!(
				"Completed gRPC call: {} in {:?}, status={}, message={}",
				rpc_method_details.format_path(),
				duration,
				tonic::Code::from_i32(code),
				grpc_message,
			);
		}
		None => {
			// Trailers frame arrived without grpc-status — protocol violation.
			telemetry::add_grpc_error(&[
				KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
				KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
				KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
				KeyValue::new(telemetry::RPC_CLIENT, rpc_method_details.client),
				KeyValue::new(telemetry::ATTRIBUTE_ERROR, "missing_grpc_status"),
			]);

			debug!(
				"Completed gRPC call: {} in {:?}, error: missing or unparseable grpc-status in trailers",
				rpc_method_details.format_path(),
				duration,
			);
		}
	}
}

/// A wrapper around a response body that captures gRPC trailers for telemetry
pub struct TrailerCapturingBody<B> {
	inner: B,
	rpc_method_details: RpcMethodDetails,
	start_time: Instant,
	skip_telemetry: bool,
}

impl<B> TrailerCapturingBody<B> {
	fn new(
		inner: B,
		rpc_method_details: RpcMethodDetails,
		start_time: Instant,
	) -> Self {
		Self {
			inner,
			rpc_method_details,
			start_time,
			skip_telemetry: false,
		}
	}

	/// Wrap a body without capturing trailers or emitting telemetry.
	fn noop(inner: B) -> Self {
		Self {
			inner,
			rpc_method_details: RpcMethodDetails {
				system: RPC_SYSTEM_GRPC, service: "health", method: "check",
				client: "unknown",
			},
			start_time: Instant::now(),
			skip_telemetry: true,
		}
	}
}

impl<B> HttpBody for TrailerCapturingBody<B>
where
	B: HttpBody + Unpin,
	B::Error: std::fmt::Display,
{
	type Data = B::Data;
	type Error = B::Error;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
		let result = Pin::new(&mut self.inner).poll_frame(cx);

		if self.skip_telemetry {
			return result;
		}

		match &result {
			// Handle body/framing errors
			Poll::Ready(Some(Err(e))) => {
				telemetry::add_grpc_error(&[
					KeyValue::new(telemetry::RPC_SYSTEM, self.rpc_method_details.system),
					KeyValue::new(telemetry::RPC_SERVICE, self.rpc_method_details.service),
					KeyValue::new(telemetry::RPC_METHOD, self.rpc_method_details.method),
					KeyValue::new(telemetry::RPC_CLIENT, self.rpc_method_details.client),
					KeyValue::new(telemetry::ATTRIBUTE_ERROR, "body_error"),
				]);

				trace!(
					"gRPC call {} failed with body error: {} (after {:?})",
					self.rpc_method_details.format_path(), e, self.start_time.elapsed(),
				);
			}
			// Check if this is the trailers frame. Called unconditionally so
			// that a missing grpc-status is treated as a protocol error.
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(trailers) = frame.trailers_ref() {
					report_grpc_status(
						trailers, &self.rpc_method_details, self.start_time.elapsed(),
					);
				}
			}
			// Other cases (Pending, Ready(None)) don't need special handling
			_ => {}
		}

		result
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> http_body::SizeHint {
		self.inner.size_hint()
	}
}

#[derive(Clone)]
pub struct TelemetryMetricsService<S> {
	inner: S,
}

impl<S> TelemetryMetricsService<S> {
	fn new(inner: S) -> TelemetryMetricsService<S> {
		TelemetryMetricsService { inner }
	}
}

impl<S, B, ResBody> tower::Service<http::Request<B>> for TelemetryMetricsService<S>
where
	S: tower::Service<http::Request<B>, Response = http::Response<ResBody>> + Send + 'static,
	S::Future: Send + 'static,
	S::Error: std::fmt::Debug,
	B: http_body::Body + Send + 'static,
	B::Error: Into<tonic::codegen::StdError> + Send + 'static,
	ResBody: HttpBody + Unpin + Send + Default + 'static,
	ResBody::Error: std::fmt::Display,
{
	type Response = http::Response<TrailerCapturingBody<ResBody>>;
	type Error = S::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: http::Request<B>) -> Self::Future {
		// Health check probes bypass telemetry
		if req.uri().path() == "/grpc.health.v1.Health/Check" {
			let future = self.inner.call(req);
			return Box::pin(async { future.await.map(|r| r.map(|b| TrailerCapturingBody::noop(b))) });
		}

		let is_grpc = req.headers().get("content-type")
			.map_or(false, |ct| ct == "application/grpc");

		let raw_ua = req.headers().get(USER_AGENT_HEADER).and_then(|v| v.to_str().ok());
		let client = match bucket_client(raw_ua) {
			Ok(client) => client,
			Err(()) => {
				// Header is present but doesn't match `<name>/<version>`.
				// Reject the request with a trailers-only invalid_argument
				// response so misbehaving clients get a clear signal rather
				// than silently rolling up into a junk bucket.
				debug!("rejecting RPC: malformed x-user-agent: {:?}", raw_ua);
				let response: http::Response<ResBody> = tonic::Status::invalid_argument(
					"x-user-agent must match `<name>/<version>`",
				).into_http();
				return Box::pin(async move {
					Ok(response.map(TrailerCapturingBody::noop))
				});
			}
		};

		let rpc_method_details = if is_grpc {
			// Log protocol version used by user.
			// We allow +50 above MAX to detect clients using newer versions,
			// while still capping the range to prevent cardinality explosion
			// from malicious clients sending arbitrary values.
			let pver = req.headers().get("pver")
				.and_then(|hv| hv.to_str().ok())
				.and_then(|s| u64::from_str(s).ok())
				.filter(|&v| v <= MAX_PROTOCOL_VERSION + 50);

			if let Some(pver) = pver {
				telemetry::count_protocol_version(pver);
			}

			let (service, method) = lookup_grpc_method(req.uri().path());
			RpcMethodDetails { system: RPC_SYSTEM_GRPC, service, method, client }
		} else {
			RpcMethodDetails {
				system: RPC_SYSTEM_HTTP, service: "unknown", method: "unknown", client,
			}
		};

		let attributes = [
			KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
			KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
			KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
			KeyValue::new(telemetry::RPC_CLIENT, rpc_method_details.client),
		];
		telemetry::add_grpc_in_progress(&attributes);

		let start_time = Instant::now();
		let grpc_span = info_span!(
			telemetry::TRACE_GRPC,
			otel.kind = "server",
			{ telemetry::RPC_SYSTEM } = rpc_method_details.system,
			{ telemetry::RPC_SERVICE } = rpc_method_details.service,
			{ telemetry::RPC_METHOD } = rpc_method_details.method,
			{ telemetry::RPC_CLIENT } = rpc_method_details.client,
			{ telemetry::RPC_ACCESS_TOKEN } = req.headers().get(ACCESS_TOKEN_HEADER)
				.and_then(|v| v.to_str().ok()),
		);
		let future = self.inner.call(req);

		Box::pin(async move {
			let res = future.instrument(grpc_span.clone()).await;
			let _enter = grpc_span.enter();

			let duration = start_time.elapsed();

			telemetry::record_grpc_latency(duration, &attributes);
			telemetry::drop_grpc_in_progress(&attributes);

			match res {
				// Check for protocol-level errors (connection failures, timeouts, etc.)
				Err(err) => {
					telemetry::add_grpc_error(&[
						KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
						KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
						KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
						KeyValue::new(telemetry::RPC_CLIENT, rpc_method_details.client),
						KeyValue::new(telemetry::ATTRIBUTE_ERROR, "protocol_error"),
					]);

					let protocol_error = format!("{:?}", err);
					trace!("Completed gRPC call: {} in {:?}, protocol_error: {}",
						rpc_method_details.format_path(), duration, protocol_error,
					);
					Err(err)
				}
				// Wrap the response body to capture gRPC status from trailers.
				// For error responses tonic uses a trailers-only response: the
				// grpc-status lives in the HTTP response headers (no body frames
				// are ever sent), so check there first before falling through to
				// the body-trailer path.
				Ok(response) => {
					let (parts, body) = response.into_parts();

					// Trailers-only response (tonic error path): grpc-status is
					// in the HTTP response headers rather than a body trailer frame.
					// Only call report_grpc_status when the header is present;
					// absence here is normal and means status will arrive via body.
					if parts.headers.contains_key("grpc-status") {
						report_grpc_status(&parts.headers, &rpc_method_details, duration);
					}

					let wrapped = TrailerCapturingBody::new(body, rpc_method_details, start_time);
					Ok(http::Response::from_parts(parts, wrapped))
				}
			}
		})
	}
}

#[derive(Clone)]
pub struct TelemetryMetricsLayer;

impl<S> tower::Layer<S> for TelemetryMetricsLayer {
	type Service = TelemetryMetricsService<S>;

	fn layer(&self, inner: S) -> Self::Service {
		TelemetryMetricsService::new(inner)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_client_name_accepts_schema() {
		assert_eq!(parse_client_name("bark/0.2.3"), Some("bark"));
		assert_eq!(parse_client_name("my-wallet/1.0"), Some("my-wallet"));
		assert_eq!(parse_client_name("my_wallet/1.0"), Some("my_wallet"));
		// Versions with extra `/` or `-` are kept opaque on the right side.
		assert_eq!(parse_client_name("bark/0.2.3-DIRTY"), Some("bark"));
	}

	#[test]
	fn parse_client_name_rejects_violations() {
		// Missing or empty halves.
		assert_eq!(parse_client_name(""), None);
		assert_eq!(parse_client_name("bark"), None);
		assert_eq!(parse_client_name("bark/"), None);
		assert_eq!(parse_client_name("/0.2.3"), None);
		// Uppercase in the name (we don't lowercase to stay allocation-free).
		assert_eq!(parse_client_name("Bark/0.2.3"), None);
		// Invalid characters in the name.
		assert_eq!(parse_client_name("bark!/0.2.3"), None);
		assert_eq!(parse_client_name(" bark/0.2.3"), None);
		// Name too long.
		let long = format!("{}/1.0", "a".repeat(MAX_CLIENT_NAME_LEN + 1));
		assert_eq!(parse_client_name(&long), None);
	}

	#[test]
	fn bucket_client_classifies_inputs() {
		assert_eq!(bucket_client(None), Ok("unknown"));
		assert_eq!(bucket_client(Some("bark/0.2.3")), Ok("bark"));
		assert_eq!(bucket_client(Some("bark")), Err(()));
		assert_eq!(bucket_client(Some("")), Err(()));
		assert_eq!(bucket_client(Some("Bark/0.2.3")), Err(()));
	}
}

