use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use std::time::Instant;

use http_body::Body as HttpBody;
use opentelemetry::KeyValue;
use server_rpc::lookup_grpc_method;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};
use tracing::{debug, info_span, trace, Instrument};
use crate::telemetry::{self};
use super::MAX_PROTOCOL_VERSION;

const RPC_SYSTEM_HTTP: &str = "http";
const RPC_SYSTEM_GRPC: &str = "grpc";

#[derive(Clone, Debug)]
pub struct RpcMethodDetails {
	system: &'static str,
	service: &'static str,
	method: &'static str,
}

impl RpcMethodDetails {
	pub fn format_path(&self) -> String {
		format!("{}://{}/{}", self.system, self.service, self.method)
	}
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

/// A wrapper around a response body that captures gRPC trailers for telemetry
pub struct TrailerCapturingBody<B> {
	inner: B,
	rpc_method_details: RpcMethodDetails,
	start_time: Instant,
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

		match &result {
			// Handle body/framing errors
			Poll::Ready(Some(Err(e))) => {
				telemetry::add_grpc_error(&[
					KeyValue::new(telemetry::RPC_SYSTEM, self.rpc_method_details.system),
					KeyValue::new(telemetry::RPC_SERVICE, self.rpc_method_details.service),
					KeyValue::new(telemetry::RPC_METHOD, self.rpc_method_details.method),
					KeyValue::new(telemetry::ATTRIBUTE_ERROR, "body_error"),
				]);

				trace!(
					"gRPC call {} failed with body error: {} (after {:?})",
					self.rpc_method_details.format_path(),
					e,
					self.start_time.elapsed(),
				);
			}
			// Check if this is the trailers frame
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(trailers) = frame.trailers_ref() {
					// Extract gRPC status from trailers
					let grpc_status_code = trailers
						.get("grpc-status")
						.and_then(|v| v.to_str().ok())
						.and_then(|s| s.parse::<i32>().ok());

					match grpc_status_code {
						Some(0) => {
							trace!(
								"Completed gRPC call: {} in {:?}, status: OK",
								self.rpc_method_details.format_path(),
								self.start_time.elapsed(),
							);
						}
						Some(code) => {
							telemetry::add_grpc_error(&[
								KeyValue::new(telemetry::RPC_SYSTEM, self.rpc_method_details.system),
								KeyValue::new(telemetry::RPC_SERVICE, self.rpc_method_details.service),
								KeyValue::new(telemetry::RPC_METHOD, self.rpc_method_details.method),
								KeyValue::new(telemetry::ATTRIBUTE_ERROR, tonic::Code::from_i32(code).to_string()),
							]);

							let grpc_message = trailers
								.get("grpc-message")
								.and_then(|v| v.to_str().ok())
								.unwrap_or("unknown error");

							debug!(
								"Completed gRPC call: {} in {:?}, status={}, message={}",
								self.rpc_method_details.format_path(),
								self.start_time.elapsed(),
								tonic::Code::from_i32(code),
								grpc_message,
							);
						}
						None => {
							// Missing or unparseable grpc-status is a protocol error
							telemetry::add_grpc_error(&[
								KeyValue::new(telemetry::RPC_SYSTEM, self.rpc_method_details.system),
								KeyValue::new(telemetry::RPC_SERVICE, self.rpc_method_details.service),
								KeyValue::new(telemetry::RPC_METHOD, self.rpc_method_details.method),
								KeyValue::new(telemetry::ATTRIBUTE_ERROR, "missing_grpc_status"),
							]);

							debug!(
								"Completed gRPC call: {} in {:?}, error: missing or unparseable grpc-status in trailers",
								self.rpc_method_details.format_path(),
								self.start_time.elapsed(),
							);
						}
					}
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
	ResBody: HttpBody + Unpin + Send + 'static,
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
		let is_grpc = req.headers().get("content-type")
			.map_or(false, |ct| ct == "application/grpc");

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
			RpcMethodDetails { system: RPC_SYSTEM_GRPC, service, method }
		} else {
			RpcMethodDetails { system: RPC_SYSTEM_HTTP, service: "unknown", method: "unknown" }
		};

		let attributes = [
			KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
			KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
			KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
		];
		telemetry::add_grpc_in_progress(&attributes);

		let start_time = Instant::now();
		let grpc_span = info_span!(
			telemetry::TRACE_GRPC,
			otel.kind = "server",
			{ telemetry::RPC_SYSTEM } = rpc_method_details.system,
			{ telemetry::RPC_SERVICE } = rpc_method_details.service,
			{ telemetry::RPC_METHOD } = rpc_method_details.method,
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
						KeyValue::new(telemetry::ATTRIBUTE_ERROR, "protocol_error"),
					]);

					let protocol_error = format!("{:?}", err);
					trace!("Completed gRPC call: {} in {:?}, protocol_error: {}",
						rpc_method_details.format_path(), duration, protocol_error,
					);
					Err(err)
				}
				// Wrap the response body to capture gRPC status from trailers
				Ok(response) => {
					let (parts, body) = response.into_parts();
					let wrapped_body = TrailerCapturingBody::new(
						body,
						rpc_method_details,
						start_time,
					);
					Ok(http::Response::from_parts(parts, wrapped_body))
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
