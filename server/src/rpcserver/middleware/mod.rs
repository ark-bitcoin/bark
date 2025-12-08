use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::Poll;
use std::time::Instant;
use log::trace;
use opentelemetry::{global, Context, KeyValue};
use opentelemetry::trace::{Span, SpanKind, TraceContextExt, Tracer};
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};
use crate::telemetry::{self, MetricsService};
use crate::telemetry::SpanExt;

const RPC_SYSTEM_HTTP: &'static str = "http";
const RPC_SYSTEM_GRPC: &'static str = "grpc";

const RPC_UNKNOWN: &'static str = "Unknown";

const RPC_SERVICES: [&str; 3] = [RPC_SERVICE_ARK, RPC_SERVICE_ADMIN, RPC_SERVICE_INTEGRATION];

const RPC_SERVICE_ARK: &'static str = "ArkService";

pub const RPC_SERVICE_ARK_HANDSHAKE: &'static str = "handshake";
pub const RPC_SERVICE_ARK_GET_ARK_INFO: &'static str = "get_ark_info";
pub const RPC_SERVICE_ARK_GET_FRESH_ROUNDS: &'static str = "get_fresh_rounds";
pub const RPC_SERVICE_ARK_GET_ROUND: &'static str = "get_round";
pub const RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN: &'static str = "request_board_cosign";
pub const RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS: &'static str = "register_board_vtxos";
pub const RPC_SERVICE_ARK_CHECKPOINTED_COSIGN_OOR: &'static str = "checkpointed_cosign_oor";
pub const RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN: &'static str = "request_arkoor_package_cosign";
pub const RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX: &'static str = "post_arkoor_package_mailbox";
pub const RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX: &'static str = "empty_arkoor_mailbox";
pub const RPC_SERVICE_ARK_POST_VTXOS_MAILBOX: &'static str = "post_vtxos_mailbox";
pub const RPC_SERVICE_ARK_SUBSCRIBE_MAILBOX: &'static str = "subscribe_mailbox";
pub const RPC_SERVICE_ARK_READ_MAILBOX: &'static str = "read_mailbox";
pub const RPC_SERVICE_ARK_REQUEST_LIGHTNING_PAY_HTLC_COSIGN: &'static str = "request_lightning_pay_htlc_cosign";
// TODO: Remove this once we hit 0.1.0-beta.6 or higher
pub const RPC_SERVICE_ARK_START_LIGHTNING_PAYMENT: &'static str = "start_lightning_payment";
// TODO: Remove this once we hit 0.1.0-beta.6 or higher
pub const RPC_SERVICE_ARK_FINISH_LIGHTNING_PAYMENT: &'static str = "finish_lightning_payment";
pub const RPC_SERVICE_ARK_INITIATE_LIGHTNING_PAYMENT: &'static str = "initiate_lightning_payment";
pub const RPC_SERVICE_ARK_CHECK_LIGHTNING_PAYMENT: &'static str = "check_lightning_payment";
pub const RPC_SERVICE_ARK_REQUEST_LIGHTNING_PAY_HTLC_REVOCATION: &'static str = "request_lightning_pay_htlc_revocation";
// TODO: Remove this once we hit 0.1.0-beta.6 or higher
pub const RPC_SERVICE_ARK_REVOKE_LIGHTNING_PAYMENT: &'static str = "revoke_lightning_payment";
pub const RPC_SERVICE_ARK_FETCH_BOLT12_INVOICE: &'static str = "fetch_bolt12_invoice";
pub const RPC_SERVICE_ARK_START_LIGHTNING_RECEIVE: &'static str = "start_lightning_receive";
pub const RPC_SERVICE_ARK_CHECK_LIGHTNING_RECEIVE: &'static str = "check_lightning_receive";
pub const RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE: &'static str = "claim_lightning_receive";
pub const RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS: &'static str = "subscribe_rounds";
pub const RPC_SERVICE_ARK_LAST_ROUND_EVENT: &'static str = "last_round_event";
pub const RPC_SERVICE_ARK_SUBMIT_PAYMENT: &'static str = "submit_payment";
pub const RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES: &'static str = "provide_vtxo_signatures";
pub const RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES: &'static str = "provide_forfeit_signatures";

const RPC_SERVICE_ARK_METHODS: [&str; 28] = [
	RPC_SERVICE_ARK_HANDSHAKE,
	RPC_SERVICE_ARK_GET_ARK_INFO,
	RPC_SERVICE_ARK_GET_FRESH_ROUNDS,
	RPC_SERVICE_ARK_GET_ROUND,
	RPC_SERVICE_ARK_REQUEST_BOARD_COSIGN,
	RPC_SERVICE_ARK_REGISTER_BOARD_VTXOS,
	RPC_SERVICE_ARK_REQUEST_ARKOOR_PACKAGE_COSIGN,
	RPC_SERVICE_ARK_POST_ARKOOR_PACKAGE_MAILBOX,
	RPC_SERVICE_ARK_EMPTY_ARKOOR_MAILBOX,
	RPC_SERVICE_ARK_POST_VTXOS_MAILBOX,
	RPC_SERVICE_ARK_SUBSCRIBE_MAILBOX,
	RPC_SERVICE_ARK_READ_MAILBOX,
	RPC_SERVICE_ARK_START_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_FINISH_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_REQUEST_LIGHTNING_PAY_HTLC_COSIGN,
	RPC_SERVICE_ARK_INITIATE_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_CHECK_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_REQUEST_LIGHTNING_PAY_HTLC_REVOCATION,
	RPC_SERVICE_ARK_REVOKE_LIGHTNING_PAYMENT,
	RPC_SERVICE_ARK_FETCH_BOLT12_INVOICE,
	RPC_SERVICE_ARK_START_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_CHECK_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_CLAIM_LIGHTNING_RECEIVE,
	RPC_SERVICE_ARK_SUBSCRIBE_ROUNDS,
	RPC_SERVICE_ARK_LAST_ROUND_EVENT,
	RPC_SERVICE_ARK_SUBMIT_PAYMENT,
	RPC_SERVICE_ARK_PROVIDE_VTXO_SIGNATURES,
	RPC_SERVICE_ARK_PROVIDE_FORFEIT_SIGNATURES,
];

const RPC_SERVICE_ADMIN: &'static str = "AdminService";

pub const RPC_SERVICE_ADMIN_WALLET_SYNC: &'static str = "wallet_sync";
pub const RPC_SERVICE_ADMIN_WALLET_STATUS: &'static str = "wallet_status";
pub const RPC_SERVICE_ADMIN_TRIGGER_ROUND: &'static str = "trigger_round";
pub const RPC_SERVICE_ADMIN_TRIGGER_SWEEP: &'static str = "trigger_sweep";
pub const RPC_SERVICE_ADMIN_START_LIGHTNING_NODE: &'static str = "start_lightning_node";
pub const RPC_SERVICE_ADMIN_STOP_LIGHTNING_NODE: &'static str = "stop_lightning_node";
pub const RPC_SERVICE_ADMIN_STOP: &'static str = "stop";

const RPC_SERVICE_ADMIN_METHODS: [&str; 7] = [
	RPC_SERVICE_ADMIN_WALLET_SYNC,
	RPC_SERVICE_ADMIN_WALLET_STATUS,
	RPC_SERVICE_ADMIN_TRIGGER_ROUND,
	RPC_SERVICE_ADMIN_TRIGGER_SWEEP,
	RPC_SERVICE_ADMIN_START_LIGHTNING_NODE,
	RPC_SERVICE_ADMIN_STOP_LIGHTNING_NODE,
	RPC_SERVICE_ADMIN_STOP,
];

const RPC_SERVICE_INTEGRATION: &'static str = "IntegrationService";

pub const RPC_SERVICE_INTEGRATION_GET_TOKENS: &'static str = "get_tokens";
pub const RPC_SERVICE_INTEGRATION_GET_TOKEN_INFO: &'static str = "get_token_info";
pub const RPC_SERVICE_INTEGRATION_UPDATE_TOKEN: &'static str = "update_token";

const RPC_SERVICE_INTEGRATION_METHODS: [&str; 3] = [
	RPC_SERVICE_INTEGRATION_GET_TOKENS,
	RPC_SERVICE_INTEGRATION_GET_TOKEN_INFO,
	RPC_SERVICE_INTEGRATION_UPDATE_TOKEN,
];

#[derive(Clone, Debug)]
pub struct RpcMethodDetails {
	system: &'static str,
	service: &'static str,
	method: &'static str,
}

impl RpcMethodDetails {
	pub(crate) fn grpc_ark(method: &'static str) -> RpcMethodDetails {
		RpcMethodDetails {
			system: RPC_SYSTEM_GRPC,
			service: RPC_SERVICE_ARK,
			method,
		}
	}

	pub(crate) fn grpc_admin(method: &'static str) -> RpcMethodDetails {
		RpcMethodDetails {
			system: RPC_SYSTEM_GRPC,
			service: RPC_SERVICE_ADMIN,
			method,
		}
	}

	pub(crate) fn grpc_intman(method: &'static str) -> RpcMethodDetails {
		RpcMethodDetails {
			system: RPC_SYSTEM_GRPC,
			service: RPC_SERVICE_INTEGRATION,
			method,
		}
	}

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

#[derive(Clone)]
pub struct TelemetryMetricsService<S> {
	inner: S,
}

impl<S> TelemetryMetricsService<S> {
	fn new(inner: S) -> TelemetryMetricsService<S> {
		TelemetryMetricsService { inner }
	}
}

impl<S, B> tower::Service<http::Request<B>> for TelemetryMetricsService<S>
where
	S: tower::Service<http::Request<B>> + Send + 'static,
	S::Future: Send + 'static,
	S::Error: std::fmt::Debug,
	B: http_body::Body + Send + 'static,
	B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
	type Response = S::Response;
	type Error = S::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(
		&mut self,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(&mut self, req: http::Request<B>) -> Self::Future {
		let uri = req.uri();
		let is_grpc = req.headers().get("content-type")
			.map_or(false, |ct| ct == "application/grpc");

		let mut rpc_method_details = RpcMethodDetails {
			system: RPC_SYSTEM_HTTP,
			service: RPC_UNKNOWN,
			method: RPC_UNKNOWN,
		};

		if is_grpc {
			rpc_method_details.system = RPC_SYSTEM_GRPC;
			if let Some((service, method)) = extract_service_method(&uri) {
				rpc_method_details.service = service;
				rpc_method_details.method = method;
			}

			// log protocol version used by user
			if let Some(hv) = req.headers().get("grpc-pver") {
				if let Ok(s) = hv.to_str() {
					if let Ok(pver) = u64::from_str(s) {
						telemetry::count_protocol_version(pver);
					}
				}
			}
		}

		let attributes = [
			KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
			KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
			KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
		];
		telemetry::add_grpc_in_progress(&attributes);

		// NB currently only captains uses
		let tracer = global::tracer(telemetry::Captaind::TRACER);
		let mut span = tracer
			.span_builder(rpc_method_details.format_path())
			.with_kind(SpanKind::Server)
			.start(&tracer);
		span.set_str_attr(telemetry::RPC_SYSTEM, rpc_method_details.system);
		span.set_str_attr(telemetry::RPC_SERVICE, rpc_method_details.service);
		span.set_str_attr(telemetry::RPC_METHOD, rpc_method_details.method);

		span.add_event(format!("Processing {} request", rpc_method_details.format_path()), vec![]);

		let span_context = Context::current_with_span(span);

		let start_time = Instant::now();
		let future = self.inner.call(req);
		Box::pin(async move {
			let res = future.await;

			let duration = start_time.elapsed();

			telemetry::record_grpc_latency(duration, &attributes);
			telemetry::drop_grpc_in_progress(&attributes);

			if let Err(ref status) = res {
				let error_string = format!("{:?}", status);

				telemetry::add_grpc_error(&[
					KeyValue::new(telemetry::RPC_SYSTEM, rpc_method_details.system),
					KeyValue::new(telemetry::RPC_SERVICE, rpc_method_details.service),
					KeyValue::new(telemetry::RPC_METHOD, rpc_method_details.method),
					KeyValue::new(telemetry::ATTRIBUTE_ERROR, error_string.clone()),
				]);

				trace!("Completed gRPC call: {} in {:?}, status: {}",
					rpc_method_details.format_path(), duration, error_string,
				);
			} else {
				span_context.span().set_int_attr(telemetry::RPC_GRPC_STATUS_CODE, tonic::Code::Ok as i64);

				trace!("Completed gRPC call: {} in {:?}, status: OK",
					rpc_method_details.format_path(), duration,
				);
			}

			res
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

fn pascal_to_snake(s: &str) -> String {
	let mut snake_case = String::new();

	for (i, c) in s.chars().enumerate() {
		if c.is_uppercase() {
			if i != 0 {
				snake_case.push('_');
			}
			snake_case.push(c.to_ascii_lowercase());
		} else {
			snake_case.push(c);
		}
	}

	snake_case
}

fn extract_service_method(url: &http::uri::Uri) -> Option<(&'static str, &'static str)> {
	// Find the last '/' in the URL
	let path = url.path();
	if let Some(last_slash_idx) = path.rfind('/') {
		let method = &path[last_slash_idx + 1..];
		let method_snake = pascal_to_snake(method);
		trace!("Extracting service method: {}", method_snake);
		let method_snake_ref: &str = &method_snake;

		// Find the last '.' before the method part
		let before_method = &path[..last_slash_idx];
		if let Some(dot_idx) = before_method.rfind('.') {
			let service = &before_method[dot_idx + 1..];
			trace!("Extracting service: {}", service);

			let service_ref = RPC_SERVICES
				.iter()
				.find(|&&m| m == service)
				.copied()?;

			let method_ref = RPC_SERVICE_ARK_METHODS
				.iter()
				.chain(RPC_SERVICE_ADMIN_METHODS.iter())
				.chain(RPC_SERVICE_INTEGRATION_METHODS.iter())
				.find(|&&m| m == method_snake_ref)
				.copied()?;

			return Some((service_ref, method_ref));
		}
	}

	None
}
