use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::Poll;
use std::time::Instant;

use opentelemetry::KeyValue;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};
use tracing::trace;
use crate::telemetry::{self};

const RPC_SYSTEM_HTTP: &'static str = "http";
const RPC_SYSTEM_GRPC: &'static str = "grpc";

const RPC_UNKNOWN: &'static str = "Unknown";

const RPC_SERVICES: &[&str] = &[RPC_SERVICE_ARK, RPC_SERVICE_ADMIN, RPC_SERVICE_INTEGRATION];

const RPC_SERVICE_ARK: &'static str = "ArkService";
const RPC_SERVICE_ADMIN: &'static str = "AdminService";
const RPC_SERVICE_INTEGRATION: &'static str = "IntegrationService";

pub mod rpc_names {
	pub mod ark {
		pub const HANDSHAKE: &str = "handshake";
		pub const GET_ARK_INFO: &str = "get_ark_info";
		pub const GET_FRESH_ROUNDS: &str = "get_fresh_rounds";
		pub const GET_ROUND: &str = "get_round";
		pub const REQUEST_BOARD_COSIGN: &str = "request_board_cosign";
		pub const REGISTER_BOARD_VTXO: &str = "register_board_vtxo";
		pub const CHECKPOINTED_COSIGN_OOR: &str = "checkpointed_cosign_oor";
		pub const REQUEST_ARKOOR_PACKAGE_COSIGN: &str = "request_arkoor_package_cosign";
		pub const POST_ARKOOR_PACKAGE_MAILBOX: &str = "post_arkoor_package_mailbox";
		pub const EMPTY_ARKOOR_MAILBOX: &str = "empty_arkoor_mailbox";
		pub const POST_VTXOS_MAILBOX: &str = "post_vtxos_mailbox";
		pub const SUBSCRIBE_MAILBOX: &str = "subscribe_mailbox";
		pub const READ_MAILBOX: &str = "read_mailbox";
		pub const REQUEST_LIGHTNING_PAY_HTLC_COSIGN: &str = "request_lightning_pay_htlc_cosign";
		// TODO: Remove this once we hit 0.1.0-beta.6 or higher
		pub const START_LIGHTNING_PAYMENT: &str = "start_lightning_payment";
		// TODO: Remove this once we hit 0.1.0-beta.6 or higher
		pub const FINISH_LIGHTNING_PAYMENT: &str = "finish_lightning_payment";
		pub const INITIATE_LIGHTNING_PAYMENT: &str = "initiate_lightning_payment";
		pub const CHECK_LIGHTNING_PAYMENT: &str = "check_lightning_payment";
		pub const REQUEST_LIGHTNING_PAY_HTLC_REVOCATION: &str = "request_lightning_pay_htlc_revocation";
		// TODO: Remove this once we hit 0.1.0-beta.6 or higher
		pub const REVOKE_LIGHTNING_PAYMENT: &str = "revoke_lightning_payment";
		pub const FETCH_BOLT12_INVOICE: &str = "fetch_bolt12_invoice";
		pub const START_LIGHTNING_RECEIVE: &str = "start_lightning_receive";
		pub const CHECK_LIGHTNING_RECEIVE: &str = "check_lightning_receive";
		pub const CLAIM_LIGHTNING_RECEIVE: &str = "claim_lightning_receive";
		pub const SUBSCRIBE_ROUNDS: &str = "subscribe_rounds";
		pub const LAST_ROUND_EVENT: &str = "last_round_event";
		pub const SUBMIT_PAYMENT: &str = "submit_payment";
		pub const PROVIDE_VTXO_SIGNATURES: &str = "provide_vtxo_signatures";
		pub const PROVIDE_FORFEIT_SIGNATURES: &str = "provide_forfeit_signatures";
		pub const SUBMIT_ROUND_PARTICIPATION: &str = "submit_round_participation";
		pub const ROUND_PARTICIPATION_STATUS: &str = "round_participation_status";
		pub const REQUEST_LEAF_VTXO_COSIGN: &str = "request_leaf_vtxo_cosign";
		pub const REQUEST_FORFEIT_NONCES: &str = "request_forfeit_nonces";
		pub const FORFEIT_VTXOS: &str = "forfeit_vtxos";
	}

	pub mod admin {
		pub const WALLET_SYNC: &str = "wallet_sync";
		pub const WALLET_STATUS: &str = "wallet_status";
		pub const TRIGGER_ROUND: &str = "trigger_round";
		pub const TRIGGER_SWEEP: &str = "trigger_sweep";
		pub const START_LIGHTNING_NODE: &str = "start_lightning_node";
		pub const STOP_LIGHTNING_NODE: &str = "stop_lightning_node";
		pub const STOP: &str = "stop";
	}

	pub mod integration {
		pub const GET_TOKENS: &str = "get_tokens";
		pub const GET_TOKEN_INFO: &str = "get_token_info";
		pub const UPDATE_TOKEN: &str = "update_token";
	}
}

const RPC_SERVICE_ARK_METHODS: &[&str] = &[
	rpc_names::ark::HANDSHAKE,
	rpc_names::ark::GET_ARK_INFO,
	rpc_names::ark::GET_FRESH_ROUNDS,
	rpc_names::ark::GET_ROUND,
	rpc_names::ark::REQUEST_BOARD_COSIGN,
	rpc_names::ark::REGISTER_BOARD_VTXO,
	rpc_names::ark::REQUEST_ARKOOR_PACKAGE_COSIGN,
	rpc_names::ark::POST_ARKOOR_PACKAGE_MAILBOX,
	rpc_names::ark::EMPTY_ARKOOR_MAILBOX,
	rpc_names::ark::POST_VTXOS_MAILBOX,
	rpc_names::ark::SUBSCRIBE_MAILBOX,
	rpc_names::ark::READ_MAILBOX,
	rpc_names::ark::START_LIGHTNING_PAYMENT,
	rpc_names::ark::FINISH_LIGHTNING_PAYMENT,
	rpc_names::ark::REQUEST_LIGHTNING_PAY_HTLC_COSIGN,
	rpc_names::ark::INITIATE_LIGHTNING_PAYMENT,
	rpc_names::ark::CHECK_LIGHTNING_PAYMENT,
	rpc_names::ark::REQUEST_LIGHTNING_PAY_HTLC_REVOCATION,
	rpc_names::ark::REVOKE_LIGHTNING_PAYMENT,
	rpc_names::ark::FETCH_BOLT12_INVOICE,
	rpc_names::ark::START_LIGHTNING_RECEIVE,
	rpc_names::ark::CHECK_LIGHTNING_RECEIVE,
	rpc_names::ark::CLAIM_LIGHTNING_RECEIVE,
	rpc_names::ark::SUBSCRIBE_ROUNDS,
	rpc_names::ark::LAST_ROUND_EVENT,
	rpc_names::ark::SUBMIT_PAYMENT,
	rpc_names::ark::PROVIDE_VTXO_SIGNATURES,
	rpc_names::ark::PROVIDE_FORFEIT_SIGNATURES,
	rpc_names::ark::SUBMIT_ROUND_PARTICIPATION,
	rpc_names::ark::ROUND_PARTICIPATION_STATUS,
	rpc_names::ark::REQUEST_LEAF_VTXO_COSIGN,
	rpc_names::ark::REQUEST_FORFEIT_NONCES,
	rpc_names::ark::FORFEIT_VTXOS,
];

const RPC_SERVICE_ADMIN_METHODS: &[&str] = &[
	rpc_names::admin::WALLET_SYNC,
	rpc_names::admin::WALLET_STATUS,
	rpc_names::admin::TRIGGER_ROUND,
	rpc_names::admin::TRIGGER_SWEEP,
	rpc_names::admin::START_LIGHTNING_NODE,
	rpc_names::admin::STOP_LIGHTNING_NODE,
	rpc_names::admin::STOP,
];

const RPC_SERVICE_INTEGRATION_METHODS: &[&str] = &[
	rpc_names::integration::GET_TOKENS,
	rpc_names::integration::GET_TOKEN_INFO,
	rpc_names::integration::UPDATE_TOKEN,
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
