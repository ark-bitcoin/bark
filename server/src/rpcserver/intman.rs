
use std::net::SocketAddr;
use std::sync::{atomic, Arc};

use tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer;
use tracing::{error, info};
use server_rpc::protos;

use crate::rpcserver::{StatusContext, ToStatusResult};
use crate::Server;

#[async_trait]
impl server_rpc::server::IntegrationService for Server {
	#[tracing::instrument(skip(self, req))]
	async fn get_tokens(
		&self,
		req: tonic::Request<protos::intman::TokensRequest>,
	) -> Result<tonic::Response<protos::intman::Tokens>, tonic::Status> {
		// The extension prefers `X-Forwarded-For`, which is client-
		// controlled. Trustworthy here because the integration listener
		// is reachable only via the traefik->envoy chain (traefik strips
		// client XFF, envoy resolves via `xff_num_trusted_hops: 1`) and
		// UFW closes the raw port. See `RemoteAddrService` docs.
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key.clone()).badarg("invalid API key")?;

		let tokens = self.get_integration_tokens(
			client_address, api_key, req.r#type().into(), req.count,
		).await.to_status()?;

		// going to assume we aren't creating expired tokens.
		let tokens_response = protos::intman::Tokens {
			tokens: tokens.into_iter().map(|t| {
				let expires_at = t.expires_at.timestamp() as u64;
				let token_type: protos::intman::TokenType = t.token_type.into();
				let status: protos::intman::TokenStatus = t.status.into();
				protos::intman::TokenInfo {
					token: t.token,
					r#type: token_type.into(),
					status: status.into(),
					since: t.updated_at.timestamp() as u64,
					expires_at,
				}
			}).collect(),
		};

		Ok(tonic::Response::new(tokens_response))
	}

	#[tracing::instrument(skip(self, req))]
	async fn get_token_info(
		&self,
		req: tonic::Request<protos::intman::TokenInfoRequest>,
	) -> Result<tonic::Response<protos::intman::TokenInfo>, tonic::Status> {
		// The extension prefers `X-Forwarded-For`, which is client-
		// controlled. Trustworthy here because the integration listener
		// is reachable only via the traefik->envoy chain (traefik strips
		// client XFF, envoy resolves via `xff_num_trusted_hops: 1`) and
		// UFW closes the raw port. See `RemoteAddrService` docs.
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key).badarg("invalid API key")?;

		let (_, _, token) = self.get_integration_token(client_address, api_key, req.token.as_str())
			.await.to_status()?;

		let status = if token.is_expired() {
			protos::intman::TokenStatus::Expired
		} else {
			token.status.into()
		};
		let token_type: protos::intman::TokenType = token.token_type.into();
		let expires_at = token.expires_at.timestamp() as u64;

		let token_response = protos::intman::TokenInfo {
			token: token.token,
			r#type: token_type.into(),
			status: status.into(),
			since: token.updated_at.timestamp() as u64,
			expires_at,
		};

		Ok(tonic::Response::new(token_response))
	}

	#[tracing::instrument(skip(self, req))]
	async fn update_token(
		&self,
		req: tonic::Request<protos::intman::UpdateTokenRequest>,
	) -> Result<tonic::Response<protos::intman::TokenInfo>, tonic::Status> {
		// The extension prefers `X-Forwarded-For`, which is client-
		// controlled. Trustworthy here because the integration listener
		// is reachable only via the traefik->envoy chain (traefik strips
		// client XFF, envoy resolves via `xff_num_trusted_hops: 1`) and
		// UFW closes the raw port. See `RemoteAddrService` docs.
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key.clone()).badarg("invalid API key")?;

		let token = self.update_integration_token(
			client_address,
			api_key,
			req.token.as_str(),
			req.status().into(),
		)
			.await.to_status()?;

		let status = if token.is_expired() {
			protos::intman::TokenStatus::Expired
		} else {
			token.status.into()
		};
		let token_type: protos::intman::TokenType = token.token_type.into();
		let expires_at = token.expires_at.timestamp() as u64;

		let token_response = protos::intman::TokenInfo {
			token: token.token,
			r#type: token_type.into(),
			status: status.into(),
			since: token.updated_at.timestamp() as u64,
			expires_at,
		};

		Ok(tonic::Response::new(token_response))
	}
}


/// Run the integration gRPC endpoint.
///
/// `config.rpc.integration_address` must be reachable only through the
/// trusted proxy chain (traefik -> envoy -> captaind). `RemoteAddrLayer`
/// honours `X-Forwarded-For` unconditionally, so the per-key IP
/// filters downstream are meaningful only while traefik normalises XFF
/// (`trustedIPs: []`), envoy resolves it (`xff_num_trusted_hops: 1`),
/// and UFW blocks direct access to the port.
pub async fn run_rpc_server(server: Arc<Server>) -> anyhow::Result<()> {
	crate::rpcserver::RPC_RICH_ERRORS.store(server.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = server.rtmgr.spawn_critical("IntegrationRpcServer");

	let addr = server.config.rpc.integration_address.expect("shouldn't call this method otherwise");
	info!("Starting integration gRPC service on address {}", addr);
	let integration_server = server_rpc::server::IntegrationServiceServer::from_arc(server.clone());

	tonic::transport::Server::builder()
		.layer(OtelGrpcLayer::default())
		.layer(crate::rpcserver::middleware::TelemetryMetricsLayer)
		.layer(crate::rpcserver::middleware::RemoteAddrLayer)
		.add_service(integration_server)
		.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
		.map_err(|e| {
			error!("Failed to start admin gRPC server on {}: {}", addr, e);

			e
		})?;

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}
