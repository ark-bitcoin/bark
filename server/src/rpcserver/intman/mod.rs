
use std::net::SocketAddr;
use std::sync::{atomic, Arc};

use log::{error, info};

use server_rpc::protos;

use crate::rpcserver::middleware::rpc_names;
use crate::rpcserver::middleware::RpcMethodDetails;
use crate::rpcserver::ToStatusResult;
use crate::Server;

#[tonic::async_trait]
impl server_rpc::server::IntegrationService for Server {
	async fn get_tokens(
		&self,
		req: tonic::Request<protos::intman::TokensRequest>,
	) -> Result<tonic::Response<protos::intman::Tokens>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_intman(rpc_names::integration::GET_TOKENS);
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key.clone()).expect("Invalid API key");

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

	async fn get_token_info(
		&self,
		req: tonic::Request<protos::intman::TokenInfoRequest>,
	) -> Result<tonic::Response<protos::intman::TokenInfo>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_intman(rpc_names::integration::GET_TOKEN_INFO);
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key).unwrap();

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

	async fn update_token(
		&self,
		req: tonic::Request<protos::intman::UpdateTokenRequest>,
	) -> Result<tonic::Response<protos::intman::TokenInfo>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_intman(rpc_names::integration::UPDATE_TOKEN);
		let client_address =
			if let Some(remote_addr) = req.extensions().get::<SocketAddr>().cloned() {
				Some(remote_addr)
			} else if let Some(remote_addr) = req.remote_addr() {
				Some(remote_addr)
			} else {
				None
			};
		let req = req.into_inner();
		let api_key = uuid::Uuid::try_from(req.api_key.clone()).unwrap();

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


/// Run the public gRPC endpoint.
pub async fn run_rpc_server(server: Arc<Server>) -> anyhow::Result<()> {
	crate::rpcserver::RPC_RICH_ERRORS.store(server.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = server.rtmgr.spawn_critical("IntegrationRpcServer");

	let addr = server.config.rpc.integration_address.expect("shouldn't call this method otherwise");
	info!("Starting integration gRPC service on address {}", addr);
	let integration_server = server_rpc::server::IntegrationServiceServer::from_arc(server.clone());

	if server.config.otel_collector_endpoint.is_some() {
		tonic::transport::Server::builder()
			.layer(crate::rpcserver::middleware::TelemetryMetricsLayer)
			.layer(crate::rpcserver::middleware::RemoteAddrLayer)
			.add_service(integration_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	} else {
		tonic::transport::Server::builder()
			.layer(crate::rpcserver::middleware::RemoteAddrLayer)
			.add_service(integration_server)
			.serve_with_shutdown(addr, server.rtmgr.shutdown_signal()).await
			.map_err(|e| {
				error!("Failed to start admin gRPC server on {}: {}", addr, e);

				e
			})?;
	};

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}
