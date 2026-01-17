use std::str::FromStr;
use std::sync::{atomic, Arc};

use tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer;
use tracing::{info, trace, warn};
use server_rpc::{self as rpc, protos};

use crate::rpcserver::{middleware, ToStatusResult, RPC_RICH_ERRORS};
use crate::Server;

#[async_trait]
impl rpc::server::WalletAdminService for Server {
	#[tracing::instrument(skip(self, _req))]
	async fn wallet_sync(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {

		self.sync_wallets().await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	#[tracing::instrument(skip(self, _req))]
	async fn wallet_status(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::WalletStatusResponse>, tonic::Status> {

		let rounds = self.rounds_wallet.lock().await.status();

		Ok(tonic::Response::new(protos::WalletStatusResponse {
			rounds: Some(rounds.into()),
			forfeits: None,
		}))
	}
}

#[async_trait]
impl rpc::server::RoundAdminService for Server {
	#[tracing::instrument(skip(self, _req))]
	async fn trigger_round(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {

		match self.rounds.round_trigger_tx.try_send(()) {
			Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
				panic!("round scheduler closed");
			},
			Err(e) => warn!("Failed to send round trigger: {:?}", e),
			Ok(_) => trace!("round scheduler not closed"),
		}

		Ok(tonic::Response::new(protos::Empty{}))
	}
}

#[async_trait]
impl rpc::server::LightningAdminService for Server {
	#[tracing::instrument(skip(self, req))]
	async fn start_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.activate(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}

	#[tracing::instrument(skip(self, req))]
	async fn stop_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.disable(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}
}

#[async_trait]
impl rpc::server::SweepAdminService for Server {
	#[tracing::instrument(skip(self, _req))]
	async fn trigger_sweep(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {

		Err(tonic::Status::unavailable("VtxoSweeper disabled"))
	}
}

/// Run the public gRPC endpoint.
pub async fn run_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(srv.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = srv.rtmgr.spawn_critical("AdminRpcServer");

	let addr = srv.config.rpc.admin_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::WalletAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::RoundAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::LightningAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::SweepAdminServiceServer::from_arc(srv.clone()));

	tonic::transport::Server::builder()
		.layer(OtelGrpcLayer::default())
		.layer(middleware::TelemetryMetricsLayer)
		.add_routes(routes)
		.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}
