use std::str::FromStr;
use std::sync::{atomic, Arc};

use tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer;
use tracing::{info, trace, warn};
use server_rpc::{self as rpc, protos};

use crate::rpcserver::{middleware, StatusContext, ToStatusResult, RPC_RICH_ERRORS};
use crate::rpcserver::middleware::rpc_names;
use crate::rpcserver::middleware::RpcMethodDetails;
use crate::Server;

#[async_trait]
impl rpc::server::WalletAdminService for Server {
	async fn wallet_sync(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::WALLET_SYNC);

		self.sync_wallets().await.to_status()?;

		Ok(tonic::Response::new(protos::Empty {}))
	}

	async fn wallet_status(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::WalletStatusResponse>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::WALLET_STATUS);

		let rounds = async {
			Ok(self.rounds_wallet.lock().await.status())
		};
		let forfeits = async {
			if let Some(ref fw) = self.forfeits {
				Some(fw.wallet_status().await).transpose()
			} else {
				Ok(None)
			}
		};

		let (rounds, forfeits) = tokio::try_join!(rounds, forfeits).to_status()?;

		Ok(tonic::Response::new(protos::WalletStatusResponse {
			rounds: Some(rounds.into()),
			forfeits: forfeits.map(|f| f.into()),
		}))
	}
}

#[async_trait]
impl rpc::server::RoundAdminService for Server {
	async fn trigger_round(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::TRIGGER_ROUND);

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
	async fn start_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::START_LIGHTNING_NODE);
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.activate(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}

	async fn stop_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::STOP_LIGHTNING_NODE);
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.cln.disable(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}
}

#[async_trait]
impl rpc::server::SweepAdminService for Server {
	async fn trigger_sweep(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let _ = RpcMethodDetails::grpc_admin(rpc_names::admin::TRIGGER_SWEEP);

		if let Some(ref vs) = self.vtxo_sweeper {
			vs.trigger_sweep().context("VtxoSweeper down")?;
			Ok(tonic::Response::new(protos::Empty{}))
		} else {
			Err(tonic::Status::unavailable("VtxoSweeper disabled"))
		}
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
