//! The admin gRPC interface of captaind and watchmand.
//!
//! This interface deliberately has no authentication, authorization or transport encryption. It is
//! an operator plane as privileged as shell access on the host, kept unreachable by deployment and
//! not by the daemon.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{atomic, Arc};

use ark::VtxoId;
use tonic_tracing_opentelemetry::middleware::server::OtelGrpcLayer;
use tracing::{info, trace, warn};
use server_rpc::{self as rpc, protos};

use crate::rpcserver::{
	middleware, StatusContext, ToStatusResult,
	DEFAULT_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS, RPC_RICH_ERRORS,
};
use crate::system::RuntimeManager;
use crate::Server;

#[async_trait]
impl rpc::server::WalletAdminService for Server {
	#[tracing::instrument(skip(self, _req))]
	async fn wallet_status(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::WalletStatusResponse>, tonic::Status> {

		let rounds = async {
			Ok(self.rounds_wallet.lock().await.status())
		};
		let watchman = async {
			if let Some(ref fw) = self.watchman_wallet {
				Ok::<_, anyhow::Error>(Some(fw.lock().await.status()))
			} else {
				Ok(None)
			}
		};

		let (rounds, watchman) = tokio::try_join!(rounds, watchman).to_status()?;

		Ok(tonic::Response::new(protos::WalletStatusResponse {
			rounds: Some(rounds.into()),
			watchman: watchman.map(|f| f.into()),
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
		let _ = self.lightning_manager.activate(uri);
		Ok(tonic::Response::new(protos::Empty{}))
	}

	#[tracing::instrument(skip(self, req))]
	async fn stop_lightning_node(
		&self,
		req: tonic::Request<protos::LightningNodeUri>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let uri = http::Uri::from_str(req.uri.as_str()).unwrap();
		let _ = self.lightning_manager.disable(uri);
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

		match &self.watchman_handle {
			Some(handle) => {
				handle.trigger_sweep();
				Ok(tonic::Response::new(protos::Empty {}))
			},
			None => Err(tonic::Status::unavailable("watchman not enabled")),
		}
	}
}

#[async_trait]
impl rpc::server::SweepAdminService for crate::watchman::Daemon {
	#[tracing::instrument(skip(self, _req))]
	async fn trigger_sweep(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {

		self.watchman_handle().trigger_sweep();
		Ok(tonic::Response::new(protos::Empty {}))
	}
}

#[async_trait]
impl rpc::server::NurseryAdminService for Server {
	#[tracing::instrument(skip(self, req))]
	async fn abandon(
		&self,
		req: tonic::Request<protos::AbandonRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let txid = bitcoin::Txid::from_str(&req.txid)
			.badarg("invalid txid")?;
		if self.tx_nursery.abandon(txid).await.to_status()? {
			Ok(tonic::Response::new(protos::Empty {}))
		} else {
			Err(tonic::Status::not_found("no active nursery tx with that txid"))
		}
	}
}

#[async_trait]
impl rpc::server::BanAdminService for Server {
	#[tracing::instrument(skip(self, req))]
	async fn ban_vtxo(
		&self,
		req: tonic::Request<protos::BanVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let vtxo_id = VtxoId::from_slice(&req.vtxo_id)
			.badarg("invalid vtxo id")?;
		let chain_tip = self.chain_tip().height;
		let until_height = chain_tip.saturating_add(req.ban_blocks);
		self.db.write(async |t| t.ban_vtxo(vtxo_id, until_height).await).await.to_status()?;
		Ok(tonic::Response::new(protos::Empty {}))
	}

	#[tracing::instrument(skip(self, req))]
	async fn unban_vtxo(
		&self,
		req: tonic::Request<protos::UnbanVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		let req = req.into_inner();
		let vtxo_id = VtxoId::from_slice(&req.vtxo_id)
			.badarg("invalid vtxo id")?;
		self.db.write(async |t| t.unban_vtxo(vtxo_id).await).await.to_status()?;
		Ok(tonic::Response::new(protos::Empty {}))
	}

	#[tracing::instrument(skip(self, _req))]
	async fn list_banned_vtxos(
		&self,
		_req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::ListBannedVtxosResponse>, tonic::Status> {
		let chain_tip = self.sync_manager.chain_tip().height;
		let banned = self.db.read(async |t| t.list_banned_vtxos(chain_tip).await).await.to_status()?;
		let banned_vtxos = banned.into_iter().map(|v| {
			protos::BannedVtxo {
				vtxo_id: v.vtxo_id.to_bytes().to_vec(),
				banned_until_height: v.banned_until_height,
			}
		}).collect();
		Ok(tonic::Response::new(protos::ListBannedVtxosResponse { banned_vtxos }))
	}
}

/// Run the captaind admin gRPC endpoint.
pub async fn run_rpc_server(srv: Arc<Server>) -> anyhow::Result<()> {
	RPC_RICH_ERRORS.store(srv.config.rpc_rich_errors, atomic::Ordering::Relaxed);

	let _worker = srv.rtmgr.spawn_critical("AdminRpcServer");

	let addr = srv.config.rpc.admin_address.expect("shouldn't call this method otherwise");
	info!("Starting admin gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::WalletAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::RoundAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::LightningAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::SweepAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::BanAdminServiceServer::from_arc(srv.clone()))
		.add_service(rpc::server::NurseryAdminServiceServer::from_arc(srv.clone()));

	tonic::transport::Server::builder()
		.http2_max_pending_accept_reset_streams(Some(DEFAULT_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS))
		.layer(OtelGrpcLayer::default())
		.layer(middleware::TelemetryMetricsLayer)
		.add_routes(routes)
		.serve_with_shutdown(addr, srv.rtmgr.shutdown_signal()).await?;

	info!("Terminated admin gRPC service on address {}", addr);

	Ok(())
}

/// Run the watchmand admin gRPC server, exposing only `SweepAdminService`.
pub async fn run_watchmand_admin_rpc_server(
	addr: SocketAddr,
	daemon: Arc<crate::watchman::Daemon>,
	rtmgr: RuntimeManager,
) -> anyhow::Result<()> {
	info!("Starting watchmand admin gRPC service on address {}", addr);

	let routes = tonic::service::Routes::default()
		.add_service(rpc::server::SweepAdminServiceServer::from_arc(daemon));

	tonic::transport::Server::builder()
		.http2_max_pending_accept_reset_streams(Some(DEFAULT_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS))
		.layer(OtelGrpcLayer::default())
		.layer(middleware::TelemetryMetricsLayer)
		.add_routes(routes)
		.serve_with_shutdown(addr, rtmgr.shutdown_signal())
		.await?;

	info!("Terminated watchmand admin gRPC service on address {}", addr);

	Ok(())
}
