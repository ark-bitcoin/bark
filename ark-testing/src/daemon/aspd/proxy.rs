
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio_stream::Stream;

use aspd_rpc::{self as rpc, protos};

use crate::util::FutureExt;

/// Trait used to easily implement aspd proxy interfaces.
#[tonic::async_trait]
pub trait AspdRpcProxy: Send + Sync + Clone + 'static {
	fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel>;

	async fn handshake(&mut self, req: protos::HandshakeRequest) -> Result<protos::HandshakeResponse, tonic::Status> {
		Ok(self.upstream().handshake(req).await?.into_inner())
	}

	async fn get_fresh_rounds(&mut self, req: protos::FreshRoundsRequest) -> Result<protos::FreshRounds, tonic::Status> {
		Ok(self.upstream().get_fresh_rounds(req).await?.into_inner())
	}

	async fn get_round(&mut self, req: protos::RoundId) -> Result<protos::RoundInfo, tonic::Status> {
		Ok(self.upstream().get_round(req).await?.into_inner())
	}

	async fn request_board_cosign(&mut self, req: protos::BoardCosignRequest) -> Result<protos::BoardCosignResponse, tonic::Status> {
		Ok(self.upstream().request_board_cosign(req).await?.into_inner())
	}

	async fn register_board_vtxo(&mut self, req: protos::BoardVtxoRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().register_board_vtxo(req).await?.into_inner())
	}

	async fn request_oor_cosign(&mut self, req: protos::OorCosignRequest) -> Result<protos::OorCosignResponse, tonic::Status> {
		Ok(self.upstream().request_oor_cosign(req).await?.into_inner())
	}

	async fn post_oor_mailbox(&mut self, req: protos::OorVtxo) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().post_oor_mailbox(req).await?.into_inner())
	}

	async fn empty_oor_mailbox(&mut self, req: protos::OorVtxosRequest) -> Result<protos::OorVtxosResponse, tonic::Status> {
		Ok(self.upstream().empty_oor_mailbox(req).await?.into_inner())
	}

	async fn start_bolt11_payment(&mut self, req: protos::Bolt11PaymentRequest) -> Result<protos::Bolt11PaymentDetails, tonic::Status> {
		Ok(self.upstream().start_bolt11_payment(req).await?.into_inner())
	}

	async fn finish_bolt11_payment(&mut self, req: protos::SignedBolt11PaymentDetails) -> Result<protos::Bolt11PaymentResult, tonic::Status> {
		Ok(self.upstream().finish_bolt11_payment(req).await?.into_inner())
	}

	async fn check_bolt11_payment(&mut self, req: protos::CheckBolt11PaymentRequest) -> Result<protos::Bolt11PaymentResult, tonic::Status> {
		Ok(self.upstream().check_bolt11_payment(req).await?.into_inner())
	}

	async fn revoke_bolt11_payment(&mut self, req: protos::RevokeBolt11PaymentRequest) -> Result<protos::OorCosignResponse, tonic::Status> {
		Ok(self.upstream().revoke_bolt11_payment(req).await?.into_inner())
	}

	async fn start_bolt11_onboard(
		&self,
		req: protos::StartBolt11OnboardRequest,
	) -> Result<protos::StartBolt11OnboardResponse, tonic::Status> {
		Ok(self.upstream().start_bolt11_onboard(req).await?.into_inner())
	}

	async fn subscribe_rounds(&mut self, req: protos::Empty) -> Result<Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>, tonic::Status> {
		Ok(Box::new(self.upstream().subscribe_rounds(req).await?.into_inner()))
	}

	async fn submit_payment(&mut self, req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().submit_payment(req).await?.into_inner())
	}

	async fn provide_vtxo_signatures(&mut self, req: protos::VtxoSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().provide_vtxo_signatures(req).await?.into_inner())
	}

	async fn provide_forfeit_signatures(&mut self, req: protos::ForfeitSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().provide_forfeit_signatures(req).await?.into_inner())
	}
}

pub struct AspdRpcProxyServer {
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
	pub stop: tokio::sync::oneshot::Sender<()>,
	pub address: String,
}

impl AspdRpcProxyServer {
	/// Run an aspd proxy server.
	pub async fn start(proxy: impl AspdRpcProxy) -> AspdRpcProxyServer {
		loop {
			let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
			let stop_rx = futures::FutureExt::map(stop_rx, |_| ());

			let port = portpicker::pick_unused_port().expect("free port available");
			let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
			let server = rpc::server::ArkServiceServer::new(AspdRpcProxyWrapper(proxy.clone()));

			// The serve_with_shutdown call stays running if the port number
			// is accepted, but returns immediatelly if it's not.
			// So we have to ignore the port usage error and then check if
			// the future yields fast.
			let server_res = tokio::spawn(async move {
				let ret = tonic::transport::Server::builder()
					.add_service(server)
					.serve_with_shutdown(addr, stop_rx)
					.await;
				if let Err(ref e) = ret {
					if let Some(e) = std::error::Error::source(&e) {
						if let Some(e) = e.downcast_ref::<io::Error>() {
							if e.kind() == io::ErrorKind::AddrInUse {
								return;
							}
						}
					}
				}
				ret.expect("rpc proxy server stopped with error");
			});
			if server_res.try_fast().await.is_ok() {
				continue;
			}

			// try to connect
			let addr = format!("http://{}", addr);
			let client = loop {
				tokio::time::sleep(Duration::from_millis(10)).await;
				if let Ok(c) = rpc::ArkServiceClient::connect(addr.clone()).await {
					break c;
				}
			};

			return AspdRpcProxyServer {
				client: client,
				stop: stop_tx,
				address: addr,
			};
		}
	}
}

/// A wrapper struct around a proxy implementation to run a tonic server.
struct AspdRpcProxyWrapper<T: AspdRpcProxy>(T);

#[tonic::async_trait]
impl<T: AspdRpcProxy> rpc::server::ArkService for AspdRpcProxyWrapper<T> {
	async fn handshake(
		&self, req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::handshake(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn get_fresh_rounds(
		&self, req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::get_fresh_rounds(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn get_round(
		&self, req: tonic::Request<protos::RoundId>,
	) -> Result<tonic::Response<protos::RoundInfo>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::get_round(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn request_board_cosign(
		&self, req: tonic::Request<protos::BoardCosignRequest>,
	) -> Result<tonic::Response<protos::BoardCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::request_board_cosign(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn register_board_vtxo(
		&self, req: tonic::Request<protos::BoardVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::register_board_vtxo(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn request_oor_cosign(
		&self, req: tonic::Request<protos::OorCosignRequest>,
	) -> Result<tonic::Response<protos::OorCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::request_oor_cosign(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn post_oor_mailbox(
		&self, req: tonic::Request<protos::OorVtxo>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::post_oor_mailbox(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn empty_oor_mailbox(
		&self, req: tonic::Request<protos::OorVtxosRequest>,
	) -> Result<tonic::Response<protos::OorVtxosResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::empty_oor_mailbox(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn start_bolt11_payment(
		&self, req: tonic::Request<protos::Bolt11PaymentRequest>,
	) -> Result<tonic::Response<protos::Bolt11PaymentDetails>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::start_bolt11_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn finish_bolt11_payment(
		&self, req: tonic::Request<protos::SignedBolt11PaymentDetails>,
	) -> Result<tonic::Response<protos::Bolt11PaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::finish_bolt11_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn check_bolt11_payment(
		&self, req: tonic::Request<protos::CheckBolt11PaymentRequest>,
	) -> Result<tonic::Response<protos::Bolt11PaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::check_bolt11_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn revoke_bolt11_payment(
		&self, req: tonic::Request<protos::RevokeBolt11PaymentRequest>,
	) -> Result<tonic::Response<protos::OorCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::revoke_bolt11_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn start_bolt11_onboard(
		&self,
		req: tonic::Request<protos::StartBolt11OnboardRequest>,
	) -> Result<tonic::Response<protos::StartBolt11OnboardResponse>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::start_bolt11_onboard(&mut self.0.clone(), req.into_inner()).await?))
	}

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::subscribe_rounds(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn submit_payment(
		&self, req: tonic::Request<protos::SubmitPaymentRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::submit_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn provide_vtxo_signatures(
		&self, req: tonic::Request<protos::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::provide_vtxo_signatures(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn provide_forfeit_signatures(
		&self, req: tonic::Request<protos::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(AspdRpcProxy::provide_forfeit_signatures(&mut self.0.clone(), req.into_inner()).await?))
	}
}
