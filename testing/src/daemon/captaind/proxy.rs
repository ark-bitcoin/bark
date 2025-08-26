
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio_stream::Stream;

use server_rpc::{self as rpc, protos};

use crate::util::FutureExt;

/// Trait used to easily implement Ark proxy interfaces.
#[tonic::async_trait]
pub trait ArkRpcProxy: Send + Sync + Clone + 'static {
	fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel>;

	async fn handshake(&mut self, req: protos::HandshakeRequest) -> Result<protos::HandshakeResponse, tonic::Status> {
		Ok(self.upstream().handshake(req).await?.into_inner())
	}

	async fn get_ark_info(&mut self, req: protos::Empty) -> Result<protos::ArkInfo, tonic::Status> {
		Ok(self.upstream().get_ark_info(req).await?.into_inner())
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

	async fn request_arkoor_package_cosign(&mut self, req: protos::ArkoorPackageCosignRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(self.upstream().request_arkoor_package_cosign(req).await?.into_inner())
	}

	async fn post_arkoor_package_mailbox(&mut self, req: protos::ArkoorPackage) -> Result<protos::Empty, tonic::Status> {
		Ok(self.upstream().post_arkoor_package_mailbox(req).await?.into_inner())
	}

	async fn empty_arkoor_mailbox(&mut self, req: protos::ArkoorVtxosRequest) -> Result<protos::ArkoorVtxosResponse, tonic::Status> {
		Ok(self.upstream().empty_arkoor_mailbox(req).await?.into_inner())
	}

	async fn start_lightning_payment(&mut self, req: protos::LightningPaymentRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(self.upstream().start_lightning_payment(req).await?.into_inner())
	}

	async fn finish_lightning_payment(&mut self, req: protos::SignedLightningPaymentDetails) -> Result<protos::LightningPaymentResult, tonic::Status> {
		Ok(self.upstream().finish_lightning_payment(req).await?.into_inner())
	}

	async fn check_lightning_payment(&mut self, req: protos::CheckLightningPaymentRequest) -> Result<protos::LightningPaymentResult, tonic::Status> {
		Ok(self.upstream().check_lightning_payment(req).await?.into_inner())
	}

	async fn revoke_lightning_payment(&mut self, req: protos::RevokeLightningPaymentRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(self.upstream().revoke_lightning_payment(req).await?.into_inner())
	}

	async fn fetch_bolt12_invoice(&mut self, req: protos::FetchBolt12InvoiceRequest) -> Result<protos::FetchBolt12InvoiceResponse, tonic::Status> {
		Ok(self.upstream().fetch_bolt12_invoice(req).await?.into_inner())
	}

	async fn start_lightning_receive(
		&self,
		req: protos::StartLightningReceiveRequest,
	) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
		Ok(self.upstream().start_lightning_receive(req).await?.into_inner())
	}

	async fn subscribe_lightning_receive(
		&self,
		req: protos::SubscribeLightningReceiveRequest,
	) -> Result<protos::SubscribeLightningReceiveResponse, tonic::Status> {
		Ok(self.upstream().subscribe_lightning_receive(req).await?.into_inner())
	}

	async fn prepare_lightning_receive_claim(&mut self, req: protos::PrepareLightningReceiveClaimRequest) -> Result<protos::PrepareLightningReceiveClaimResponse, tonic::Status> {
		Ok(self.upstream().prepare_lightning_receive_claim(req).await?.into_inner())
	}

	async fn claim_lightning_receive(&mut self, req: protos::ClaimLightningReceiveRequest) -> Result<protos::ArkoorCosignResponse, tonic::Status> {
		Ok(self.upstream().claim_lightning_receive(req).await?.into_inner())
	}

	async fn subscribe_rounds(&mut self, req: protos::Empty) -> Result<Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>, tonic::Status> {
		Ok(Box::new(self.upstream().subscribe_rounds(req).await?.into_inner()))
	}

	async fn last_round_event(&mut self, req: protos::Empty) -> Result<protos::RoundEvent, tonic::Status> {
		Ok(self.upstream().last_round_event(req).await?.into_inner())
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

pub struct ArkRpcProxyServer {
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
	pub stop: tokio::sync::oneshot::Sender<()>,
	pub address: String,
}

impl ArkRpcProxyServer {
	/// Run an ark proxy server.
	pub async fn start(proxy: impl ArkRpcProxy) -> ArkRpcProxyServer {
		loop {
			let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
			let stop_rx = futures::FutureExt::map(stop_rx, |_| ());

			let port = portpicker::pick_unused_port().expect("free port available");
			let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
			let server = rpc::server::ArkServiceServer::new(ArkRpcProxyWrapper(proxy.clone()));

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

			return ArkRpcProxyServer {
				client: client,
				stop: stop_tx,
				address: addr,
			};
		}
	}
}

/// A wrapper struct around a proxy implementation to run a tonic server.
struct ArkRpcProxyWrapper<T: ArkRpcProxy>(T);

#[tonic::async_trait]
impl<T: ArkRpcProxy> rpc::server::ArkService for ArkRpcProxyWrapper<T> {
	async fn handshake(
		&self, req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::handshake(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn get_ark_info(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::ArkInfo>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_ark_info(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn get_fresh_rounds(
		&self, req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_fresh_rounds(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn get_round(
		&self, req: tonic::Request<protos::RoundId>,
	) -> Result<tonic::Response<protos::RoundInfo>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_round(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn request_board_cosign(
		&self, req: tonic::Request<protos::BoardCosignRequest>,
	) -> Result<tonic::Response<protos::BoardCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::request_board_cosign(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn register_board_vtxo(
		&self, req: tonic::Request<protos::BoardVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::register_board_vtxo(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn request_arkoor_package_cosign(
		&self, req: tonic::Request<protos::ArkoorPackageCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::request_arkoor_package_cosign(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn post_arkoor_package_mailbox(
		&self, req: tonic::Request<protos::ArkoorPackage>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::post_arkoor_package_mailbox(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn empty_arkoor_mailbox(
		&self, req: tonic::Request<protos::ArkoorVtxosRequest>,
	) -> Result<tonic::Response<protos::ArkoorVtxosResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::empty_arkoor_mailbox(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn start_lightning_payment(
		&self, req: tonic::Request<protos::LightningPaymentRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::start_lightning_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn finish_lightning_payment(
		&self, req: tonic::Request<protos::SignedLightningPaymentDetails>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::finish_lightning_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn check_lightning_payment(
		&self, req: tonic::Request<protos::CheckLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::check_lightning_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn revoke_lightning_payment(
		&self, req: tonic::Request<protos::RevokeLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::revoke_lightning_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn fetch_bolt12_invoice(
		&self, req: tonic::Request<protos::FetchBolt12InvoiceRequest>,
	) -> Result<tonic::Response<protos::FetchBolt12InvoiceResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::fetch_bolt12_invoice(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn start_lightning_receive(
		&self,
		req: tonic::Request<protos::StartLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::StartLightningReceiveResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::start_lightning_receive(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn subscribe_lightning_receive(
		&self,
		req: tonic::Request<protos::SubscribeLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::SubscribeLightningReceiveResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::subscribe_lightning_receive(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn prepare_lightning_receive_claim(
		&self, req: tonic::Request<protos::PrepareLightningReceiveClaimRequest>,
	) -> Result<tonic::Response<protos::PrepareLightningReceiveClaimResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::prepare_lightning_receive_claim(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn claim_lightning_receive(
		&self, req: tonic::Request<protos::ClaimLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::ArkoorCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::claim_lightning_receive(&mut self.0.clone(), req.into_inner()).await?))
	}

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::subscribe_rounds(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn last_round_event(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::RoundEvent>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::last_round_event(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn submit_payment(
		&self, req: tonic::Request<protos::SubmitPaymentRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::submit_payment(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn provide_vtxo_signatures(
		&self, req: tonic::Request<protos::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::provide_vtxo_signatures(&mut self.0.clone(), req.into_inner()).await?))
	}

	async fn provide_forfeit_signatures(
		&self, req: tonic::Request<protos::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::provide_forfeit_signatures(&mut self.0.clone(), req.into_inner()).await?))
	}
}
