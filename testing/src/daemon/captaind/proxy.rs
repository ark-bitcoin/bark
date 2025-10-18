
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio_stream::Stream;

use server_rpc::{self as rpc, protos};

use crate::daemon::captaind::ArkClient;
use crate::util::FutureExt;

/// Trait used to easily implement Ark proxy interfaces.
#[tonic::async_trait]
pub trait ArkRpcProxy: Send + Sync + Clone + 'static {
	async fn handshake(&self, upstream: &mut ArkClient, req: protos::HandshakeRequest) -> Result<protos::HandshakeResponse, tonic::Status> {
		Ok(upstream.handshake(req).await?.into_inner())
	}

	async fn get_ark_info(&self, upstream: &mut ArkClient, req: protos::Empty) -> Result<protos::ArkInfo, tonic::Status> {
		Ok(upstream.get_ark_info(req).await?.into_inner())
	}

	async fn get_fresh_rounds(&self, upstream: &mut ArkClient, req: protos::FreshRoundsRequest) -> Result<protos::FreshRounds, tonic::Status> {
		Ok(upstream.get_fresh_rounds(req).await?.into_inner())
	}

	async fn get_round(&self, upstream: &mut ArkClient, req: protos::RoundId) -> Result<protos::RoundInfo, tonic::Status> {
		Ok(upstream.get_round(req).await?.into_inner())
	}

	async fn request_board_cosign(&self, upstream: &mut ArkClient, req: protos::BoardCosignRequest) -> Result<protos::BoardCosignResponse, tonic::Status> {
		Ok(upstream.request_board_cosign(req).await?.into_inner())
	}

	async fn register_board_vtxo(&self, upstream: &mut ArkClient, req: protos::BoardVtxoRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(upstream.register_board_vtxo(req).await?.into_inner())
	}

	async fn request_arkoor_package_cosign(&self, upstream: &mut ArkClient, req: protos::ArkoorPackageCosignRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(upstream.request_arkoor_package_cosign(req).await?.into_inner())
	}

	async fn post_arkoor_package_mailbox(&self, upstream: &mut ArkClient, req: protos::ArkoorPackage) -> Result<protos::Empty, tonic::Status> {
		Ok(upstream.post_arkoor_package_mailbox(req).await?.into_inner())
	}

	async fn empty_arkoor_mailbox(&self, upstream: &mut ArkClient, req: protos::ArkoorVtxosRequest) -> Result<protos::ArkoorVtxosResponse, tonic::Status> {
		Ok(upstream.empty_arkoor_mailbox(req).await?.into_inner())
	}

	async fn start_lightning_payment(&self, upstream: &mut ArkClient, req: protos::StartLightningPaymentRequest) -> Result<protos::StartLightningPaymentResponse, tonic::Status> {
		Ok(upstream.start_lightning_payment(req).await?.into_inner())
	}

	async fn finish_lightning_payment(&self, upstream: &mut ArkClient, req: protos::SignedLightningPaymentDetails) -> Result<protos::LightningPaymentResult, tonic::Status> {
		Ok(upstream.finish_lightning_payment(req).await?.into_inner())
	}

	async fn check_lightning_payment(&self, upstream: &mut ArkClient, req: protos::CheckLightningPaymentRequest) -> Result<protos::LightningPaymentResult, tonic::Status> {
		Ok(upstream.check_lightning_payment(req).await?.into_inner())
	}

	async fn revoke_lightning_payment(&self, upstream: &mut ArkClient, req: protos::RevokeLightningPaymentRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(upstream.revoke_lightning_payment(req).await?.into_inner())
	}

	async fn fetch_bolt12_invoice(&self, upstream: &mut ArkClient, req: protos::FetchBolt12InvoiceRequest) -> Result<protos::FetchBolt12InvoiceResponse, tonic::Status> {
		Ok(upstream.fetch_bolt12_invoice(req).await?.into_inner())
	}

	async fn start_lightning_receive(
		&self,
		upstream: &mut ArkClient,
		req: protos::StartLightningReceiveRequest,
	) -> Result<protos::StartLightningReceiveResponse, tonic::Status> {
		Ok(upstream.start_lightning_receive(req).await?.into_inner())
	}

	async fn check_lightning_receive(
		&self,
		upstream: &mut ArkClient,
		req: protos::CheckLightningReceiveRequest,
	) -> Result<protos::CheckLightningReceiveResponse, tonic::Status> {
		Ok(upstream.check_lightning_receive(req).await?.into_inner())
	}

	async fn prepare_lightning_receive_claim(&self, upstream: &mut ArkClient, req: protos::PrepareLightningReceiveClaimRequest) -> Result<protos::PrepareLightningReceiveClaimResponse, tonic::Status> {
		Ok(upstream.prepare_lightning_receive_claim(req).await?.into_inner())
	}

	async fn claim_lightning_receive(&self, upstream: &mut ArkClient, req: protos::ClaimLightningReceiveRequest) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
		Ok(upstream.claim_lightning_receive(req).await?.into_inner())
	}

	async fn subscribe_rounds(&self, upstream: &mut ArkClient, req: protos::Empty) -> Result<Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>, tonic::Status> {
		Ok(Box::new(upstream.subscribe_rounds(req).await?.into_inner()))
	}

	async fn last_round_event(&self, upstream: &mut ArkClient, req: protos::Empty) -> Result<protos::RoundEvent, tonic::Status> {
		Ok(upstream.last_round_event(req).await?.into_inner())
	}

	async fn submit_payment(&self, upstream: &mut ArkClient, req: protos::SubmitPaymentRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(upstream.submit_payment(req).await?.into_inner())
	}

	async fn provide_vtxo_signatures(&self, upstream: &mut ArkClient, req: protos::VtxoSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(upstream.provide_vtxo_signatures(req).await?.into_inner())
	}

	async fn provide_forfeit_signatures(&self, upstream: &mut ArkClient, req: protos::ForfeitSignaturesRequest) -> Result<protos::Empty, tonic::Status> {
		Ok(upstream.provide_forfeit_signatures(req).await?.into_inner())
	}
}

pub struct ArkRpcProxyServer {
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
	pub stop: tokio::sync::oneshot::Sender<()>,
	pub address: String,
}

impl ArkRpcProxyServer {
	/// Run an ark proxy server.
	pub async fn start(proxy: impl ArkRpcProxy, upstream: ArkClient) -> ArkRpcProxyServer {
		loop {
			let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
			let stop_rx = futures::FutureExt::map(stop_rx, |_| ());

			let port = portpicker::pick_unused_port().expect("free port available");
			let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
			let server = rpc::server::ArkServiceServer::new(ArkRpcProxyWrapper {
				proxy: proxy.clone(),
				upstream: upstream.clone(),
			});

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
struct ArkRpcProxyWrapper<T: ArkRpcProxy> {
	proxy: T,
	upstream: ArkClient,
}

#[tonic::async_trait]
impl<T: ArkRpcProxy> rpc::server::ArkService for ArkRpcProxyWrapper<T> {
	async fn handshake(
		&self, req: tonic::Request<protos::HandshakeRequest>,
	) -> Result<tonic::Response<protos::HandshakeResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::handshake(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn get_ark_info(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::ArkInfo>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_ark_info(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn get_fresh_rounds(
		&self, req: tonic::Request<protos::FreshRoundsRequest>,
	) -> Result<tonic::Response<protos::FreshRounds>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_fresh_rounds(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn get_round(
		&self, req: tonic::Request<protos::RoundId>,
	) -> Result<tonic::Response<protos::RoundInfo>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::get_round(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn request_board_cosign(
		&self, req: tonic::Request<protos::BoardCosignRequest>,
	) -> Result<tonic::Response<protos::BoardCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::request_board_cosign(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn register_board_vtxo(
		&self, req: tonic::Request<protos::BoardVtxoRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::register_board_vtxo(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn request_arkoor_package_cosign(
		&self, req: tonic::Request<protos::ArkoorPackageCosignRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::request_arkoor_package_cosign(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn post_arkoor_package_mailbox(
		&self, req: tonic::Request<protos::ArkoorPackage>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::post_arkoor_package_mailbox(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn empty_arkoor_mailbox(
		&self, req: tonic::Request<protos::ArkoorVtxosRequest>,
	) -> Result<tonic::Response<protos::ArkoorVtxosResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::empty_arkoor_mailbox(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn start_lightning_payment(
		&self, req: tonic::Request<protos::StartLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::StartLightningPaymentResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::start_lightning_payment(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn finish_lightning_payment(
		&self, req: tonic::Request<protos::SignedLightningPaymentDetails>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::finish_lightning_payment(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn check_lightning_payment(
		&self, req: tonic::Request<protos::CheckLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::LightningPaymentResult>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::check_lightning_payment(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn revoke_lightning_payment(
		&self, req: tonic::Request<protos::RevokeLightningPaymentRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::revoke_lightning_payment(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn fetch_bolt12_invoice(
		&self, req: tonic::Request<protos::FetchBolt12InvoiceRequest>,
	) -> Result<tonic::Response<protos::FetchBolt12InvoiceResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::fetch_bolt12_invoice(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn start_lightning_receive(
		&self,
		req: tonic::Request<protos::StartLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::StartLightningReceiveResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::start_lightning_receive(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn check_lightning_receive(
		&self,
		req: tonic::Request<protos::CheckLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::CheckLightningReceiveResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::check_lightning_receive(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn prepare_lightning_receive_claim(
		&self, req: tonic::Request<protos::PrepareLightningReceiveClaimRequest>,
	) -> Result<tonic::Response<protos::PrepareLightningReceiveClaimResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::prepare_lightning_receive_claim(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn claim_lightning_receive(
		&self, req: tonic::Request<protos::ClaimLightningReceiveRequest>,
	) -> Result<tonic::Response<protos::ArkoorPackageCosignResponse>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::claim_lightning_receive(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	type SubscribeRoundsStream = Box<
		dyn Stream<Item = Result<protos::RoundEvent, tonic::Status>> + Unpin + Send + 'static
	>;

	async fn subscribe_rounds(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<Self::SubscribeRoundsStream>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::subscribe_rounds(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn last_round_event(
		&self, req: tonic::Request<protos::Empty>,
	) -> Result<tonic::Response<protos::RoundEvent>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::last_round_event(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn submit_payment(
		&self, req: tonic::Request<protos::SubmitPaymentRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::submit_payment(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn provide_vtxo_signatures(
		&self, req: tonic::Request<protos::VtxoSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::provide_vtxo_signatures(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}

	async fn provide_forfeit_signatures(
		&self, req: tonic::Request<protos::ForfeitSignaturesRequest>,
	) -> Result<tonic::Response<protos::Empty>, tonic::Status> {
		Ok(tonic::Response::new(ArkRpcProxy::provide_forfeit_signatures(&self.proxy, &mut self.upstream.clone(), req.into_inner()).await?))
	}
}
